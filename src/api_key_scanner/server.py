"""MCP server entrypoint.

Exposes `verify_gateway` which orchestrates:
  1. Resolve claimed model alias
  2. Load bundled probe set (llmmap + met)
  3. Load reference fingerprints (from APIGUARD_FINGERPRINT_DIR)
  4. Read the user's API key from a named env var (the only place the raw
     key is ever touched; never logged, never returned)
  5. Call the target gateway in parallel with the probe set
  6. Run D1 / D2 / D4 detectors locally
  7. Bayesian-fuse scores into a single trust_score and verdict label
  8. Return a Verdict dict (JSON-serialisable for MCP transport)
"""

from __future__ import annotations

import logging
import os
import sys
import time
from pathlib import Path
from typing import Any

from mcp.server.fastmcp import FastMCP

from api_key_scanner import __version__, aliases, fingerprint_fetch
from api_key_scanner import probes as probes_mod
from api_key_scanner.aliases import UnknownModelError
from api_key_scanner.detectors import fusion, llmmap, met, metadata
from api_key_scanner.fingerprint_fetch import FingerprintFetchError
from api_key_scanner.gateway import ClientConfig, OpenAICompatClient
from api_key_scanner.probes import FingerprintDataMissingError
from api_key_scanner.schemas import (
    Budget,
    DetectorResult,
    Evidence,
    FingerprintEntry,
    ProbeResponse,
    Verdict,
)

logger = logging.getLogger("api_key_scanner")
_handler = logging.StreamHandler(sys.stderr)
_handler.setFormatter(logging.Formatter("[api-key-scanner] %(levelname)s: %(message)s"))
logger.addHandler(_handler)
logger.setLevel(os.environ.get("APIGUARD_LOG_LEVEL", "INFO"))

mcp = FastMCP("api-key-scanner")


# Populated on first successful auto-fetch. Subsequent verify_gateway calls
# in the same process reuse the resolved directory without re-checking
# GitHub or hitting the sigstore verifier again.
_RESOLVED_FINGERPRINT_DIR: Path | None = None


async def _resolve_fingerprint_dir(*, offline: bool) -> Path | None:
    """Return a local fingerprint dir, fetching from GitHub Releases if needed.

    Resolution order:
      1. APIGUARD_FINGERPRINT_DIR — explicit override, always wins
      2. Process-level cache from a prior fetch in this server instance
      3. fingerprint_fetch.ensure_fingerprints() — downloads + Sigstore-verifies

    Returns None on fetch failure; the caller degrades to inconclusive with
    a warning rather than crashing the tool.
    """
    global _RESOLVED_FINGERPRINT_DIR

    explicit = os.environ.get("APIGUARD_FINGERPRINT_DIR")
    if explicit:
        return Path(explicit).expanduser()

    if _RESOLVED_FINGERPRINT_DIR is not None:
        return _RESOLVED_FINGERPRINT_DIR

    try:
        result = await fingerprint_fetch.ensure_fingerprints(
            repo=os.environ.get("APIGUARD_FINGERPRINT_REPO", "zhonghp/api-key-scanner"),
            pinned_tag=os.environ.get("APIGUARD_FINGERPRINT_RELEASE"),
            auto_update=os.environ.get("APIGUARD_FINGERPRINT_AUTO_UPDATE", "1") != "0",
            offline=offline or os.environ.get("APIGUARD_OFFLINE", "0") == "1",
        )
    except FingerprintFetchError as exc:
        logger.warning("auto-fetch failed (%s): %s", exc.kind, exc)
        return None

    logger.info(
        "fetched fingerprint tag=%s (from_cache=%s) path=%s",
        result.tag,
        result.from_cache,
        result.path,
    )
    # Propagate tag into Verdict.fingerprint_version via the env var the
    # probes module already reads. One-shot per process; safe.
    os.environ[probes_mod.FINGERPRINT_VERSION_ENV] = result.tag
    _RESOLVED_FINGERPRINT_DIR = result.path
    return result.path


@mcp.tool()
async def verify_gateway(
    endpoint_url: str,
    claimed_model: str,
    api_key_env_var: str,
    budget: Budget = "standard",
    offline: bool = False,
    include_raw_responses: bool = False,
) -> dict[str, Any]:
    """Verify whether an LLM API gateway is actually serving the claimed model.

    Privacy: your API key NEVER leaves your machine. Pass the NAME of the
    env var holding the key, not the key itself. The key is read locally
    via os.environ and used only to call the target endpoint.

    Args:
        endpoint_url: OpenAI-compatible endpoint, e.g. "https://xxx.com/v1".
        claimed_model: The model the gateway claims to serve, e.g. "claude-opus-4".
        api_key_env_var: NAME of env var holding the key (NOT the key itself).
        budget: Probe budget.
            - "cheap": ~8 probes, ~$0.02-0.10
            - "standard": ~30 probes, ~$0.20-1.50 (default)
            - "deep": ~100 probes, ~$1-5
        offline: If True, skip any network-dependent fingerprint fetch (M3).
        include_raw_responses: Embed raw gateway outputs in evidence (verbose).

    Returns:
        Verdict dict with trust_score (0-1) and detailed evidence.

    Phase 1 limitations:
        - Covers only A1 (cross-family substitution), A5 (system-prompt
          tampering), A7 (cached replay).
        - Does NOT reliably detect same-family downgrade (Opus->Sonnet),
          quantization, or adaptive routing. See docs/2026-04-20-phase1-*.md.
    """
    t_start = time.perf_counter()
    logger.info(
        "verify_gateway: endpoint=%s claimed=%s budget=%s offline=%s",
        endpoint_url,
        claimed_model,
        budget,
        offline,
    )

    # 1. Env var gate — fail fast with a helpful message, never touch the key
    #    until we know the basics are OK.
    api_key = os.environ.get(api_key_env_var)
    if not api_key:
        return _inconclusive(
            endpoint_url=endpoint_url,
            claimed_model=claimed_model,
            resolved_id=claimed_model,
            reason=(
                f"Environment variable '{api_key_env_var}' is not set or empty. "
                f"Set it in your shell (e.g. `export {api_key_env_var}=...`) and retry. "
                f"The key is read locally and never leaves your machine."
            ),
            duration_ms=_elapsed_ms(t_start),
        )

    # 2. Resolve the alias to a canonical id via the single choke point.
    #    Fail with a specific message if the model isn't in our catalog — this
    #    distinguishes "unknown model" from "fingerprints not deployed".
    try:
        canonical_id = aliases.to_canonical(claimed_model)
    except UnknownModelError as exc:
        return _inconclusive(
            endpoint_url=endpoint_url,
            claimed_model=claimed_model,
            resolved_id=claimed_model,
            reason=str(exc),
            duration_ms=_elapsed_ms(t_start),
        )

    # 3. Load probes (bundled JSONL)
    probe_list = probes_mod.load_probes(budget)

    # 4. Load fingerprints. If APIGUARD_FINGERPRINT_DIR isn't set, we fetch
    #    the latest signed GitHub Release once per process and cache it under
    #    platformdirs. The sigstore identity check is the trust anchor here.
    fp_dir = await _resolve_fingerprint_dir(offline=offline)
    try:
        fingerprints = probes_mod.load_fingerprints(canonical_id, fingerprint_dir=fp_dir)
    except FingerprintDataMissingError as exc:
        return _inconclusive(
            endpoint_url=endpoint_url,
            claimed_model=claimed_model,
            resolved_id=canonical_id,
            reason=str(exc),
            duration_ms=_elapsed_ms(t_start),
        )

    # 5. Call gateway — this is where the raw key is used, and the only place.
    client = OpenAICompatClient(
        ClientConfig(
            endpoint_url=endpoint_url,
            api_key=api_key,
            model=claimed_model,
        )
    )
    try:
        responses = await client.run_probes(probe_list)
    except Exception as exc:
        # Never include the key or full exception chain — could contain headers
        logger.warning("gateway call failed: %s", type(exc).__name__)
        return _inconclusive(
            endpoint_url=endpoint_url,
            claimed_model=claimed_model,
            resolved_id=canonical_id,
            reason=f"Could not reach gateway: {type(exc).__name__}",
            duration_ms=_elapsed_ms(t_start),
        )

    # 6. Run the three detectors (all local, no network)
    d1 = llmmap.run(
        gateway_responses=responses,
        fingerprints=fingerprints,
        claimed_model_id=canonical_id,
    )
    d2 = met.run(
        gateway_responses=responses,
        fingerprints=fingerprints,
        claimed_model_id=canonical_id,
    )
    d4 = metadata.run(
        gateway_responses=responses,
        fingerprints=fingerprints,
        claimed_model_id=canonical_id,
    )
    detectors = [d1, d2, d4]

    # 7. Fuse
    trust_score = fusion.combine(detectors)
    verdict_label = fusion.label(trust_score, detectors)
    conf = fusion.confidence(detectors)

    # 8. Evidence
    evidence = _build_evidence(responses, detectors, include_raw=include_raw_responses)

    # 9. Cost estimate (best effort)
    cost_usd = _estimate_cost_usd(responses, canonical_id)

    num_failed = sum(1 for r in responses if r.error)

    verdict = Verdict(
        trust_score=trust_score,
        verdict=verdict_label,
        confidence=conf,
        claimed_model=claimed_model,
        resolved_model_id=canonical_id,
        endpoint_url=endpoint_url,
        detectors={d.name: d for d in detectors},
        evidence=evidence,
        probe_set_version=probes_mod.PROBE_SET_VERSION,
        fingerprint_version=probes_mod.current_fingerprint_version(),
        mcp_version=__version__,
        num_probes_sent=len(responses),
        num_probes_failed=num_failed,
        cost_usd_estimate=cost_usd,
        duration_ms=_elapsed_ms(t_start),
    )
    return verdict.model_dump()


# ---- Helpers ---------------------------------------------------------------


def _elapsed_ms(t_start: float) -> int:
    return int((time.perf_counter() - t_start) * 1000)


def _inconclusive(
    *,
    endpoint_url: str,
    claimed_model: str,
    resolved_id: str,
    reason: str,
    duration_ms: int = 0,
) -> dict[str, Any]:
    return Verdict(
        trust_score=0.0,
        verdict="inconclusive",
        confidence="low",
        claimed_model=claimed_model,
        resolved_model_id=resolved_id,
        endpoint_url=endpoint_url,
        probe_set_version=probes_mod.PROBE_SET_VERSION,
        fingerprint_version=probes_mod.current_fingerprint_version(),
        mcp_version=__version__,
        duration_ms=duration_ms,
        disclaimer=reason,
    ).model_dump()


def _build_evidence(
    responses: list[ProbeResponse],
    detectors: list[DetectorResult],
    *,
    include_raw: bool = False,
    max_items: int = 8,
) -> list[Evidence]:
    """Turn detector details + sample data into human-readable evidence items."""
    out: list[Evidence] = []

    # If any probe errored, surface the first error so users can see WHY.
    # The gateway client already scrubs API keys; error strings are safe to
    # show. This is the most-requested diagnostic when "all probes failed".
    error_responses = [r for r in responses if r.error]
    if error_responses:
        sample = error_responses[0]
        error_text = (sample.error or "")[:220]
        out.append(
            Evidence(
                probe_id=sample.probe_id,
                category="metadata",
                observation=(
                    f"{len(error_responses)}/{len(responses)} probes failed. "
                    f"first error: {error_text}"
                ),
                severity="alarm",
            )
        )

    # D1: surface the nearest-neighbor voting disagreement (if any)
    d1 = _find_detector(detectors, "d1_llmmap")
    if d1 and d1.status != "failed":
        top_guess = d1.details.get("top_guess")
        votes = d1.details.get("top_guess_votes", 0)
        total_scored = d1.details.get("num_samples_scored", 0)
        if top_guess and d1.score < 1.0:
            out.append(
                Evidence(
                    probe_id="llmmap-aggregate",
                    category="identification",
                    observation=(
                        f"D1 LLMmap: top-guess is {top_guess} ({votes}/{total_scored} samples), "
                        f"score {d1.score:.2f}"
                    ),
                    severity="alarm" if d1.score == 0.0 else "warn",
                )
            )

    # D2: surface the worst-rejected probes
    d2 = _find_detector(detectors, "d2_met")
    if d2 and d2.status != "failed":
        per_probe = d2.details.get("per_probe") or []
        per_probe_sorted = sorted(per_probe, key=lambda p: p.get("p_value", 1.0))
        for entry in per_probe_sorted[:2]:
            p_val = entry.get("p_value", 1.0)
            if p_val < 0.1:
                out.append(
                    Evidence(
                        probe_id=entry.get("probe_id", "?"),
                        category="creative",
                        observation=(
                            f"D2 MET: MMD two-sample test rejected at p={p_val:.3f} "
                            f"(gateway distribution diverges from reference)"
                        ),
                        severity="alarm" if p_val < 0.02 else "warn",
                    )
                )

    # D4: surface fired signals
    d4 = _find_detector(detectors, "d4_metadata")
    if d4 and d4.status != "failed":
        for sig in d4.details.get("signals", []):
            if sig.get("score", 1.0) <= 0.3:
                out.append(
                    Evidence(
                        probe_id="metadata-aggregate",
                        category="metadata",
                        observation=f"D4 {sig['name']}: {sig['reason']}",
                        severity="alarm" if sig["score"] <= 0.3 else "warn",
                    )
                )

    # Raw samples only if user opted in (verbose mode)
    if include_raw:
        for r in responses[:3]:
            if r.output:
                short = r.output[:120] + ("..." if len(r.output) > 120 else "")
                out.append(
                    Evidence(
                        probe_id=r.probe_id,
                        category="identification",
                        observation=f'sample[{r.sample_index}]: "{short}"',
                        severity="info",
                    )
                )

    return out[:max_items]


def _find_detector(detectors: list[DetectorResult], name: str) -> DetectorResult | None:
    for d in detectors:
        if d.name == name:
            return d
    return None


# Rough per-1K-token rates for the 10 Phase 1 models, USD. Kept coarse on
# purpose — this is just for the cost_usd_estimate line in the report; users
# should treat it as ±50%.
_ROUGH_RATES_USD_PER_1K: dict[str, tuple[float, float]] = {
    # (input_rate, output_rate)
    "anthropic/claude-opus-4": (15.0, 75.0),
    "anthropic/claude-sonnet-4": (3.0, 15.0),
    "anthropic/claude-haiku-4.5": (1.0, 5.0),
    "openai/gpt-5": (10.0, 30.0),
    "openai/gpt-5-mini": (0.5, 2.0),
    "openai/gpt-5.4": (10.0, 30.0),
    "openai/gpt-5.4-mini": (0.5, 2.0),
    "openai/gpt-4o": (2.5, 10.0),
    "openai/gpt-4o-mini": (0.15, 0.6),
    "google/gemini-2.5-pro": (3.5, 10.5),
    "google/gemini-2.5-flash": (0.3, 2.5),
    "meta/llama-3.3-70b": (0.5, 0.7),
}


def _estimate_cost_usd(responses: list[ProbeResponse], canonical_id: str) -> float:
    rates = _ROUGH_RATES_USD_PER_1K.get(canonical_id)
    if rates is None:
        return 0.0
    in_rate, out_rate = rates
    # We don't track input tokens per-response. Assume ~50 input tokens per probe
    # (short prompts). Output tokens we have from usage field when gateway returns it.
    total_in = 50 * len([r for r in responses if not r.error])
    total_out = sum((r.output_tokens or 0) for r in responses)
    return round(total_in / 1000 * in_rate + total_out / 1000 * out_rate, 3)


# Re-export for callers that want to build their own probes from outside
FingerprintEntry = FingerprintEntry  # re-export for type access


def _load_dotenv_if_requested() -> None:
    """Opt-in loading of a `.env` file at MCP startup.

    Activated by the `APIGUARD_DOTENV_PATH` env var (usually set via the
    `.mcp.json` `env` block). When active:
      - Reads the given path as a dotenv file
      - Populates os.environ with its entries, **without** overriding values
        that are already set (so `.mcp.json` env + shell env always win)

    We deliberately require an explicit path rather than searching for
    `.env` in cwd, because MCP subprocesses have unpredictable cwd when
    spawned by different agents (Claude Code, opencode, Cursor, …).
    """
    raw = os.environ.get("APIGUARD_DOTENV_PATH", "").strip()
    if not raw:
        return

    path = Path(raw).expanduser()
    if not path.exists():
        logger.warning("APIGUARD_DOTENV_PATH=%s but file does not exist; skipping", path)
        return

    try:
        from dotenv import load_dotenv
    except ImportError:
        logger.warning("APIGUARD_DOTENV_PATH set but python-dotenv not available")
        return

    load_dotenv(dotenv_path=path, override=False)
    logger.info("loaded env from %s", path)


def run() -> None:
    """Run the MCP server over stdio (what Claude Code spawns)."""
    _load_dotenv_if_requested()
    logger.info("api-key-scanner-mcp v%s starting (stdio)", __version__)
    mcp.run()


if __name__ == "__main__":
    run()
