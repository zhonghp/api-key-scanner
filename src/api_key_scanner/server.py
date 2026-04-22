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

import json
import logging
import os
import sys
import time
from pathlib import Path
from typing import Any

from mcp.server.fastmcp import FastMCP

from api_key_scanner import __version__, aliases, evaluation, fingerprint_fetch
from api_key_scanner import probes as probes_mod
from api_key_scanner.aliases import UnknownModelError
from api_key_scanner.fingerprint_fetch import FingerprintFetchError
from api_key_scanner.gateway import ClientConfig, OpenAICompatClient
from api_key_scanner.probes import FingerprintDataMissingError
from api_key_scanner.schemas import Budget, FingerprintEntry, Probe, Verdict

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

# Last auto-fetch error, kept so verify_gateway can surface the concrete
# failure reason in its Verdict when load_fingerprints subsequently fails.
# Cleared on successful fetch.
_LAST_FETCH_ERROR: str | None = None


async def _resolve_fingerprint_dir(*, offline: bool) -> Path | None:
    """Return a local fingerprint dir, fetching from GitHub Releases if needed.

    Resolution order:
      1. APIGUARD_FINGERPRINT_DIR — explicit override, always wins
      2. Process-level cache from a prior fetch in this server instance
      3. fingerprint_fetch.ensure_fingerprints() — downloads + Sigstore-verifies

    Returns None on fetch failure; the caller degrades to inconclusive with
    a warning rather than crashing the tool.
    """
    global _RESOLVED_FINGERPRINT_DIR, _LAST_FETCH_ERROR

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
        _LAST_FETCH_ERROR = f"{exc.kind}: {exc}"
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
    _LAST_FETCH_ERROR = None
    return result.path


@mcp.tool()
async def list_supported_models() -> dict[str, Any]:
    """List models covered by the current signed fingerprint release.

    Call this before verify_gateway when you are uncertain whether a given
    claimed_model is one the tool can actually check against. Returns the
    canonical IDs (like 'openai/gpt-4o' or 'anthropic/claude-opus-4') for
    which reference fingerprints are loaded on this machine right now,
    plus the release tag they came from.

    If the auto-fetch hasn't happened or failed, the list comes back
    empty and the `status` field explains why — so the caller can tell
    the user "the tool can't reach GitHub Releases" versus "your
    requested model isn't in our catalog".
    """
    fp_dir = await _resolve_fingerprint_dir(offline=False)
    tag = os.environ.get(probes_mod.FINGERPRINT_VERSION_ENV, "unset")

    if fp_dir is None:
        return {
            "status": "unavailable",
            "fingerprint_tag": tag,
            "models": [],
            "reason": _LAST_FETCH_ERROR or "no fingerprint data and no APIGUARD_FINGERPRINT_DIR",
        }

    manifest_path = fp_dir / "MANIFEST.json"
    if manifest_path.is_file():
        try:
            manifest = json.loads(manifest_path.read_text(encoding="utf-8"))
            models = sorted(manifest.get("models", {}).keys())
            return {"status": "ok", "fingerprint_tag": tag, "models": models}
        except (OSError, json.JSONDecodeError) as exc:
            logger.warning("could not parse %s: %s", manifest_path, exc)

    # Fallback: enumerate <vendor>/<model>.jsonl directly.
    models: list[str] = []
    for vendor_dir in sorted(p for p in fp_dir.iterdir() if p.is_dir()):
        for jsonl in sorted(vendor_dir.glob("*.jsonl")):
            models.append(f"{vendor_dir.name}/{jsonl.stem}")
    return {
        "status": "ok" if models else "empty",
        "fingerprint_tag": tag,
        "models": models,
    }


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
            - "cheap": ~13 probes, quick spot-check
            - "standard": ~58 probes (default), reasonable confidence
            - "deep": ~92 probes, high confidence
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
        reason = str(exc)
        if _LAST_FETCH_ERROR and "fetch attempt failed" not in reason:
            reason = f"{reason} (auto-fetch detail: {_LAST_FETCH_ERROR})"
        return _inconclusive(
            endpoint_url=endpoint_url,
            claimed_model=claimed_model,
            resolved_id=canonical_id,
            reason=reason,
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

    verdict = evaluation.evaluate_responses(
        endpoint_url=endpoint_url,
        claimed_model=claimed_model,
        canonical_id=canonical_id,
        probe_list=probe_list,
        responses=responses,
        fingerprints=fingerprints,
        probe_set_version=probes_mod.PROBE_SET_VERSION,
        duration_ms=_elapsed_ms(t_start),
        include_raw_responses=include_raw_responses,
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


def _build_detector_probe_ids(probes: list[Probe]) -> dict[str, set[str]]:
    return evaluation.build_detector_probe_ids(probes)


# Re-export for callers that want to build their own probes from outside
FingerprintEntry = FingerprintEntry  # re-export for type access


_DEFAULT_DOTENV_PATH = Path.home() / ".api-key-scanner" / ".env"


def _load_dotenv_if_requested() -> None:
    """Load a `.env` file at MCP startup.

    Resolution order:
      1. `APIGUARD_DOTENV_PATH` env var if set (usually from `.mcp.json`'s
         `env` block)
      2. `~/.api-key-scanner/.env` if that file exists

    When either path loads, its entries populate os.environ **without**
    overriding values already set — so shell exports and `.mcp.json` env
    always win. This lets a user stash their gateway API key in a
    predictable place and not worry about the shell-env-vs-subprocess
    snapshot problem that plagues MCP clients (Claude Code spawns the
    server once at app launch; later `export VAR=...` in a terminal
    never reaches it).

    We deliberately avoid scanning cwd — MCP subprocesses have
    unpredictable cwd across Claude Code / opencode / Cursor.
    """
    raw = os.environ.get("APIGUARD_DOTENV_PATH", "").strip()
    if raw:
        path = Path(raw).expanduser()
        source = "APIGUARD_DOTENV_PATH"
        if not path.exists():
            logger.warning("%s=%s but file does not exist; skipping", source, path)
            return
    elif _DEFAULT_DOTENV_PATH.is_file():
        path = _DEFAULT_DOTENV_PATH
        source = "default ~/.api-key-scanner/.env"
    else:
        return

    try:
        from dotenv import load_dotenv
    except ImportError:
        logger.warning("dotenv requested (%s) but python-dotenv not available", source)
        return

    load_dotenv(dotenv_path=path, override=False)
    logger.info("loaded env from %s (%s)", path, source)


def run() -> None:
    """Run the MCP server over stdio (what Claude Code spawns)."""
    _load_dotenv_if_requested()
    logger.info("api-key-scanner-mcp v%s starting (stdio)", __version__)
    mcp.run()


if __name__ == "__main__":
    run()
