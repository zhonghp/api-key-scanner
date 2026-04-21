"""Probe + fingerprint loading.

Phase 1 loads from two locations:
  1. Bundled probes in `api_key_scanner/data/probes/*.jsonl` (shipped with PyPI pkg)
  2. Fingerprints from a local directory specified by `APIGUARD_FINGERPRINT_DIR`
     env var (set by the user, or the weekly auto-updater in M3).

M3 will extend this to fetch signed Release assets from GitHub on first
use and cache them under `platformdirs.user_cache_dir("apiguard")`. For now
the loader is local-only: if the fingerprint directory isn't present,
verify_gateway returns an inconclusive Verdict with a clear instruction.
"""

from __future__ import annotations

import logging
import os
from importlib import resources
from pathlib import Path

from api_key_scanner import aliases
from api_key_scanner.aliases import UnknownModelError
from api_key_scanner.schemas import Budget, FingerprintEntry, Probe

logger = logging.getLogger(__name__)

_BUDGET_PROBE_COUNT: dict[Budget, dict[str, int]] = {
    # Samples per run = (llmmap_probes × 1) + (met_probes × 10 samples each)
    "cheap": {"llmmap": 3, "met": 1},  # 13 total calls
    "standard": {"llmmap": 8, "met": 5},  # 58 total calls
    "deep": {"llmmap": 12, "met": 8},  # 92 total calls
}


class FingerprintDataMissingError(Exception):
    """Raised when the fingerprint directory is not configured/present.

    Verify_gateway catches this and returns an inconclusive Verdict with
    the recovery instruction in the disclaimer.
    """

    def __init__(self, detail: str | None = None):
        self.detail = detail
        base = (
            "No fingerprint data available. By default the server auto-fetches "
            "a signed fingerprint release from GitHub on first use; if that "
            "failed (network, sigstore verification, or rate limit), set "
            "APIGUARD_FINGERPRINT_DIR to a locally-downloaded release directory "
            "to bypass the fetch."
        )
        if detail:
            base += f" (fetch attempt failed: {detail})"
        super().__init__(base)


def load_probes(budget: Budget = "standard") -> list[Probe]:
    """Load the bundled probe set for this budget.

    Budget caps the total sample count so users with small quotas don't
    blow up their bill during verification.
    """
    caps = _BUDGET_PROBE_COUNT[budget]

    probes: list[Probe] = []
    probes.extend(_load_bundled_jsonl("llmmap_v1.jsonl", cap=caps["llmmap"]))
    probes.extend(_load_bundled_jsonl("met_v1.jsonl", cap=caps["met"]))
    return probes


def _load_bundled_jsonl(filename: str, *, cap: int | None = None) -> list[Probe]:
    """Load probes from the bundled data package, limiting to `cap` if set."""
    # 3.10 compat: MultiplexedPath.joinpath takes one arg only; chain it
    traversable = resources.files("api_key_scanner.data").joinpath("probes").joinpath(filename)
    with traversable.open("r", encoding="utf-8") as f:
        out: list[Probe] = []
        for i, line in enumerate(f):
            line = line.strip()
            if not line:
                continue
            if cap is not None and i >= cap:
                break
            out.append(Probe.model_validate_json(line))
    return out


def load_fingerprints(
    canonical_model_id: str, *, fingerprint_dir: Path | str | None = None
) -> dict[str, list[FingerprintEntry]]:
    """Load reference fingerprints for comparison.

    Returns a mapping `canonical_model_id -> list[FingerprintEntry]` covering
    the claimed model AND every other known model we have data for. D1
    LLMmap needs the cross-family references to do nearest-neighbor voting;
    D2 MET only compares against the claimed model.

    Args:
        canonical_model_id: the claimed model (resolved alias). We always try
            to load this one; raise FingerprintDataMissingError if absent.
        fingerprint_dir: explicit path; falls back to APIGUARD_FINGERPRINT_DIR
            env var. Expected layout:
              <dir>/anthropic/claude-opus-4.jsonl
              <dir>/openai/gpt-4o.jsonl
              ...

    Raises:
        FingerprintDataMissingError: no directory available or claimed model
            has no fingerprint file.
    """
    resolved_dir = _resolve_fingerprint_dir(fingerprint_dir)
    if resolved_dir is None or not resolved_dir.is_dir():
        raise FingerprintDataMissingError()

    result: dict[str, list[FingerprintEntry]] = {}
    orphans: list[str] = []

    # Walk all <vendor>/<model>.jsonl files and normalize their implied id
    # through aliases.to_canonical. This is the read-side of the alignment
    # contract — anything not in aliases.json is surfaced as an orphan so
    # callers don't get confused by silent name drift.
    for vendor_dir in sorted(resolved_dir.iterdir()):
        if not vendor_dir.is_dir():
            continue
        for model_file in sorted(vendor_dir.glob("*.jsonl")):
            raw_id = f"{vendor_dir.name}/{model_file.stem}"
            try:
                normalized = aliases.to_canonical(raw_id)
            except UnknownModelError:
                orphans.append(raw_id)
                continue
            entries = _load_fingerprint_file(model_file)
            if entries:
                result[normalized] = entries

    if orphans:
        logger.warning(
            "fingerprint dir %s contains unrecognized model files: %s. "
            "Add them to aliases.json (or rename) so verify_gateway can find them.",
            resolved_dir,
            orphans,
        )

    if canonical_model_id not in result:
        available = sorted(result.keys())
        if available:
            detail = (
                f"no fingerprint for '{canonical_model_id}' in the current "
                f"release. Models covered: {', '.join(available)}. "
                f"Call list_supported_models for the live list."
            )
        else:
            detail = f"fingerprint directory {resolved_dir} exists but is empty"
        raise FingerprintDataMissingError(detail=detail)

    return result


def _load_fingerprint_file(path: Path) -> list[FingerprintEntry]:
    entries: list[FingerprintEntry] = []
    with path.open("r", encoding="utf-8") as f:
        for line in f:
            line = line.strip()
            if not line:
                continue
            try:
                entries.append(FingerprintEntry.model_validate_json(line))
            except Exception as exc:
                logger.warning("skipping malformed fingerprint entry in %s: %s", path, exc)
    return entries


def _resolve_fingerprint_dir(explicit: Path | str | None) -> Path | None:
    if explicit is not None:
        return Path(explicit)
    env = os.environ.get("APIGUARD_FINGERPRINT_DIR")
    if env:
        return Path(env).expanduser()
    return None


# Versioning constants that make it into the Verdict so users can tell
# which data set produced a given verdict.
PROBE_SET_VERSION = "v1"
FINGERPRINT_VERSION_ENV = "APIGUARD_FINGERPRINT_VERSION"


def current_fingerprint_version() -> str:
    """Best-effort tag for the active fingerprint data.

    Returns the APIGUARD_FINGERPRINT_VERSION env var if set (typically
    injected by the M3 release fetcher as `v2026.04.20` etc), else 'unset'.
    """
    return os.environ.get(FINGERPRINT_VERSION_ENV, "unset")
