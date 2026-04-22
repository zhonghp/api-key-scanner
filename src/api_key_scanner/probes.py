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

# Per-budget probe loading configuration.
#   probes             — read the first N entries from the file (order matters)
#   samples_per_probe  — hard cap on num_samples; reduces but never upscales
# The "deep" tier was removed after the v2 pool saturates at standard (8 llmmap
# + 25 met = 33 probe types). Future high-confidence tiers should introduce a
# new name (e.g. "strict") rather than reusing "deep".
_BUDGET_CONFIG: dict[Budget, dict[str, dict[str, int]]] = {
    "cheap": {
        "llmmap": {"probes": 3, "samples_per_probe": 1},
        "met": {"probes": 5, "samples_per_probe": 3},
    },  # v2 total: 3 + 15 = 18 calls (smoke test)
    "standard": {
        "llmmap": {"probes": 8, "samples_per_probe": 1},
        "met": {"probes": 25, "samples_per_probe": 10},
    },  # v2 total: 8 + 250 = 258 calls (full MET paper protocol)
}

# Bundled probe files. New versions live alongside older ones so they can be
# selected via APIGUARD_PROBE_SET_VERSION for rollback / A-B testing without
# redeploying the package.
_BUNDLED_FILES: dict[str, dict[str, str]] = {
    "v1": {"llmmap": "llmmap_v1.jsonl", "met": "met_v1.jsonl"},
    "v2": {"llmmap": "llmmap_v2.jsonl", "met": "met_v2.jsonl"},
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


def load_probes(budget: Budget = "cheap") -> list[Probe]:
    """Load the bundled probe set for this budget.

    Probe-set version is :data:`PROBE_SET_VERSION` by default; override via
    ``APIGUARD_PROBE_SET_VERSION`` env var for rollback / A-B testing.
    Budget caps total sample count so users with small quotas don't blow
    up their bill during verification.
    """
    version = current_probe_set_version()
    cfg = _BUDGET_CONFIG[budget]
    files = _BUNDLED_FILES[version]

    probes: list[Probe] = []
    for probe_type in ("llmmap", "met"):
        loaded = _load_bundled_jsonl(files[probe_type], cap=cfg[probe_type]["probes"])
        sample_cap = cfg[probe_type]["samples_per_probe"]
        for probe in loaded:
            if probe.num_samples > sample_cap:
                probe.num_samples = sample_cap
        probes.extend(loaded)
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
    banner-match needs the cross-family references to do nearest-neighbor voting;
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
PROBE_SET_VERSION = "v2"
_PROBE_SET_VERSION_ENV = "APIGUARD_PROBE_SET_VERSION"
FINGERPRINT_VERSION_ENV = "APIGUARD_FINGERPRINT_VERSION"


def current_probe_set_version() -> str:
    """Resolve probe-set version with env-var override.

    Callers should use this (rather than the :data:`PROBE_SET_VERSION`
    constant directly) when reporting the active version at runtime —
    e.g. when populating :class:`Verdict.probe_set_version`.
    """
    version = os.environ.get(_PROBE_SET_VERSION_ENV, PROBE_SET_VERSION)
    if version not in _BUNDLED_FILES:
        raise ValueError(
            f"unknown probe set version: {version}; "
            f"valid: {sorted(_BUNDLED_FILES)}"
        )
    return version


def current_fingerprint_version() -> str:
    """Best-effort tag for the active fingerprint data.

    Returns the APIGUARD_FINGERPRINT_VERSION env var if set (typically
    injected by the M3 release fetcher as `v2026.04.20` etc), else 'unset'.
    """
    return os.environ.get(FINGERPRINT_VERSION_ENV, "unset")
