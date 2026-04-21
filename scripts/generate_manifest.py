#!/usr/bin/env python3
"""Generate MANIFEST.json from a fingerprints output directory (M3 step 2).

Walks <dir>/<vendor>/<model>.jsonl and produces:
    <dir>/MANIFEST.json

containing per-file sha256 sums plus collection provenance metadata.
This manifest is what Sigstore will sign in CI, and what downstream
verify_gateway clients will check before trusting the data.

Run after collect_all.py:
    uv run python scripts/collect_all.py --out ./fingerprints
    uv run python scripts/generate_manifest.py ./fingerprints
    # -> ./fingerprints/MANIFEST.json
"""

from __future__ import annotations

import argparse
import hashlib
import json
import os
import sys
from datetime import datetime, timezone
from pathlib import Path

from api_key_scanner import __version__ as collector_version
from api_key_scanner import aliases
from api_key_scanner.aliases import UnknownModelError

_PROBE_FILES = ("llmmap_v1.jsonl", "met_v1.jsonl")


def _sha256_of_file(path: Path) -> str:
    h = hashlib.sha256()
    with path.open("rb") as f:
        for chunk in iter(lambda: f.read(64 * 1024), b""):
            h.update(chunk)
    return h.hexdigest()


def _count_jsonl_lines(path: Path) -> int:
    count = 0
    with path.open("r", encoding="utf-8") as f:
        for line in f:
            if line.strip():
                count += 1
    return count


def _probes_snapshot() -> dict[str, str]:
    """Hash the probe JSONL files currently shipped with the installed package.

    Consumers can cross-check that their fingerprint data was collected from
    the same probe set version they're using.
    """
    from importlib import resources

    snapshot: dict[str, str] = {}
    for fname in _PROBE_FILES:
        # 3.10 compat: joinpath takes one arg on MultiplexedPath; chain it
        traversable = resources.files("api_key_scanner.data").joinpath("probes").joinpath(fname)
        with traversable.open("rb") as f:
            data = f.read()
        snapshot[fname] = hashlib.sha256(data).hexdigest()
    return snapshot


def _build_manifest(fp_dir: Path, version: str) -> dict:
    """Walk <fp_dir>/<vendor>/<model>.jsonl and build the manifest dict."""
    models: dict[str, dict] = {}
    orphans: list[str] = []

    for vendor_dir in sorted(fp_dir.iterdir()):
        if not vendor_dir.is_dir() or vendor_dir.name.startswith("."):
            continue
        for jsonl in sorted(vendor_dir.glob("*.jsonl")):
            canonical_id = f"{vendor_dir.name}/{jsonl.stem}"
            # Cross-check against aliases
            try:
                resolved = aliases.to_canonical(canonical_id)
            except UnknownModelError:
                orphans.append(canonical_id)
                continue
            if resolved != canonical_id:
                orphans.append(f"{canonical_id} (resolves to {resolved})")
                continue

            rel = jsonl.relative_to(fp_dir).as_posix()
            models[canonical_id] = {
                "file": rel,
                "sha256": _sha256_of_file(jsonl),
                "size_bytes": jsonl.stat().st_size,
                "num_samples": _count_jsonl_lines(jsonl),
                "provenance": {
                    "collector_version": collector_version,
                    # Optional runtime hints; real values come from env in CI
                    "account_tier": os.environ.get("APIGUARD_ACCOUNT_TIER", "unspecified"),
                    "region": os.environ.get("APIGUARD_REGION", "unspecified"),
                },
            }

    if orphans:
        print(
            f"warning: skipped {len(orphans)} orphan model file(s) not in aliases.json:",
            file=sys.stderr,
        )
        for o in orphans:
            print(f"  - {o}", file=sys.stderr)

    return {
        "version": version,
        "probe_set_version": "v1",
        "collected_at": datetime.now(timezone.utc).isoformat(),
        "collector_version": collector_version,
        "models": models,
        "probes_snapshot": _probes_snapshot(),
    }


def main() -> int:
    parser = argparse.ArgumentParser(
        description="Generate MANIFEST.json from a fingerprints output directory."
    )
    parser.add_argument("fingerprints_dir", help="Path containing <vendor>/<model>.jsonl files")
    parser.add_argument(
        "--version",
        default=None,
        help="Manifest version tag; defaults to v<YYYY.MM.DD>",
    )
    parser.add_argument(
        "--out",
        default=None,
        help="Output path (default: <fingerprints_dir>/MANIFEST.json)",
    )
    parser.add_argument(
        "--require-models",
        type=int,
        default=0,
        help="Exit non-zero if fewer than this many models were found",
    )
    args = parser.parse_args()

    fp_dir = Path(args.fingerprints_dir)
    if not fp_dir.is_dir():
        print(f"error: {fp_dir} is not a directory", file=sys.stderr)
        return 2

    version = args.version or f"v{datetime.now(timezone.utc).strftime('%Y.%m.%d')}"
    out_path = Path(args.out) if args.out else fp_dir / "MANIFEST.json"

    manifest = _build_manifest(fp_dir, version=version)
    n_models = len(manifest["models"])

    if n_models < args.require_models:
        print(
            f"error: found {n_models} models but --require-models={args.require_models}",
            file=sys.stderr,
        )
        return 1

    with out_path.open("w", encoding="utf-8") as f:
        json.dump(manifest, f, indent=2, ensure_ascii=False)
        f.write("\n")

    print(
        f"[manifest] {version}: {n_models} models -> {out_path}",
        file=sys.stderr,
    )
    return 0


if __name__ == "__main__":
    sys.exit(main())
