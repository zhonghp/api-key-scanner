#!/usr/bin/env python3
"""Validate a fingerprints directory + its MANIFEST.json (M3 step 3).

Runs three kinds of check:

  1. Schema — every JSONL line parses as a FingerprintEntry
  2. Alignment — every file path implies a canonical_id that aliases.to_canonical accepts
  3. Manifest integrity — recompute sha256 of every file, compare to MANIFEST

Used in CI on PRs that touch the fingerprints directory (`.github/workflows/
validate.yml`) and as the last step of the weekly collection workflow before
uploading to GitHub Releases.
"""

from __future__ import annotations

import argparse
import hashlib
import json
import sys
from pathlib import Path

from api_key_scanner import aliases
from api_key_scanner.aliases import UnknownModelError
from api_key_scanner.schemas import FingerprintEntry


def _sha256(path: Path) -> str:
    h = hashlib.sha256()
    with path.open("rb") as f:
        for chunk in iter(lambda: f.read(64 * 1024), b""):
            h.update(chunk)
    return h.hexdigest()


def _validate_file_schema(path: Path) -> list[str]:
    """Return list of per-line schema errors; empty list = all lines OK."""
    errs: list[str] = []
    with path.open("r", encoding="utf-8") as f:
        for i, line in enumerate(f, start=1):
            line = line.strip()
            if not line:
                continue
            try:
                FingerprintEntry.model_validate_json(line)
            except Exception as exc:
                errs.append(f"{path.name}:{i}: {type(exc).__name__}: {exc}")
                if len(errs) >= 5:  # cap per-file
                    errs.append(f"{path.name}: ... (more errors truncated)")
                    return errs
    return errs


def _validate_alignment(fp_dir: Path) -> list[str]:
    errs: list[str] = []
    for vendor_dir in sorted(fp_dir.iterdir()):
        if not vendor_dir.is_dir() or vendor_dir.name.startswith("."):
            continue
        for jsonl in sorted(vendor_dir.glob("*.jsonl")):
            canonical_id = f"{vendor_dir.name}/{jsonl.stem}"
            try:
                resolved = aliases.to_canonical(canonical_id)
            except UnknownModelError:
                errs.append(
                    f"{canonical_id}: not in aliases.json — verify_gateway won't find this file"
                )
                continue
            if resolved != canonical_id:
                errs.append(
                    f"{canonical_id}: resolves to {resolved} "
                    f"(case/alias drift — rename or fix aliases)"
                )
    return errs


def _validate_manifest(fp_dir: Path, manifest_path: Path) -> list[str]:
    errs: list[str] = []
    with manifest_path.open("r", encoding="utf-8") as f:
        manifest = json.load(f)

    models = manifest.get("models", {})
    if not models:
        errs.append("MANIFEST.json has no models[]")
        return errs

    for canonical_id, entry in models.items():
        file_rel = entry.get("file")
        expected_sha = entry.get("sha256")
        if not file_rel or not expected_sha:
            errs.append(f"{canonical_id}: manifest entry missing file or sha256")
            continue

        file_path = fp_dir / file_rel
        if not file_path.exists():
            errs.append(f"{canonical_id}: manifest references {file_rel} but file missing")
            continue

        actual_sha = _sha256(file_path)
        if actual_sha != expected_sha:
            errs.append(
                f"{canonical_id}: sha256 mismatch "
                f"(manifest={expected_sha[:12]}... actual={actual_sha[:12]}...)"
            )

    # Cross-check: every file on disk is in manifest
    for vendor_dir in sorted(fp_dir.iterdir()):
        if not vendor_dir.is_dir() or vendor_dir.name.startswith("."):
            continue
        for jsonl in sorted(vendor_dir.glob("*.jsonl")):
            canonical_id = f"{vendor_dir.name}/{jsonl.stem}"
            if canonical_id not in models:
                errs.append(f"{canonical_id}: file exists but missing from MANIFEST.json")

    return errs


def main() -> int:
    parser = argparse.ArgumentParser(
        description="Validate a fingerprints directory + MANIFEST.json."
    )
    parser.add_argument("fingerprints_dir", help="Path containing <vendor>/<model>.jsonl files")
    parser.add_argument(
        "--manifest",
        default=None,
        help="Path to MANIFEST.json (default: <fingerprints_dir>/MANIFEST.json)",
    )
    parser.add_argument(
        "--skip-manifest",
        action="store_true",
        help="Only run schema + alignment checks, not manifest integrity",
    )
    args = parser.parse_args()

    fp_dir = Path(args.fingerprints_dir)
    if not fp_dir.is_dir():
        print(f"error: {fp_dir} is not a directory", file=sys.stderr)
        return 2

    all_errs: list[str] = []

    # 1. Schema
    schema_errs: list[str] = []
    jsonl_files = list(fp_dir.rglob("*.jsonl"))
    for jsonl in jsonl_files:
        schema_errs.extend(_validate_file_schema(jsonl))

    # 2. Alignment
    alignment_errs = _validate_alignment(fp_dir)

    # 3. Manifest
    manifest_errs: list[str] = []
    if not args.skip_manifest:
        manifest_path = Path(args.manifest) if args.manifest else fp_dir / "MANIFEST.json"
        if not manifest_path.exists():
            manifest_errs.append(f"{manifest_path} not found — run generate_manifest.py first")
        else:
            manifest_errs = _validate_manifest(fp_dir, manifest_path)

    # Report
    print(f"[validate] {len(jsonl_files)} JSONL files in {fp_dir}", file=sys.stderr)
    for label, errs in (
        ("schema", schema_errs),
        ("alignment", alignment_errs),
        ("manifest", manifest_errs),
    ):
        if errs:
            print(f"[validate] {label} FAILED ({len(errs)} errors):", file=sys.stderr)
            for e in errs:
                print(f"  - {e}", file=sys.stderr)
            all_errs.extend(errs)
        else:
            print(f"[validate] {label}: ok", file=sys.stderr)

    if all_errs:
        return 1
    return 0


if __name__ == "__main__":
    sys.exit(main())
