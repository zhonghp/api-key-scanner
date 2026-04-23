#!/usr/bin/env python3
"""Validate a fingerprints directory plus MANIFEST.json."""

from __future__ import annotations

import argparse
import hashlib
import sys
from collections import defaultdict
from dataclasses import dataclass
from pathlib import Path

from api_key_scanner import aliases
from api_key_scanner import probes as probes_mod
from api_key_scanner.aliases import UnknownModelError
from api_key_scanner.schemas import FingerprintEntry, Manifest


@dataclass(frozen=True)
class _FileStats:
    num_samples: int
    num_probes: int
    per_probe_counts: dict[str, int]


def _sha256(path: Path) -> str:
    h = hashlib.sha256()
    with path.open("rb") as f:
        for chunk in iter(lambda: f.read(64 * 1024), b""):
            h.update(chunk)
    return h.hexdigest()


def _validate_file_schema(path: Path) -> tuple[list[str], _FileStats]:
    """Return (per-line schema errors, derived file stats)."""
    errs: list[str] = []
    per_probe_counts: dict[str, int] = defaultdict(int)
    num_samples = 0
    with path.open("r", encoding="utf-8") as f:
        for i, line in enumerate(f, start=1):
            line = line.strip()
            if not line:
                continue
            try:
                entry = FingerprintEntry.model_validate_json(line)
            except Exception as exc:
                errs.append(f"{path.name}:{i}: {type(exc).__name__}: {exc}")
                if len(errs) >= 5:
                    errs.append(f"{path.name}: ... (more errors truncated)")
                    return errs, _FileStats(0, 0, {})
                continue
            num_samples += 1
            per_probe_counts[entry.probe_id] += 1
    return errs, _FileStats(num_samples, len(per_probe_counts), dict(per_probe_counts))


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
                    f"{canonical_id}: not in aliases.json - verify_gateway won't find this file"
                )
                continue
            if resolved != canonical_id:
                errs.append(
                    f"{canonical_id}: resolves to {resolved} "
                    f"(case/alias drift - rename or fix aliases)"
                )
    return errs


def _validate_manifest(
    fp_dir: Path,
    manifest_path: Path,
    *,
    require_complete: bool,
    require_clean_metadata: bool,
    require_probe_snapshot_match: bool,
    file_stats: dict[str, _FileStats],
) -> list[str]:
    errs: list[str] = []
    try:
        manifest = Manifest.model_validate_json(manifest_path.read_text(encoding="utf-8"))
    except Exception as exc:
        return [f"MANIFEST.json failed schema validation: {type(exc).__name__}: {exc}"]

    if not manifest.models:
        errs.append("MANIFEST.json has no models[]")
        return errs

    basename_to_models: dict[str, list[str]] = defaultdict(list)
    for canonical_id, entry in manifest.models.items():
        basename_to_models[Path(entry.file).name].append(canonical_id)
    for basename, owners in sorted(basename_to_models.items()):
        if len(owners) > 1:
            errs.append(
                f"basename collision: {basename} referenced by multiple models {sorted(owners)}"
            )

    if require_probe_snapshot_match:
        try:
            expected_snapshot = probes_mod.bundled_probes_snapshot(manifest.probe_set_version)
        except ValueError as exc:
            errs.append(str(exc))
        else:
            if manifest.probes_snapshot != expected_snapshot:
                errs.append(
                    "MANIFEST.json probes_snapshot does not match bundled probe files for "
                    f"{manifest.probe_set_version}"
                )

    for canonical_id, entry in manifest.models.items():
        file_rel = entry.file
        expected_sha = entry.sha256
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

        stats = file_stats.get(file_rel)
        if stats is None:
            errs.append(f"{canonical_id}: no derived file stats for {file_rel}")
            continue

        if entry.num_samples != stats.num_samples:
            errs.append(
                f"{canonical_id}: num_samples mismatch (manifest={entry.num_samples} actual={stats.num_samples})"
            )
        if entry.num_probes != stats.num_probes:
            errs.append(
                f"{canonical_id}: num_probes mismatch (manifest={entry.num_probes} actual={stats.num_probes})"
            )
        if (
            entry.quality.actual_samples is not None
            and entry.quality.actual_samples != stats.num_samples
        ):
            errs.append(
                f"{canonical_id}: quality.actual_samples mismatch "
                f"(manifest={entry.quality.actual_samples} actual={stats.num_samples})"
            )

        if require_complete:
            expected_counts = entry.quality.per_probe_expected_samples
            if not expected_counts:
                errs.append(
                    f"{canonical_id}: missing quality.per_probe_expected_samples under --require-complete"
                )
            else:
                missing_probe_ids = sorted(
                    probe_id for probe_id, actual in stats.per_probe_counts.items() if actual == 0
                )
                missing_probe_ids.extend(
                    probe_id
                    for probe_id in expected_counts
                    if probe_id not in stats.per_probe_counts
                )
                missing_probe_ids = sorted(set(missing_probe_ids))
                incomplete_probe_ids = sorted(
                    probe_id
                    for probe_id, expected in expected_counts.items()
                    if 0 < stats.per_probe_counts.get(probe_id, 0) < expected
                )
                if entry.quality.expected_samples is None:
                    errs.append(
                        f"{canonical_id}: missing quality.expected_samples under --require-complete"
                    )
                elif entry.quality.expected_samples != stats.num_samples:
                    errs.append(
                        f"{canonical_id}: expected_samples mismatch "
                        f"(expected={entry.quality.expected_samples} actual={stats.num_samples})"
                    )
                if entry.quality.expected_num_probes is None:
                    errs.append(
                        f"{canonical_id}: missing quality.expected_num_probes under --require-complete"
                    )
                elif entry.quality.expected_num_probes != len(expected_counts):
                    errs.append(
                        f"{canonical_id}: expected_num_probes mismatch "
                        f"(expected={entry.quality.expected_num_probes} actual={len(expected_counts)})"
                    )
                if missing_probe_ids != sorted(entry.quality.missing_probe_ids):
                    errs.append(
                        f"{canonical_id}: missing_probe_ids drift "
                        f"(manifest={sorted(entry.quality.missing_probe_ids)} actual={missing_probe_ids})"
                    )
                if incomplete_probe_ids != sorted(entry.quality.incomplete_probe_ids):
                    errs.append(
                        f"{canonical_id}: incomplete_probe_ids drift "
                        f"(manifest={sorted(entry.quality.incomplete_probe_ids)} actual={incomplete_probe_ids})"
                    )
                actual_per_probe = {
                    probe_id: stats.per_probe_counts.get(probe_id, 0)
                    for probe_id in expected_counts
                }
                if actual_per_probe != entry.quality.per_probe_actual_samples:
                    errs.append(
                        f"{canonical_id}: per_probe_actual_samples drift "
                        f"(manifest={entry.quality.per_probe_actual_samples} actual={actual_per_probe})"
                    )
                if missing_probe_ids or incomplete_probe_ids:
                    errs.append(
                        f"{canonical_id}: incomplete fingerprint "
                        f"(missing={missing_probe_ids}, incomplete={incomplete_probe_ids})"
                    )

        if require_clean_metadata and entry.quality.metadata_anomalies:
            errs.append(
                f"{canonical_id}: metadata anomalies present under "
                f"--require-clean-metadata ({len(entry.quality.metadata_anomalies)})"
            )

    for vendor_dir in sorted(fp_dir.iterdir()):
        if not vendor_dir.is_dir() or vendor_dir.name.startswith("."):
            continue
        for jsonl in sorted(vendor_dir.glob("*.jsonl")):
            canonical_id = f"{vendor_dir.name}/{jsonl.stem}"
            if canonical_id not in manifest.models:
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
    parser.add_argument(
        "--require-complete",
        action="store_true",
        help="Fail if any model is missing expected probe samples",
    )
    parser.add_argument(
        "--require-clean-metadata",
        action="store_true",
        help="Fail if manifest records metadata anomalies for any model",
    )
    parser.add_argument(
        "--skip-probe-snapshot-check",
        action="store_true",
        help="Skip verifying MANIFEST.probes_snapshot against bundled probe files",
    )
    args = parser.parse_args()

    fp_dir = Path(args.fingerprints_dir)
    if not fp_dir.is_dir():
        print(f"error: {fp_dir} is not a directory", file=sys.stderr)
        return 2

    all_errs: list[str] = []

    schema_errs: list[str] = []
    file_stats: dict[str, _FileStats] = {}
    jsonl_files = list(fp_dir.rglob("*.jsonl"))
    for jsonl in jsonl_files:
        errs, stats = _validate_file_schema(jsonl)
        schema_errs.extend(errs)
        file_stats[jsonl.relative_to(fp_dir).as_posix()] = stats

    alignment_errs = _validate_alignment(fp_dir)

    manifest_errs: list[str] = []
    if not args.skip_manifest:
        manifest_path = Path(args.manifest) if args.manifest else fp_dir / "MANIFEST.json"
        if not manifest_path.exists():
            manifest_errs.append(f"{manifest_path} not found - run generate_manifest.py first")
        else:
            manifest_errs = _validate_manifest(
                fp_dir,
                manifest_path,
                require_complete=args.require_complete,
                require_clean_metadata=args.require_clean_metadata,
                require_probe_snapshot_match=not args.skip_probe_snapshot_check,
                file_stats=file_stats,
            )

    print(f"[validate] {len(jsonl_files)} JSONL files in {fp_dir}", file=sys.stderr)
    for label, errs in (
        ("schema", schema_errs),
        ("alignment", alignment_errs),
        ("manifest", manifest_errs),
    ):
        if errs:
            print(f"[validate] {label} FAILED ({len(errs)} errors):", file=sys.stderr)
            for err in errs:
                print(f"  - {err}", file=sys.stderr)
            all_errs.extend(errs)
        else:
            print(f"[validate] {label}: ok", file=sys.stderr)

    if all_errs:
        return 1
    return 0


if __name__ == "__main__":
    sys.exit(main())
