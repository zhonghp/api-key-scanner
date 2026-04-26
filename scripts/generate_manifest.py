#!/usr/bin/env python3
"""Generate MANIFEST.json from a fingerprints output directory."""

from __future__ import annotations

import argparse
import hashlib
import json
import os
import sys
from datetime import datetime, timezone
from pathlib import Path
from typing import Any

from api_key_scanner import __version__ as collector_version
from api_key_scanner import aliases
from api_key_scanner import probes as probes_mod
from api_key_scanner.aliases import UnknownModelError
from api_key_scanner.schemas import CollectedFingerprintSidecar


def _sha256_of_file(path: Path) -> str:
    h = hashlib.sha256()
    with path.open("rb") as f:
        for chunk in iter(lambda: f.read(64 * 1024), b""):
            h.update(chunk)
    return h.hexdigest()


def _scan_jsonl(path: Path) -> tuple[int, int]:
    """Return (num_nonempty_lines, num_unique_probe_ids)."""
    count = 0
    probe_ids: set[str] = set()
    with path.open("r", encoding="utf-8") as f:
        for line in f:
            line = line.strip()
            if not line:
                continue
            count += 1
            try:
                probe_ids.add(json.loads(line)["probe_id"])
            except Exception:
                continue
    return count, len(probe_ids)


def _meta_path_for(jsonl_path: Path) -> Path:
    return jsonl_path.with_suffix(".meta.json")


def _load_sidecar(jsonl_path: Path) -> CollectedFingerprintSidecar | None:
    meta_path = _meta_path_for(jsonl_path)
    if not meta_path.is_file():
        return None
    try:
        return CollectedFingerprintSidecar.model_validate_json(
            meta_path.read_text(encoding="utf-8")
        )
    except Exception as exc:
        raise ValueError(f"{meta_path} failed sidecar schema validation: {exc}") from exc


def _resolve_probe_set_version(
    models: dict[str, dict[str, Any]],
    explicit_probe_set_version: str | None,
) -> str:
    if explicit_probe_set_version:
        return explicit_probe_set_version

    declared_versions = {
        entry.get("quality", {}).get("probe_set_version")
        for entry in models.values()
        if entry.get("quality", {}).get("probe_set_version")
    }
    declared_versions.discard(None)
    if len(declared_versions) > 1:
        raise ValueError(
            f"collection sidecars disagree on probe_set_version: {sorted(declared_versions)}"
        )
    if declared_versions:
        return declared_versions.pop()
    return probes_mod.current_probe_set_version()


def _build_manifest(fp_dir: Path, version: str, probe_set_version: str | None) -> dict[str, Any]:
    models: dict[str, dict[str, Any]] = {}
    orphans: list[str] = []

    for vendor_dir in sorted(fp_dir.iterdir()):
        if not vendor_dir.is_dir() or vendor_dir.name.startswith("."):
            continue
        for jsonl in sorted(vendor_dir.glob("*.jsonl")):
            if jsonl.name.endswith(".rejected.jsonl"):
                continue
            canonical_id = f"{vendor_dir.name}/{jsonl.stem}"
            try:
                resolved = aliases.to_canonical(canonical_id)
            except UnknownModelError:
                orphans.append(canonical_id)
                continue
            if resolved != canonical_id:
                orphans.append(f"{canonical_id} (resolves to {resolved})")
                continue

            rel = jsonl.relative_to(fp_dir).as_posix()
            sidecar = _load_sidecar(jsonl)
            if sidecar is not None and sidecar.canonical_id != canonical_id:
                raise ValueError(
                    f"{_meta_path_for(jsonl)} canonical_id={sidecar.canonical_id!r} "
                    f"does not match file path {canonical_id!r}"
                )
            num_samples, num_probes = _scan_jsonl(jsonl)
            quality = {
                "probe_set_version": sidecar.probe_set_version if sidecar else None,
                "budget": sidecar.budget if sidecar else None,
                "expected_num_probes": sidecar.expected_num_probes if sidecar else None,
                "expected_samples": sidecar.expected_samples if sidecar else None,
                "actual_samples": sidecar.actual_samples if sidecar else num_samples,
                "missing_probe_ids": sidecar.missing_probe_ids if sidecar else [],
                "incomplete_probe_ids": sidecar.incomplete_probe_ids if sidecar else [],
                "per_probe_expected_samples": (
                    sidecar.per_probe_expected_samples if sidecar else {}
                ),
                "per_probe_actual_samples": sidecar.per_probe_actual_samples if sidecar else {},
                "metadata_anomalies": sidecar.metadata_anomalies if sidecar else [],
            }
            provenance = {
                "collector_version": collector_version,
                "account_tier": os.environ.get("APIGUARD_ACCOUNT_TIER", "unspecified"),
                "region": os.environ.get("APIGUARD_REGION", "unspecified"),
                "model_id": sidecar.model_id if sidecar else canonical_id.split("/", 1)[1],
                "reference_mode": sidecar.reference_mode if sidecar else "unknown",
            }
            if sidecar and sidecar.notes:
                provenance["notes"] = sidecar.notes
            if sidecar and sidecar.auto_detect_label:
                provenance["auto_detect_label"] = sidecar.auto_detect_label
            if sidecar and sidecar.resolved_request_url:
                provenance["resolved_request_url"] = sidecar.resolved_request_url

            models[canonical_id] = {
                "file": rel,
                "sha256": _sha256_of_file(jsonl),
                "size_bytes": jsonl.stat().st_size,
                "num_probes": num_probes,
                "num_samples": num_samples,
                "provenance": provenance,
                "quality": quality,
                "request_overrides": sidecar.request_overrides if sidecar else {},
                "request_omit_fields": sidecar.request_omit_fields if sidecar else [],
                "api_format": sidecar.api_format if sidecar else "openai",
                "auth_scheme": sidecar.auth_scheme if sidecar else "default",
                "verification_overrides_required": (
                    sidecar.verification_overrides_required if sidecar else False
                ),
            }

    if orphans:
        print(
            f"warning: skipped {len(orphans)} orphan model file(s) not in aliases.json:",
            file=sys.stderr,
        )
        for orphan in orphans:
            print(f"  - {orphan}", file=sys.stderr)

    manifest_probe_set_version = _resolve_probe_set_version(
        models=models, explicit_probe_set_version=probe_set_version
    )
    for entry in models.values():
        if entry["quality"].get("probe_set_version") in (None, ""):
            entry["quality"]["probe_set_version"] = manifest_probe_set_version

    return {
        "version": version,
        "probe_set_version": manifest_probe_set_version,
        "collected_at": datetime.now(timezone.utc).isoformat(),
        "collector_version": collector_version,
        "models": models,
        "probes_snapshot": probes_mod.bundled_probes_snapshot(manifest_probe_set_version),
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
    parser.add_argument(
        "--probe-set-version",
        default=None,
        help=(
            "Probe-set version to record in the manifest "
            "(default: inferred from sidecars, else current bundled version)"
        ),
    )
    args = parser.parse_args()

    fp_dir = Path(args.fingerprints_dir)
    if not fp_dir.is_dir():
        print(f"error: {fp_dir} is not a directory", file=sys.stderr)
        return 2

    version = args.version or f"v{datetime.now(timezone.utc).strftime('%Y.%m.%d')}"
    out_path = Path(args.out) if args.out else fp_dir / "MANIFEST.json"

    try:
        manifest = _build_manifest(
            fp_dir, version=version, probe_set_version=args.probe_set_version
        )
    except ValueError as exc:
        print(f"error: {exc}", file=sys.stderr)
        return 2

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
        f"[manifest] {version} probe_set={manifest['probe_set_version']}: "
        f"{n_models} models -> {out_path}",
        file=sys.stderr,
    )
    return 0


if __name__ == "__main__":
    sys.exit(main())
