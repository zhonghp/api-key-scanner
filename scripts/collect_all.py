#!/usr/bin/env python3
"""Batch fingerprint collection driver (M3).

Reads models.yaml, iterates through every enabled entry, and runs the same
probe protocol that verify_gateway uses against each configured endpoint.
Output layout matches what probes.load_fingerprints expects:

    fingerprints/<vendor>/<model>.jsonl

For every collected JSONL we also write a sibling ``.meta.json`` sidecar with
the probe budget, expected sample counts, request overrides, provenance, and
collection anomalies. ``generate_manifest.py`` consumes those sidecars so the
release manifest is built from the same collection facts the collector saw.
"""

from __future__ import annotations

import argparse
import asyncio
import json
import os
import sys
from collections import Counter
from dataclasses import dataclass
from datetime import datetime, timezone
from pathlib import Path
from typing import Any

import yaml
from dotenv import load_dotenv

from api_key_scanner import aliases
from api_key_scanner import probes as probes_mod
from api_key_scanner.aliases import UnknownModelError
from api_key_scanner.gateway import ClientConfig, OpenAICompatClient
from api_key_scanner.schemas import (
    Budget,
    CollectedFingerprintSidecar,
    Probe,
    ProbeResponse,
    ReferenceMode,
    validate_request_omit_fields,
    validate_request_overrides_dict,
)


@dataclass(frozen=True)
class _CollectionDefaults:
    default_budget: Budget
    probe_set_version: str
    reference_mode: ReferenceMode


@dataclass(frozen=True)
class _ModelTarget:
    canonical_id: str
    endpoint: str
    model_id: str
    key_env: str
    budget: Budget
    request_overrides: dict[str, Any]
    request_omit_fields: list[str]
    reference_mode: ReferenceMode
    notes: str | None = None


@dataclass(frozen=True)
class _CollectionResult:
    canonical_id: str
    actual_samples: int
    failed_samples: int
    expected_samples: int
    missing_probe_ids: list[str]
    incomplete_probe_ids: list[str]
    metadata_anomalies: list[dict[str, Any]]


def _normalize_reference_mode(raw: object) -> ReferenceMode:
    if raw in ("vendor_direct", "internal_gateway", "unknown"):
        return raw
    raise ValueError("reference_mode must be one of: vendor_direct, internal_gateway, unknown")


def _load_config(path: Path) -> tuple[list[_ModelTarget], _CollectionDefaults]:
    """Parse models.yaml into enabled targets plus collection defaults."""
    with path.open("r", encoding="utf-8") as f:
        cfg = yaml.safe_load(f) or {}

    collection = cfg.get("collection", {}) or {}
    defaults = _CollectionDefaults(
        default_budget=collection.get("default_budget", "cheap"),
        probe_set_version=collection.get(
            "probe_set_version", probes_mod.current_probe_set_version()
        ),
        reference_mode=_normalize_reference_mode(collection.get("reference_mode", "unknown")),
    )

    targets: list[_ModelTarget] = []
    for entry in cfg.get("models", []) or []:
        if not entry.get("enabled", True):
            continue
        request_overrides = entry.get("request_overrides") or {}
        if not isinstance(request_overrides, dict):
            raise ValueError(
                f"{entry.get('canonical_id', '<unknown>')}: request_overrides must be a mapping"
            )
        request_omit_fields = entry.get("request_omit_fields") or []
        if not isinstance(request_omit_fields, list) or not all(
            isinstance(field, str) for field in request_omit_fields
        ):
            raise ValueError(
                f"{entry.get('canonical_id', '<unknown>')}: request_omit_fields must be a list of strings"
            )
        try:
            validate_request_overrides_dict(request_overrides)
            request_omit_fields = validate_request_omit_fields(request_omit_fields)
        except ValueError as exc:
            raise ValueError(f"{entry.get('canonical_id', '<unknown>')}: {exc}") from exc
        targets.append(
            _ModelTarget(
                canonical_id=entry["canonical_id"],
                endpoint=entry["endpoint"],
                model_id=entry["model_id"],
                key_env=entry["key_env"],
                budget=entry.get("budget", defaults.default_budget),
                request_overrides=request_overrides,
                request_omit_fields=request_omit_fields,
                reference_mode=_normalize_reference_mode(
                    entry.get("reference_mode", defaults.reference_mode)
                ),
                notes=entry.get("notes"),
            )
        )
    return targets, defaults


def _validate_alignment(targets: list[_ModelTarget]) -> list[str]:
    """Every canonical_id must map to itself through aliases.to_canonical."""
    errors: list[str] = []
    for target in targets:
        try:
            resolved = aliases.to_canonical(target.canonical_id)
        except UnknownModelError:
            errors.append(
                f"{target.canonical_id!r}: not in aliases.json canonical[] - add it or fix models.yaml"
            )
            continue
        if resolved != target.canonical_id:
            errors.append(
                f"{target.canonical_id!r}: canonical form resolves to {resolved!r} "
                f"(case/alias drift - pick one spelling)"
            )
    return errors


def _meta_path_for(jsonl_path: Path) -> Path:
    return jsonl_path.with_suffix(".meta.json")


def _build_success_entry(response: ProbeResponse, *, collected_at: str) -> dict[str, Any]:
    return {
        "probe_id": response.probe_id,
        "sample_index": response.sample_index,
        "output": response.output,
        "output_tokens": response.output_tokens,
        "response_ms": response.response_ms,
        "ttft_ms": response.ttft_ms,
        "system_fingerprint": response.system_fingerprint,
        "finish_reason": response.finish_reason,
        "reasoning_tokens": response.reasoning_tokens,
        "collected_at": collected_at,
    }


def _analyze_responses(
    probes: list[Probe], responses: list[ProbeResponse]
) -> tuple[list[dict[str, Any]], dict[str, int], list[dict[str, Any]]]:
    expected_per_probe = {probe.probe_id: probe.num_samples for probe in probes}
    max_tokens_per_probe = {probe.probe_id: probe.params.max_tokens for probe in probes}
    actual_per_probe = Counter()
    anomalies: list[dict[str, Any]] = []
    successful_entries: list[dict[str, Any]] = []
    collected_at = datetime.now(timezone.utc).isoformat()

    for response in responses:
        if response.error or not response.output:
            continue
        actual_per_probe[response.probe_id] += 1
        successful_entries.append(_build_success_entry(response, collected_at=collected_at))

        probe_max_tokens = max_tokens_per_probe.get(response.probe_id)
        if (
            probe_max_tokens is not None
            and response.output_tokens is not None
            and response.output_tokens > probe_max_tokens
        ):
            anomalies.append(
                {
                    "kind": "output_tokens_exceeds_max_tokens",
                    "probe_id": response.probe_id,
                    "sample_index": response.sample_index,
                    "reported_output_tokens": response.output_tokens,
                    "probe_max_tokens": probe_max_tokens,
                }
            )
        if response.reasoning_tokens is not None and response.reasoning_tokens > 0:
            anomalies.append(
                {
                    "kind": "reasoning_tokens_present",
                    "probe_id": response.probe_id,
                    "sample_index": response.sample_index,
                    "reasoning_tokens": response.reasoning_tokens,
                }
            )

    actual_counts = {
        probe_id: actual_per_probe.get(probe_id, 0) for probe_id in sorted(expected_per_probe)
    }
    return successful_entries, actual_counts, anomalies


async def _collect_one(
    target: _ModelTarget,
    *,
    out_dir: Path,
    declared_probe_set_version: str,
) -> _CollectionResult:
    """Collect a single model's fingerprint and write JSONL + sidecar."""
    key = os.environ.get(target.key_env)
    if not key:
        print(
            f"[collect] SKIP {target.canonical_id}: env var {target.key_env} not set",
            file=sys.stderr,
        )
        return _CollectionResult(
            canonical_id=target.canonical_id,
            actual_samples=0,
            failed_samples=0,
            expected_samples=0,
            missing_probe_ids=[],
            incomplete_probe_ids=[],
            metadata_anomalies=[],
        )

    probes = probes_mod.load_probes_for_version(
        target.budget, probe_set_version=declared_probe_set_version
    )
    expected_per_probe = {probe.probe_id: probe.num_samples for probe in probes}
    expected_samples = sum(expected_per_probe.values())
    print(
        f"[collect] {target.canonical_id}: {target.endpoint} "
        f"model={target.model_id} budget={target.budget} "
        f"({len(probes)} probes x {expected_samples} samples)",
        file=sys.stderr,
    )

    client = OpenAICompatClient(
        ClientConfig(
            endpoint_url=target.endpoint,
            api_key=key,
            model=target.model_id,
            concurrency=3,
            max_retries=3,
            request_overrides=target.request_overrides,
            request_omit_fields=target.request_omit_fields,
        )
    )
    responses = await client.run_probes(probes)
    successful_entries, actual_per_probe, metadata_anomalies = _analyze_responses(probes, responses)
    failed_responses = [response for response in responses if response.error or not response.output]
    for response in failed_responses[:3]:
        print(
            f"[collect]   {target.canonical_id} skip "
            f"{response.probe_id}#{response.sample_index}: "
            f"{response.error or 'empty output'}",
            file=sys.stderr,
        )
    if len(failed_responses) > 3:
        print(
            f"[collect]   {target.canonical_id}: "
            f"... {len(failed_responses) - 3} more failed samples omitted",
            file=sys.stderr,
        )

    vendor, model_name = target.canonical_id.split("/", 1)
    out_file = out_dir / vendor / f"{model_name}.jsonl"
    out_file.parent.mkdir(parents=True, exist_ok=True)

    with out_file.open("w", encoding="utf-8") as f:
        for entry in successful_entries:
            f.write(json.dumps(entry, ensure_ascii=False) + "\n")

    missing_probe_ids = sorted(
        probe_id for probe_id, actual in actual_per_probe.items() if actual == 0
    )
    incomplete_probe_ids = sorted(
        probe_id
        for probe_id, expected in expected_per_probe.items()
        if 0 < actual_per_probe.get(probe_id, 0) < expected
    )

    sidecar = CollectedFingerprintSidecar.model_validate(
        {
            "canonical_id": target.canonical_id,
            "model_id": target.model_id,
            "budget": target.budget,
            "probe_set_version": declared_probe_set_version,
            "reference_mode": target.reference_mode,
            "request_overrides": target.request_overrides,
            "request_omit_fields": target.request_omit_fields,
            "verification_overrides_required": bool(
                target.request_overrides or target.request_omit_fields
            ),
            "expected_num_probes": len(probes),
            "expected_samples": expected_samples,
            "actual_samples": len(successful_entries),
            "missing_probe_ids": missing_probe_ids,
            "incomplete_probe_ids": incomplete_probe_ids,
            "per_probe_expected_samples": expected_per_probe,
            "per_probe_actual_samples": actual_per_probe,
            "metadata_anomalies": metadata_anomalies,
            "notes": target.notes,
        }
    )
    _meta_path_for(out_file).write_text(
        json.dumps(
            sidecar.model_dump(mode="json", exclude_none=True),
            indent=2,
            ensure_ascii=False,
        )
        + "\n",
        encoding="utf-8",
    )

    failed_samples = sum(1 for response in responses if response.error or not response.output)
    print(
        f"[collect] {target.canonical_id}: wrote {len(successful_entries)} samples "
        f"({failed_samples} failed, {len(metadata_anomalies)} anomalies) to {out_file}",
        file=sys.stderr,
    )
    return _CollectionResult(
        canonical_id=target.canonical_id,
        actual_samples=len(successful_entries),
        failed_samples=failed_samples,
        expected_samples=expected_samples,
        missing_probe_ids=missing_probe_ids,
        incomplete_probe_ids=incomplete_probe_ids,
        metadata_anomalies=metadata_anomalies,
    )


async def _main() -> int:
    parser = argparse.ArgumentParser(
        description="Batch-collect fingerprints for every enabled model in models.yaml."
    )
    parser.add_argument("--config", default="models.yaml", help="Path to models.yaml")
    parser.add_argument("--out", default="./fingerprints", help="Output root directory")
    parser.add_argument(
        "--env-file",
        default=".env",
        help="Path to .env (loaded before reading key_env vars)",
    )
    parser.add_argument(
        "--only",
        action="append",
        default=None,
        help="Only collect these canonical ids (can be repeated). Default: all enabled.",
    )
    parser.add_argument(
        "--fail-on-empty",
        action="store_true",
        help="Exit non-zero if any enabled model produced 0 samples",
    )
    parser.add_argument(
        "--require-complete",
        action="store_true",
        help="Exit non-zero if any enabled model is missing probe samples",
    )
    args = parser.parse_args()

    env_path = Path(args.env_file)
    if env_path.exists():
        load_dotenv(dotenv_path=env_path, override=False)
        print(f"[collect] loaded {env_path}", file=sys.stderr)

    alias_report = aliases.validate_aliases_file()
    if not alias_report.ok:
        print("[collect] aliases.json has ERRORS:", file=sys.stderr)
        for error in alias_report.errors:
            print(f"  - {error}", file=sys.stderr)
        return 2

    config_path = Path(args.config)
    if not config_path.exists():
        print(f"error: {config_path} not found", file=sys.stderr)
        return 2
    try:
        targets, defaults = _load_config(config_path)
    except (ValueError, KeyError) as exc:
        print(f"error: invalid {config_path}: {exc}", file=sys.stderr)
        return 2

    active_probe_set_version = probes_mod.current_probe_set_version()
    if defaults.probe_set_version != active_probe_set_version:
        print(
            "[collect] models.yaml probe_set_version mismatch: "
            f"config declares {defaults.probe_set_version!r} but active client uses "
            f"{active_probe_set_version!r}. Set APIGUARD_PROBE_SET_VERSION to match "
            "or update models.yaml before collecting.",
            file=sys.stderr,
        )
        return 2

    if args.only:
        wanted = set(args.only)
        targets = [target for target in targets if target.canonical_id in wanted]
        if not targets:
            print(f"error: no enabled targets match --only {args.only}", file=sys.stderr)
            return 2

    if not targets:
        print("[collect] no enabled targets in models.yaml; nothing to do", file=sys.stderr)
        return 0

    alignment_errors = _validate_alignment(targets)
    if alignment_errors:
        print("[collect] models.yaml / aliases.json misalignment:", file=sys.stderr)
        for error in alignment_errors:
            print(f"  - {error}", file=sys.stderr)
        return 2

    out_dir = Path(args.out)
    out_dir.mkdir(parents=True, exist_ok=True)
    print(f"[collect] starting batch: {len(targets)} models -> {out_dir}", file=sys.stderr)

    totals: list[_CollectionResult] = []
    for target in targets:
        totals.append(
            await _collect_one(
                target,
                out_dir=out_dir,
                declared_probe_set_version=defaults.probe_set_version,
            )
        )

    print("\n[collect] summary:", file=sys.stderr)
    empty_models: list[str] = []
    incomplete_models: list[str] = []
    for result in totals:
        if result.actual_samples == 0:
            status = "EMPTY"
            empty_models.append(result.canonical_id)
        elif (
            result.actual_samples != result.expected_samples
            or result.missing_probe_ids
            or result.incomplete_probe_ids
        ):
            status = "INCOMPLETE"
            incomplete_models.append(result.canonical_id)
        else:
            status = "ok"
        print(
            f"  {status:10} {result.canonical_id:40} "
            f"{result.actual_samples:4}/{result.expected_samples:<4} "
            f"samples ({result.failed_samples} failed, {len(result.metadata_anomalies)} anomalies)",
            file=sys.stderr,
        )

    if empty_models and args.fail_on_empty:
        print(
            f"[collect] ERROR: {len(empty_models)} models produced 0 samples "
            f"(--fail-on-empty): {empty_models}",
            file=sys.stderr,
        )
        return 1

    if incomplete_models and args.require_complete:
        print(
            f"[collect] ERROR: {len(incomplete_models)} models are incomplete "
            f"(--require-complete): {incomplete_models}",
            file=sys.stderr,
        )
        return 1

    return 0


def main() -> int:
    return asyncio.run(_main())


if __name__ == "__main__":
    sys.exit(main())
