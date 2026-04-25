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
    FingerprintEntry,
    Probe,
    ProbeResponse,
    ReferenceMode,
    validate_request_omit_fields,
    validate_request_overrides_dict,
)

_DEFAULT_QUALITY_RETRIES = 2
_DEFAULT_MIN_OUTPUT_CHARS_FOR_HIGH_REASONING = 120
_DEFAULT_HIGH_REASONING_TOKENS = 128


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


@dataclass(frozen=True)
class _ResumeSnapshot:
    entries_by_key: dict[tuple[str, int], dict[str, Any]]
    ignored_entries: int
    duplicate_entries: int
    quality_rejected_entries: int


@dataclass(frozen=True)
class _QualityPolicy:
    enabled: bool
    retries: int
    min_output_chars_for_high_reasoning: int
    high_reasoning_tokens: int


@dataclass(frozen=True)
class _SampleFailure:
    probe_id: str
    sample_index: int
    reason: str


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


def _fingerprint_path_for(out_dir: Path, canonical_id: str) -> Path:
    vendor, model_name = canonical_id.split("/", 1)
    return out_dir / vendor / f"{model_name}.jsonl"


def _expected_sample_keys(probes: list[Probe]) -> set[tuple[str, int]]:
    return {
        (probe.probe_id, sample_index)
        for probe in probes
        for sample_index in range(probe.num_samples)
    }


def _load_resume_snapshot(
    out_file: Path, probes: list[Probe], quality_policy: _QualityPolicy
) -> _ResumeSnapshot:
    """Load reusable samples from an existing fingerprint JSONL.

    Only entries belonging to the current probe plan are reused. Old entries
    from a different budget/probe-set or duplicate sample indexes are ignored
    so the rewritten file has one row per expected sample.
    """
    if not out_file.exists():
        return _ResumeSnapshot(
            entries_by_key={},
            ignored_entries=0,
            duplicate_entries=0,
            quality_rejected_entries=0,
        )

    expected_keys = _expected_sample_keys(probes)
    entries_by_key: dict[tuple[str, int], dict[str, Any]] = {}
    ignored_entries = 0
    duplicate_entries = 0
    quality_rejected_entries = 0

    with out_file.open("r", encoding="utf-8") as f:
        for line in f:
            line = line.strip()
            if not line:
                continue
            try:
                entry = FingerprintEntry.model_validate_json(line)
            except Exception:
                ignored_entries += 1
                continue

            key = (entry.probe_id, entry.sample_index)
            if key not in expected_keys or not entry.output:
                ignored_entries += 1
                continue
            if _entry_quality_failure_reason(entry, quality_policy):
                quality_rejected_entries += 1
                continue
            if key in entries_by_key:
                duplicate_entries += 1
                continue
            entries_by_key[key] = entry.model_dump(mode="json")

    return _ResumeSnapshot(
        entries_by_key=entries_by_key,
        ignored_entries=ignored_entries,
        duplicate_entries=duplicate_entries,
        quality_rejected_entries=quality_rejected_entries,
    )


def _missing_probe_samples(
    probes: list[Probe], entries_by_key: dict[tuple[str, int], dict[str, Any]]
) -> list[tuple[Probe, int]]:
    return [
        (probe, sample_index)
        for probe in probes
        for sample_index in range(probe.num_samples)
        if (probe.probe_id, sample_index) not in entries_by_key
    ]


def _sort_entries_for_probe_plan(
    probes: list[Probe], entries: list[dict[str, Any]]
) -> list[dict[str, Any]]:
    probe_order = {probe.probe_id: index for index, probe in enumerate(probes)}
    return sorted(
        entries,
        key=lambda entry: (
            probe_order.get(str(entry.get("probe_id")), len(probe_order)),
            int(entry.get("sample_index", 0)),
        ),
    )


def _as_optional_int(value: object) -> int | None:
    if value is None:
        return None
    try:
        return int(value)
    except (TypeError, ValueError):
        return None


def _quality_failure_reason(
    *,
    output: str,
    finish_reason: str | None,
    reasoning_tokens: object,
    policy: _QualityPolicy,
) -> str | None:
    if not output:
        return "empty output"
    if not policy.enabled:
        return None

    if (finish_reason or "").lower() == "length":
        return "finish_reason=length"

    reasoning = _as_optional_int(reasoning_tokens)
    output_chars = len(output.strip())
    if (
        reasoning is not None
        and reasoning >= policy.high_reasoning_tokens
        and output_chars < policy.min_output_chars_for_high_reasoning
    ):
        return f"short output ({output_chars} chars) with high reasoning_tokens={reasoning}"

    return None


def _entry_quality_failure_reason(entry: FingerprintEntry, policy: _QualityPolicy) -> str | None:
    return _quality_failure_reason(
        output=entry.output,
        finish_reason=entry.finish_reason,
        reasoning_tokens=entry.reasoning_tokens,
        policy=policy,
    )


def _response_failure_reason(response: ProbeResponse, policy: _QualityPolicy) -> str | None:
    if response.error:
        return response.error
    return _quality_failure_reason(
        output=response.output,
        finish_reason=response.finish_reason,
        reasoning_tokens=response.reasoning_tokens,
        policy=policy,
    )


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


async def _collect_probe_samples_with_quality_retries(
    client: OpenAICompatClient,
    probe_samples: list[tuple[Probe, int]],
    quality_policy: _QualityPolicy,
    *,
    canonical_id: str,
) -> tuple[list[dict[str, Any]], list[_SampleFailure]]:
    sample_by_key = {
        (probe.probe_id, sample_index): (probe, sample_index)
        for probe, sample_index in probe_samples
    }
    pending = list(probe_samples)
    successful_entries: list[dict[str, Any]] = []
    collected_at = datetime.now(timezone.utc).isoformat()
    final_failures: list[_SampleFailure] = []

    for quality_attempt in range(quality_policy.retries + 1):
        responses = await client.run_probe_samples(pending)
        retry_pending: list[tuple[Probe, int]] = []
        final_failures = []

        for response in responses:
            key = (response.probe_id, response.sample_index)
            failure_reason = _response_failure_reason(response, quality_policy)
            if failure_reason is None:
                successful_entries.append(_build_success_entry(response, collected_at=collected_at))
                continue

            failure = _SampleFailure(
                probe_id=response.probe_id,
                sample_index=response.sample_index,
                reason=failure_reason,
            )
            final_failures.append(failure)
            if quality_attempt < quality_policy.retries and key in sample_by_key:
                retry_pending.append(sample_by_key[key])

        if not retry_pending:
            return successful_entries, final_failures

        print(
            f"[collect]   {canonical_id}: retrying {len(retry_pending)} "
            f"quality-failed samples ({quality_attempt + 1}/"
            f"{quality_policy.retries})",
            file=sys.stderr,
        )
        pending = retry_pending

    return successful_entries, final_failures


def _analyze_entries(
    probes: list[Probe], entries: list[dict[str, Any]]
) -> tuple[dict[str, int], list[dict[str, Any]]]:
    expected_per_probe = {probe.probe_id: probe.num_samples for probe in probes}
    max_tokens_per_probe = {probe.probe_id: probe.params.max_tokens for probe in probes}
    actual_per_probe = Counter()
    anomalies: list[dict[str, Any]] = []

    for entry in entries:
        probe_id = str(entry.get("probe_id"))
        sample_index = int(entry.get("sample_index", 0))
        actual_per_probe[probe_id] += 1

        probe_max_tokens = max_tokens_per_probe.get(probe_id)
        output_tokens = entry.get("output_tokens")
        if (
            probe_max_tokens is not None
            and output_tokens is not None
            and int(output_tokens) > probe_max_tokens
        ):
            anomalies.append(
                {
                    "kind": "output_tokens_exceeds_max_tokens",
                    "probe_id": probe_id,
                    "sample_index": sample_index,
                    "reported_output_tokens": output_tokens,
                    "probe_max_tokens": probe_max_tokens,
                }
            )
        reasoning_tokens = entry.get("reasoning_tokens")
        if reasoning_tokens is not None and int(reasoning_tokens) > 0:
            anomalies.append(
                {
                    "kind": "reasoning_tokens_present",
                    "probe_id": probe_id,
                    "sample_index": sample_index,
                    "reasoning_tokens": reasoning_tokens,
                }
            )

    actual_counts = {
        probe_id: actual_per_probe.get(probe_id, 0) for probe_id in sorted(expected_per_probe)
    }
    return actual_counts, anomalies


async def _collect_one(
    target: _ModelTarget,
    *,
    out_dir: Path,
    declared_probe_set_version: str,
    resume: bool,
    quality_policy: _QualityPolicy,
) -> _CollectionResult:
    """Collect a single model's fingerprint and write JSONL + sidecar."""
    probes = probes_mod.load_probes_for_version(
        target.budget, probe_set_version=declared_probe_set_version
    )
    expected_per_probe = {probe.probe_id: probe.num_samples for probe in probes}
    expected_samples = sum(expected_per_probe.values())

    out_file = _fingerprint_path_for(out_dir, target.canonical_id)
    snapshot = (
        _load_resume_snapshot(out_file, probes, quality_policy)
        if resume
        else _ResumeSnapshot(
            entries_by_key={},
            ignored_entries=0,
            duplicate_entries=0,
            quality_rejected_entries=0,
        )
    )
    missing_probe_samples = _missing_probe_samples(probes, snapshot.entries_by_key)

    print(
        f"[collect] {target.canonical_id}: {target.endpoint} "
        f"model={target.model_id} budget={target.budget} "
        f"({len(probes)} probes x {expected_samples} samples; "
        f"resume={'on' if resume else 'off'}, "
        f"existing={len(snapshot.entries_by_key)}, missing={len(missing_probe_samples)})",
        file=sys.stderr,
    )
    if resume and (
        snapshot.ignored_entries or snapshot.duplicate_entries or snapshot.quality_rejected_entries
    ):
        print(
            f"[collect]   {target.canonical_id}: ignored "
            f"{snapshot.ignored_entries} stale/malformed and "
            f"{snapshot.duplicate_entries} duplicate and "
            f"{snapshot.quality_rejected_entries} low-quality existing entries "
            "while resuming",
            file=sys.stderr,
        )

    successful_entries: list[dict[str, Any]] = []
    sample_failures: list[_SampleFailure] = []
    skipped_for_missing_key = False
    if missing_probe_samples:
        key = os.environ.get(target.key_env)
        if not key:
            skipped_for_missing_key = True
            print(
                f"[collect] SKIP {target.canonical_id}: env var {target.key_env} not set "
                f"and {len(missing_probe_samples)} samples still need collection",
                file=sys.stderr,
            )
        else:
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
            successful_entries, sample_failures = await _collect_probe_samples_with_quality_retries(
                client,
                missing_probe_samples,
                quality_policy,
                canonical_id=target.canonical_id,
            )
    elif resume:
        print(
            f"[collect]   {target.canonical_id}: fingerprint already complete; no API calls needed",
            file=sys.stderr,
        )

    for failure in sample_failures[:3]:
        print(
            f"[collect]   {target.canonical_id} skip "
            f"{failure.probe_id}#{failure.sample_index}: {failure.reason}",
            file=sys.stderr,
        )
    if len(sample_failures) > 3:
        print(
            f"[collect]   {target.canonical_id}: "
            f"... {len(sample_failures) - 3} more failed samples omitted",
            file=sys.stderr,
        )

    combined_entries_by_key = dict(snapshot.entries_by_key)
    for entry in successful_entries:
        combined_entries_by_key[(str(entry["probe_id"]), int(entry["sample_index"]))] = entry
    combined_entries = _sort_entries_for_probe_plan(probes, list(combined_entries_by_key.values()))
    actual_per_probe, metadata_anomalies = _analyze_entries(probes, combined_entries)

    if skipped_for_missing_key and not combined_entries:
        return _CollectionResult(
            canonical_id=target.canonical_id,
            actual_samples=0,
            failed_samples=len(missing_probe_samples),
            expected_samples=expected_samples,
            missing_probe_ids=sorted(expected_per_probe),
            incomplete_probe_ids=[],
            metadata_anomalies=[],
        )

    out_file.parent.mkdir(parents=True, exist_ok=True)

    with out_file.open("w", encoding="utf-8") as f:
        for entry in combined_entries:
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
            "actual_samples": len(combined_entries),
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

    failed_samples = len(missing_probe_samples) if skipped_for_missing_key else len(sample_failures)
    print(
        f"[collect] {target.canonical_id}: wrote {len(combined_entries)} samples "
        f"({len(snapshot.entries_by_key)} reused, {len(successful_entries)} new, "
        f"{failed_samples} failed, {len(metadata_anomalies)} anomalies) to {out_file}",
        file=sys.stderr,
    )
    return _CollectionResult(
        canonical_id=target.canonical_id,
        actual_samples=len(combined_entries),
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
        "--resume",
        action=argparse.BooleanOptionalAction,
        default=True,
        help=(
            "Resume existing fingerprint JSONL files by collecting only missing "
            "probe/sample indexes. Default: enabled; use --no-resume for a full rewrite."
        ),
    )
    parser.add_argument(
        "--quality-filter",
        action=argparse.BooleanOptionalAction,
        default=True,
        help=(
            "Reject and retry low-quality samples before writing fingerprints. "
            "Flags finish_reason=length and very short outputs dominated by "
            "reasoning tokens. Default: enabled."
        ),
    )
    parser.add_argument(
        "--quality-retries",
        type=int,
        default=_DEFAULT_QUALITY_RETRIES,
        help=(
            "Additional collection rounds for samples rejected by the quality "
            f"filter. Default: {_DEFAULT_QUALITY_RETRIES}."
        ),
    )
    parser.add_argument(
        "--quality-min-output-chars",
        type=int,
        default=_DEFAULT_MIN_OUTPUT_CHARS_FOR_HIGH_REASONING,
        help=(
            "Visible output shorter than this is rejected when reasoning_tokens "
            "is high. Default: "
            f"{_DEFAULT_MIN_OUTPUT_CHARS_FOR_HIGH_REASONING}."
        ),
    )
    parser.add_argument(
        "--quality-high-reasoning-tokens",
        type=int,
        default=_DEFAULT_HIGH_REASONING_TOKENS,
        help=(
            "Reasoning token count considered high for short-output rejection. "
            f"Default: {_DEFAULT_HIGH_REASONING_TOKENS}."
        ),
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
    if args.quality_retries < 0:
        print("error: --quality-retries must be >= 0", file=sys.stderr)
        return 2
    if args.quality_min_output_chars < 0:
        print("error: --quality-min-output-chars must be >= 0", file=sys.stderr)
        return 2
    if args.quality_high_reasoning_tokens < 0:
        print("error: --quality-high-reasoning-tokens must be >= 0", file=sys.stderr)
        return 2
    quality_policy = _QualityPolicy(
        enabled=args.quality_filter,
        retries=args.quality_retries,
        min_output_chars_for_high_reasoning=args.quality_min_output_chars,
        high_reasoning_tokens=args.quality_high_reasoning_tokens,
    )

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
                resume=args.resume,
                quality_policy=quality_policy,
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
