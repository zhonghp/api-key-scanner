#!/usr/bin/env python3
"""Batch fingerprint collection driver (M3).

Reads models.yaml, iterates through every enabled entry, and runs the same
probe protocol that verify_gateway uses against each vendor-direct endpoint.
Output layout matches what probes.load_fingerprints expects:

    fingerprints/<vendor>/<model>.jsonl

Designed to run:
  - locally for testing:  uv run python scripts/collect_all.py
  - in GitHub Actions:    .github/workflows/weekly-fingerprint-collect.yml
    (API keys come from secrets, exported as env before the script runs)

Alignment: canonical_id values in models.yaml are validated against
aliases.json via aliases.to_canonical(); any entry that doesn't resolve
makes the whole run exit 2 rather than silently write mis-named files.
"""

from __future__ import annotations

import argparse
import asyncio
import json
import os
import sys
from dataclasses import dataclass
from datetime import datetime, timezone
from pathlib import Path

import yaml
from dotenv import load_dotenv

from api_key_scanner import aliases
from api_key_scanner.aliases import UnknownModelError
from api_key_scanner.gateway import ClientConfig, OpenAICompatClient
from api_key_scanner.probes import load_probes
from api_key_scanner.schemas import Budget


@dataclass(frozen=True)
class _ModelTarget:
    canonical_id: str
    endpoint: str
    model_id: str
    key_env: str
    budget: Budget


def _load_config(path: Path) -> tuple[list[_ModelTarget], Budget]:
    """Parse models.yaml into (enabled_targets, default_budget)."""
    with path.open("r", encoding="utf-8") as f:
        cfg = yaml.safe_load(f)

    collection = cfg.get("collection", {})
    default_budget: Budget = collection.get("default_budget", "standard")

    targets: list[_ModelTarget] = []
    for entry in cfg.get("models", []):
        if not entry.get("enabled", True):
            continue
        targets.append(
            _ModelTarget(
                canonical_id=entry["canonical_id"],
                endpoint=entry["endpoint"],
                model_id=entry["model_id"],
                key_env=entry["key_env"],
                budget=entry.get("budget", default_budget),
            )
        )
    return targets, default_budget


def _validate_alignment(targets: list[_ModelTarget]) -> list[str]:
    """Every canonical_id must map to itself through aliases.to_canonical.

    Returns list of error messages; empty list means all good.
    """
    errors: list[str] = []
    for t in targets:
        try:
            resolved = aliases.to_canonical(t.canonical_id)
        except UnknownModelError:
            errors.append(
                f"{t.canonical_id!r}: not in aliases.json canonical[] — add it or fix models.yaml"
            )
            continue
        if resolved != t.canonical_id:
            errors.append(
                f"{t.canonical_id!r}: canonical form resolves to {resolved!r} "
                f"(case/alias drift — pick one spelling)"
            )
    return errors


async def _collect_one(target: _ModelTarget, *, out_dir: Path) -> tuple[int, int]:
    """Collect a single model's fingerprint. Returns (n_ok, n_failed)."""
    key = os.environ.get(target.key_env)
    if not key:
        print(
            f"[collect] SKIP {target.canonical_id}: env var {target.key_env} not set",
            file=sys.stderr,
        )
        return (0, 0)

    probes = load_probes(target.budget)
    total_samples = sum(p.num_samples for p in probes)
    print(
        f"[collect] {target.canonical_id}: {target.endpoint} "
        f"model={target.model_id} budget={target.budget} "
        f"({len(probes)} probes × {total_samples} samples)",
        file=sys.stderr,
    )

    client = OpenAICompatClient(
        ClientConfig(
            endpoint_url=target.endpoint,
            api_key=key,
            model=target.model_id,
            concurrency=3,
            max_retries=3,
        )
    )
    responses = await client.run_probes(probes)

    vendor, model_name = target.canonical_id.split("/", 1)
    out_file = out_dir / vendor / f"{model_name}.jsonl"
    out_file.parent.mkdir(parents=True, exist_ok=True)

    now = datetime.now(timezone.utc).isoformat()
    n_ok = 0
    n_err = 0
    with out_file.open("w", encoding="utf-8") as f:
        for r in responses:
            if r.error or not r.output:
                n_err += 1
                if n_err <= 3:  # cap stderr spam
                    print(
                        f"[collect]   {target.canonical_id} "
                        f"skip {r.probe_id}#{r.sample_index}: "
                        f"{r.error or 'empty output'}",
                        file=sys.stderr,
                    )
                continue
            entry = {
                "probe_id": r.probe_id,
                "sample_index": r.sample_index,
                "output": r.output,
                "output_tokens": r.output_tokens,
                "response_ms": r.response_ms,
                "ttft_ms": r.ttft_ms,
                "system_fingerprint": r.system_fingerprint,
                "finish_reason": r.finish_reason,
                "collected_at": now,
            }
            f.write(json.dumps(entry, ensure_ascii=False) + "\n")
            n_ok += 1

    print(
        f"[collect] {target.canonical_id}: wrote {n_ok} samples ({n_err} failed) to {out_file}",
        file=sys.stderr,
    )
    return n_ok, n_err


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
    args = parser.parse_args()

    # Load .env for local runs; in CI, keys come from exported secrets
    env_path = Path(args.env_file)
    if env_path.exists():
        load_dotenv(dotenv_path=env_path, override=False)
        print(f"[collect] loaded {env_path}", file=sys.stderr)

    # Validate aliases.json first
    alias_report = aliases.validate_aliases_file()
    if not alias_report.ok:
        print("[collect] aliases.json has ERRORS:", file=sys.stderr)
        for e in alias_report.errors:
            print(f"  - {e}", file=sys.stderr)
        return 2

    # Load targets
    config_path = Path(args.config)
    if not config_path.exists():
        print(f"error: {config_path} not found", file=sys.stderr)
        return 2
    targets, _ = _load_config(config_path)

    if args.only:
        wanted = set(args.only)
        targets = [t for t in targets if t.canonical_id in wanted]
        if not targets:
            print(f"error: no enabled targets match --only {args.only}", file=sys.stderr)
            return 2

    if not targets:
        print("[collect] no enabled targets in models.yaml; nothing to do", file=sys.stderr)
        return 0

    # Alignment check: every canonical_id must be in aliases.json
    alignment_errors = _validate_alignment(targets)
    if alignment_errors:
        print("[collect] models.yaml / aliases.json misalignment:", file=sys.stderr)
        for e in alignment_errors:
            print(f"  - {e}", file=sys.stderr)
        return 2

    out_dir = Path(args.out)
    out_dir.mkdir(parents=True, exist_ok=True)

    print(
        f"[collect] starting batch: {len(targets)} models -> {out_dir}",
        file=sys.stderr,
    )

    # Sequential (not concurrent): each model takes ~30-60s and the per-vendor
    # rate limits are already handled inside OpenAICompatClient.
    totals = []
    for t in targets:
        n_ok, n_err = await _collect_one(t, out_dir=out_dir)
        totals.append((t.canonical_id, n_ok, n_err))

    # Summary
    print("\n[collect] summary:", file=sys.stderr)
    empty_models: list[str] = []
    for canonical_id, n_ok, n_err in totals:
        status = "ok" if n_ok > 0 else "EMPTY"
        print(
            f"  {status:6} {canonical_id:40} {n_ok:4} samples ({n_err} failed)",
            file=sys.stderr,
        )
        if n_ok == 0:
            empty_models.append(canonical_id)

    if empty_models and args.fail_on_empty:
        print(
            f"[collect] ERROR: {len(empty_models)} models produced 0 samples "
            f"(--fail-on-empty): {empty_models}",
            file=sys.stderr,
        )
        return 1

    return 0


def main() -> int:
    return asyncio.run(_main())


if __name__ == "__main__":
    sys.exit(main())
