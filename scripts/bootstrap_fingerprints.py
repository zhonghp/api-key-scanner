#!/usr/bin/env python3
"""Manually bootstrap a small fingerprint set for local testing.

Phase 1 interim tool. M3 will replace this with a signed weekly GitHub
Actions workflow. For now, this script lets you produce a local
fingerprint dir so you can test verify_gateway end-to-end.

Configuration comes from a `.env` file (see `.env.example`):

    OPENAI_API_KEY=sk-...
    MODEL_ID=gpt-4o
    OPENAI_BASE_URL=https://api.openai.com/v1

Shell env vars always win over `.env` — you can override on the fly
without editing the file:

    OPENAI_API_KEY=sk-different uv run python scripts/bootstrap_fingerprints.py

Usage:
    uv run python scripts/bootstrap_fingerprints.py [--out DIR] [--budget cheap|standard]

Then:
    export APIGUARD_FINGERPRINT_DIR=./fingerprints
    # ...use verify_gateway normally
"""

from __future__ import annotations

import argparse
import asyncio
import json
import os
import sys
from datetime import datetime, timezone
from pathlib import Path

from dotenv import load_dotenv

from api_key_scanner import aliases
from api_key_scanner.aliases import UnknownModelError
from api_key_scanner.gateway import ClientConfig, OpenAICompatClient
from api_key_scanner.probes import load_probes
from api_key_scanner.schemas import Budget

# Env var names (kept in one place so they're easy to grep)
ENV_API_KEY = "OPENAI_API_KEY"
ENV_MODEL_ID = "MODEL_ID"
ENV_BASE_URL = "OPENAI_BASE_URL"
ENV_CANONICAL_ID = "CANONICAL_ID"  # optional override


async def main() -> int:
    parser = argparse.ArgumentParser(
        description=(
            "Collect a local fingerprint JSONL from the endpoint/model/key "
            "configured in your .env (see .env.example)."
        ),
        formatter_class=argparse.RawDescriptionHelpFormatter,
    )
    parser.add_argument(
        "--env-file",
        default=".env",
        help="Path to .env file (default: .env in current directory)",
    )
    parser.add_argument(
        "--canonical-id",
        default=None,
        help=(
            "Override the canonical id (<vendor>/<model>). "
            f"If omitted, inferred from {ENV_MODEL_ID} + {ENV_BASE_URL}, or read from "
            f"the {ENV_CANONICAL_ID} env var."
        ),
    )
    parser.add_argument(
        "--out",
        default="./fingerprints",
        help="Output directory (default: ./fingerprints)",
    )
    parser.add_argument(
        "--budget",
        default="cheap",
        choices=["cheap", "standard"],
        help="Probe budget; 'cheap' is a smoke test (~18 calls), 'standard' is the full MET paper protocol (~258 calls)",
    )
    args = parser.parse_args()

    # Load .env but don't overwrite anything already exported in the shell.
    # This lets users override the file ad-hoc with `FOO=bar uv run ...`.
    env_path = Path(args.env_file)
    if env_path.exists():
        load_dotenv(dotenv_path=env_path, override=False)
        print(f"[bootstrap] loaded {env_path}", file=sys.stderr)
    else:
        print(
            f"[bootstrap] warning: {env_path} not found; relying on shell env only",
            file=sys.stderr,
        )

    # Validate aliases.json before doing anything — catches internal inconsistencies
    # (e.g. canonical list says 'qwen/Qwen3.5-122B-A10B' but an alias points to
    # 'qwen/qwen3.5-122b-a10b') up front rather than silently writing a file
    # nobody will find later.
    report = aliases.validate_aliases_file()
    if report.warnings:
        for w in report.warnings:
            print(f"[bootstrap] aliases.json warn: {w}", file=sys.stderr)
    if not report.ok:
        print("[bootstrap] aliases.json has ERRORS; fix them first:", file=sys.stderr)
        for e in report.errors:
            print(f"  - {e}", file=sys.stderr)
        return 2

    key = os.environ.get(ENV_API_KEY)
    base_url = os.environ.get(ENV_BASE_URL)
    model_id = os.environ.get(ENV_MODEL_ID)

    missing = [
        name
        for name, val in (
            (ENV_API_KEY, key),
            (ENV_BASE_URL, base_url),
            (ENV_MODEL_ID, model_id),
        )
        if not val
    ]
    if missing:
        print(
            f"error: missing required env vars: {', '.join(missing)}. "
            f"Copy .env.example to .env and fill them in, or export them in your shell.",
            file=sys.stderr,
        )
        return 2

    # Canonical id: --canonical-id flag > CANONICAL_ID env > aliases.to_canonical(MODEL_ID)
    # to_canonical raises UnknownModelError rather than silently inventing a
    # canonical id from URL + MODEL_ID. That's the contract verify_gateway
    # relies on — no alignment drift possible.
    raw_canonical = args.canonical_id or os.environ.get(ENV_CANONICAL_ID) or model_id
    try:
        canonical_id = aliases.to_canonical(raw_canonical)
    except UnknownModelError as exc:
        print(f"error: {exc}", file=sys.stderr)
        print(
            f"hint: MODEL_ID='{model_id}' can't be mapped to a canonical id. "
            f"Options:\n"
            f"  (a) add an alias entry in src/api_key_scanner/data/aliases.json\n"
            f"  (b) export CANONICAL_ID=<vendor>/<model> or pass --canonical-id",
            file=sys.stderr,
        )
        return 2

    budget: Budget = args.budget
    probes = load_probes(budget)
    total_samples = sum(p.num_samples for p in probes)
    print(
        f"[bootstrap] endpoint={base_url} model={model_id} canonical={canonical_id}",
        file=sys.stderr,
    )
    print(
        f"[bootstrap] sending {len(probes)} probes × {total_samples} total samples "
        f"(budget={budget})...",
        file=sys.stderr,
    )

    client = OpenAICompatClient(
        ClientConfig(
            endpoint_url=base_url,
            api_key=key,
            model=model_id,
            concurrency=3,
            max_retries=3,
        )
    )
    responses = await client.run_probes(probes)

    vendor, model_name = canonical_id.split("/", 1)
    out_file = Path(args.out) / vendor / f"{model_name}.jsonl"
    out_file.parent.mkdir(parents=True, exist_ok=True)

    now = datetime.now(timezone.utc).isoformat()
    n_ok = 0
    n_err = 0
    with out_file.open("w", encoding="utf-8") as f:
        for r in responses:
            if r.error or not r.output:
                print(
                    f"[bootstrap]   skip {r.probe_id}#{r.sample_index}: "
                    f"{r.error or 'empty output'}",
                    file=sys.stderr,
                )
                n_err += 1
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
        f"[bootstrap] wrote {n_ok} samples to {out_file} ({n_err} failed)",
        file=sys.stderr,
    )
    if n_ok == 0:
        print(
            "[bootstrap] ERROR: no samples collected; check endpoint / key / model id",
            file=sys.stderr,
        )
        return 1
    return 0


if __name__ == "__main__":
    sys.exit(asyncio.run(main()))
