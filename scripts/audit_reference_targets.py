#!/usr/bin/env python3
"""Audit models.yaml reference targets without touching fingerprint data."""

from __future__ import annotations

import argparse
import sys
from dataclasses import dataclass
from pathlib import Path
from urllib.parse import urlparse

import yaml

_VENDOR_DIRECT_HOSTS: dict[str, set[str]] = {
    "openai": {"api.openai.com"},
    "anthropic": {"api.anthropic.com"},
    "google": {"generativelanguage.googleapis.com"},
}


@dataclass(frozen=True)
class TargetAudit:
    canonical_id: str
    endpoint: str
    enabled: bool
    reference_mode: str
    release_allowed: bool
    host: str
    reason: str


def _load_config(path: Path) -> list[dict]:
    with path.open("r", encoding="utf-8") as f:
        cfg = yaml.safe_load(f) or {}
    return list(cfg.get("models", []))


def _audit_target(entry: dict) -> TargetAudit:
    canonical_id = entry["canonical_id"]
    endpoint = entry["endpoint"]
    enabled = bool(entry.get("enabled", True))
    host = urlparse(endpoint).hostname or ""

    explicit_mode = entry.get("reference_mode")
    if explicit_mode:
        reference_mode = str(explicit_mode)
        reason = "explicit reference_mode"
    else:
        vendor = canonical_id.split("/", 1)[0]
        direct_hosts = _VENDOR_DIRECT_HOSTS.get(vendor)
        if direct_hosts is None:
            reference_mode = "third_party_host"
            reason = f"no vendor-direct host policy for vendor {vendor}"
        elif host in direct_hosts:
            reference_mode = "vendor_direct"
            reason = f"host {host} matches vendor-direct allowlist"
        elif host.endswith(".edgecloudapp.com"):
            reference_mode = "internal_gateway"
            reason = f"host {host} looks like an internal gateway"
        else:
            reference_mode = "proxy"
            reason = f"host {host} does not match vendor-direct allowlist"

    release_allowed = bool(entry.get("release_allowed", reference_mode == "vendor_direct"))
    return TargetAudit(
        canonical_id=canonical_id,
        endpoint=endpoint,
        enabled=enabled,
        reference_mode=reference_mode,
        release_allowed=release_allowed,
        host=host,
        reason=reason,
    )


def main() -> int:
    parser = argparse.ArgumentParser(
        description="Audit models.yaml to see whether enabled reference targets are release-safe."
    )
    parser.add_argument("--config", default="models.yaml", help="Path to models.yaml")
    parser.add_argument(
        "--only-enabled",
        action="store_true",
        help="Only print enabled targets",
    )
    parser.add_argument(
        "--require-release-safe",
        action="store_true",
        help="Exit non-zero if any printed target is not marked release-safe",
    )
    args = parser.parse_args()

    path = Path(args.config)
    if not path.is_file():
        print(f"error: {path} not found", file=sys.stderr)
        return 2

    audits = [_audit_target(entry) for entry in _load_config(path)]
    if args.only_enabled:
        audits = [audit for audit in audits if audit.enabled]

    if not audits:
        print("[audit] no targets to inspect", file=sys.stderr)
        return 0

    unsafe = [audit for audit in audits if not audit.release_allowed]
    print("[audit] reference target summary:", file=sys.stderr)
    for audit in audits:
        release_flag = "release-safe" if audit.release_allowed else "non-release"
        enabled_flag = "enabled" if audit.enabled else "disabled"
        print(
            f"  {enabled_flag:8} {release_flag:12} {audit.reference_mode:18} "
            f"{audit.canonical_id:32} {audit.host}",
            file=sys.stderr,
        )
        print(f"           reason: {audit.reason}", file=sys.stderr)

    if args.require_release_safe and unsafe:
        print(
            f"[audit] ERROR: {len(unsafe)} target(s) are not release-safe under the current policy",
            file=sys.stderr,
        )
        for audit in unsafe:
            print(f"  - {audit.canonical_id} ({audit.reference_mode})", file=sys.stderr)
        return 1

    return 0


if __name__ == "__main__":
    sys.exit(main())
