"""Model name normalization.

Users and gateways use inconsistent aliases for the same model (`claude-opus-4`,
`anthropic/claude-opus-4`, `opus`, `claude-3-opus`, dated variants, etc.).
This module maps any input name to a canonical <vendor>/<model> form that
fingerprint lookups and family comparisons use.

Unknown names are echoed back unchanged and marked unresolved — detectors
gracefully degrade rather than reject.
"""

from __future__ import annotations

import json
from dataclasses import dataclass, field
from functools import lru_cache
from importlib import resources
from typing import Any


class UnknownModelError(ValueError):
    """Raised when a model name cannot be mapped to a known canonical id.

    Raised by :func:`to_canonical`, the single choke point used by the
    bootstrap script, ``load_fingerprints`` and ``verify_gateway`` to keep
    everyone talking about the same set of ids.
    """

    def __init__(self, name: str):
        self.name = name
        super().__init__(
            f"Model '{name}' is not in aliases.json. Either add an alias "
            f"entry mapping to an existing canonical id, or add it as a new "
            f"canonical id under 'canonical' in "
            f"src/api_key_scanner/data/aliases.json."
        )


@dataclass(frozen=True)
class ResolvedModel:
    """Result of resolving a user-provided model name."""

    input_name: str
    canonical_id: str  # "<vendor>/<model>" if resolved, else input_name as-is
    family: str | None  # e.g. "anthropic/claude", None if unresolved
    is_resolved: bool  # True if found in aliases table


@dataclass
class AliasValidationReport:
    """Internal-consistency report for aliases.json itself."""

    errors: list[str] = field(default_factory=list)
    warnings: list[str] = field(default_factory=list)

    @property
    def ok(self) -> bool:
        return not self.errors


@lru_cache(maxsize=1)
def _load_aliases() -> dict[str, Any]:
    with resources.files("api_key_scanner.data").joinpath("aliases.json").open("r") as f:
        return json.load(f)


def _normalize(name: str) -> str:
    """Normalize a raw user string for alias lookup."""
    return name.strip().lower()


def resolve(name: str) -> ResolvedModel:
    """Map a user-facing model name to its canonical form.

    Lookup is case-insensitive and whitespace-stripped. Strings not found
    in the aliases table are returned unresolved (is_resolved=False); the
    caller decides whether that's fatal.
    """
    if not name:
        return ResolvedModel(input_name=name, canonical_id=name, family=None, is_resolved=False)

    data = _load_aliases()
    aliases: dict[str, str] = data["aliases"]
    normalized = _normalize(name)

    # Build a case-insensitive alias view (cached implicitly via lru_cache above).
    lower_aliases = {k.lower(): v for k, v in aliases.items()}
    canonical = lower_aliases.get(normalized)

    if canonical is None:
        return ResolvedModel(input_name=name, canonical_id=name, family=None, is_resolved=False)

    family = _family_of(canonical, data)
    return ResolvedModel(input_name=name, canonical_id=canonical, family=family, is_resolved=True)


def _family_of(canonical: str, data: dict[str, Any]) -> str | None:
    for family, members in data.get("families", {}).items():
        if canonical in members:
            return family
    return None


def same_family(a: str, b: str) -> bool:
    """True if two canonical IDs belong to the same vendor family."""
    data = _load_aliases()
    fa = _family_of(a, data)
    fb = _family_of(b, data)
    return fa is not None and fa == fb


def known_canonical_ids() -> list[str]:
    """All canonical model IDs we have fingerprint coverage for."""
    return list(_load_aliases()["canonical"])


def to_canonical(name: str) -> str:
    """Map any caller-supplied model string to a canonical id, or fail loudly.

    This is the single choke point for producing canonical ids:

      - ``scripts/bootstrap_fingerprints.py`` uses it to decide where to
        write fingerprint JSONL files.
      - ``probes.load_fingerprints`` uses it to normalize ids read from the
        filesystem, so layout drift is detected.
      - ``server.verify_gateway`` uses it so 'claimed_model' matches the
        key the loader uses.

    Because all three go through the same function, the fingerprint the
    bootstrap script produces is guaranteed to be findable by verify_gateway.

    Raises :class:`UnknownModelError` if the name is neither a known alias
    nor already a canonical id in the table. No silent fallback — that's
    exactly the class of bug this function exists to eliminate.
    """
    if not name:
        raise UnknownModelError(name)

    resolved = resolve(name)
    if resolved.is_resolved:
        return resolved.canonical_id

    # Also accept the raw canonical form (case-sensitive — no quiet case shift)
    if name in _load_aliases()["canonical"]:
        return name

    raise UnknownModelError(name)


def validate_aliases_file() -> AliasValidationReport:
    """Return a report of any internal inconsistencies in aliases.json.

    Errors (block pipeline):
      - An alias entry points to an RHS that isn't in the canonical list
      - A ``families[...]`` entry references an id not in the canonical list

    Warnings (non-blocking):
      - A canonical id has no alias pointing to it (users must use the full form)
      - A canonical id has no family assigned (no same-family detection for it)

    Run this at the top of long-running scripts (bootstrap, server startup)
    so typos like ``qwen/qwen3.5-122b-a10b`` vs ``qwen/Qwen3.5-122B-A10B``
    are caught immediately.
    """
    data = _load_aliases()
    canonical = set(data["canonical"])
    report = AliasValidationReport()

    # Every alias RHS must be in the canonical list
    for lhs, rhs in data["aliases"].items():
        if rhs not in canonical:
            report.errors.append(f"alias '{lhs}' -> '{rhs}' but '{rhs}' is NOT in canonical[]")

    # Every family member must be in the canonical list
    for family, members in data.get("families", {}).items():
        for m in members:
            if m not in canonical:
                report.errors.append(
                    f"family '{family}' contains '{m}' which is NOT in canonical[]"
                )

    # Soft checks: canonical ids that nobody can reach via alias
    aliased_rhs = set(data["aliases"].values())
    for c in sorted(canonical):
        if c not in aliased_rhs:
            report.warnings.append(
                f"canonical '{c}' has no alias entries; only the full form is usable"
            )

    # Soft checks: canonical ids not grouped into any family
    family_members: set[str] = set()
    for members in data.get("families", {}).values():
        family_members.update(members)
    for c in sorted(canonical):
        if c not in family_members:
            report.warnings.append(
                f"canonical '{c}' is not in any family; same-family downgrade detection off"
            )

    return report
