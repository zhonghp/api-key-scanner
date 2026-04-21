"""aliases.py tests."""

from __future__ import annotations

import pytest

from api_key_scanner.aliases import (
    UnknownModelError,
    known_canonical_ids,
    resolve,
    same_family,
    to_canonical,
    validate_aliases_file,
)


@pytest.mark.parametrize(
    "user_input,expected_canonical",
    [
        ("claude-opus-4", "anthropic/claude-opus-4"),
        ("opus", "anthropic/claude-opus-4"),
        ("Claude-Opus-4", "anthropic/claude-opus-4"),  # case-insensitive
        ("  claude-opus-4  ", "anthropic/claude-opus-4"),  # whitespace stripped
        ("anthropic/claude-opus-4", "anthropic/claude-opus-4"),
        ("gpt-4o", "openai/gpt-4o"),
        ("gpt4o", "openai/gpt-4o"),
        ("gpt-4o-2024-08-06", "openai/gpt-4o"),
        ("gemini-2.5-pro", "google/gemini-2.5-pro"),
        ("llama-3.3-70b", "meta/llama-3.3-70b"),
        ("haiku", "anthropic/claude-haiku-4.5"),
    ],
)
def test_resolve_known_aliases(user_input: str, expected_canonical: str) -> None:
    result = resolve(user_input)
    assert result.is_resolved is True
    assert result.canonical_id == expected_canonical


def test_resolve_unknown_returns_unresolved() -> None:
    result = resolve("some-weird-model-name")
    assert result.is_resolved is False
    assert result.canonical_id == "some-weird-model-name"
    assert result.family is None


def test_resolve_empty_string() -> None:
    result = resolve("")
    assert result.is_resolved is False
    assert result.canonical_id == ""


def test_family_of_resolved_model() -> None:
    assert resolve("claude-opus-4").family == "anthropic/claude"
    assert resolve("gpt-4o").family == "openai/gpt"
    assert resolve("gemini-2.5-pro").family == "google/gemini"
    assert resolve("llama-3.3-70b").family == "meta/llama"


@pytest.mark.parametrize(
    "a,b,expected",
    [
        ("anthropic/claude-opus-4", "anthropic/claude-sonnet-4", True),
        ("anthropic/claude-opus-4", "openai/gpt-4o", False),
        ("openai/gpt-4o", "openai/gpt-4o-mini", True),
        ("google/gemini-2.5-pro", "meta/llama-3.3-70b", False),
        # Unknown canonical -> not same family
        ("unknown/model", "anthropic/claude-opus-4", False),
    ],
)
def test_same_family(a: str, b: str, expected: bool) -> None:
    assert same_family(a, b) is expected


def test_known_canonical_ids_are_stable() -> None:
    ids = known_canonical_ids()
    # Floor of 10 — we never remove models; users may add more
    assert len(ids) >= 10
    assert "anthropic/claude-opus-4" in ids
    assert "openai/gpt-4o" in ids
    # No duplicates
    assert len(ids) == len(set(ids))


# ---- to_canonical: the single choke point ---------------------------------


def test_to_canonical_resolves_via_alias() -> None:
    assert to_canonical("opus") == "anthropic/claude-opus-4"
    assert to_canonical("GPT-4o") == "openai/gpt-4o"
    assert to_canonical("  claude-opus-4  ") == "anthropic/claude-opus-4"


def test_to_canonical_accepts_canonical_form_directly() -> None:
    """If a caller hands us something already canonical, accept it."""
    assert to_canonical("anthropic/claude-opus-4") == "anthropic/claude-opus-4"


def test_to_canonical_raises_for_unknown_name() -> None:
    with pytest.raises(UnknownModelError) as exc_info:
        to_canonical("totally-fake-model-xyz")
    msg = str(exc_info.value)
    assert "totally-fake-model-xyz" in msg
    assert "aliases.json" in msg  # the error tells the user where to fix


def test_to_canonical_raises_for_empty_string() -> None:
    with pytest.raises(UnknownModelError):
        to_canonical("")


def test_to_canonical_handles_mixed_case_input() -> None:
    """Alias lookup is case-insensitive (same as resolve()); returns canonical form."""
    # Any casing that matches a registered alias key (after lowercase+strip) works
    assert to_canonical("claude-opus-4") == "anthropic/claude-opus-4"
    assert to_canonical("CLAUDE-OPUS-4") == "anthropic/claude-opus-4"
    assert to_canonical("Anthropic/Claude-Opus-4") == "anthropic/claude-opus-4"
    # But an unknown fully-qualified id (neither alias nor canonical) must still fail
    with pytest.raises(UnknownModelError):
        to_canonical("anthropic/does-not-exist")


# ---- validate_aliases_file: internal consistency of aliases.json ---------


def test_validate_aliases_file_returns_report() -> None:
    report = validate_aliases_file()
    # Always a report object, not None
    assert hasattr(report, "errors")
    assert hasattr(report, "warnings")
    assert hasattr(report, "ok")


def test_validate_aliases_file_has_no_errors() -> None:
    """The shipped aliases.json should be internally consistent.

    If this fails, an alias is pointing to an RHS that's not in canonical[],
    or a family member is not canonical. Fix the JSON before merging.
    """
    report = validate_aliases_file()
    assert report.ok, (
        "aliases.json internal inconsistency (likely typo / case mismatch):\n  - "
        + "\n  - ".join(report.errors)
    )
