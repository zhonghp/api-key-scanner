"""detectors/llmmap.py tests."""

from __future__ import annotations

from api_key_scanner.detectors.llmmap import run
from api_key_scanner.schemas import FingerprintEntry, ProbeResponse


def _fp(model_id: str, probe_id: str, outputs: list[str]) -> list[FingerprintEntry]:
    return [
        FingerprintEntry(
            probe_id=probe_id,
            sample_index=i,
            output=out,
            collected_at="2026-04-20T00:00:00Z",
        )
        for i, out in enumerate(outputs)
    ]


def _gw(probe_id: str, outputs: list[str]) -> list[ProbeResponse]:
    return [
        ProbeResponse(probe_id=probe_id, sample_index=i, output=out)
        for i, out in enumerate(outputs)
    ]


def test_gateway_matches_claimed_model_scores_high() -> None:
    """Gateway responses look like Opus; claimed Opus; should score ~1.0."""
    fingerprints = {
        "anthropic/claude-opus-4": _fp(
            "anthropic/claude-opus-4",
            "p1",
            [
                "I'm Claude, an AI assistant made by Anthropic.",
                "I am Claude from Anthropic, happy to help.",
                "Hi, I'm Claude. Anthropic made me.",
            ],
        ),
        "openai/gpt-4o": _fp(
            "openai/gpt-4o",
            "p1",
            [
                "I'm ChatGPT, a large language model by OpenAI.",
                "I am ChatGPT developed by OpenAI.",
                "Hello, I'm ChatGPT made by OpenAI.",
            ],
        ),
    }
    gateway = _gw(
        "p1",
        [
            "I'm Claude, an AI assistant made by Anthropic.",
            "Hi, I am Claude from Anthropic.",
        ],
    )

    result = run(
        gateway_responses=gateway,
        fingerprints=fingerprints,
        claimed_model_id="anthropic/claude-opus-4",
    )

    assert result.name == "d1_llmmap"
    # 2 samples scored -> degraded per llmmap.py threshold (>=3 for 'ok')
    assert result.status == "degraded"
    assert result.score == 1.0
    assert result.details["claimed_wins"] == 2


def test_cross_family_substitution_scores_zero() -> None:
    """Gateway claims Opus but is actually GPT — D1 should catch."""
    fingerprints = {
        "anthropic/claude-opus-4": _fp(
            "anthropic/claude-opus-4",
            "p1",
            [
                "I'm Claude from Anthropic.",
                "Hi, I am Claude made by Anthropic.",
                "I'm Claude, Anthropic's AI.",
            ],
        ),
        "openai/gpt-4o": _fp(
            "openai/gpt-4o",
            "p1",
            [
                "I'm ChatGPT from OpenAI.",
                "I am ChatGPT made by OpenAI.",
                "Hi, I'm ChatGPT by OpenAI.",
            ],
        ),
    }
    # Gateway claims Opus but responds like GPT
    gateway = _gw(
        "p1",
        [
            "I'm ChatGPT, a language model from OpenAI.",
            "Hi, I'm ChatGPT made by OpenAI.",
            "I am ChatGPT by OpenAI, happy to help.",
        ],
    )

    result = run(
        gateway_responses=gateway,
        fingerprints=fingerprints,
        claimed_model_id="anthropic/claude-opus-4",
    )

    assert result.score == 0.0
    assert result.details["top_guess"] == "openai/gpt-4o"


def test_same_family_downgrade_scores_mid() -> None:
    """Gateway claims Opus but serves Sonnet — A2. Should score ~0.5."""
    fingerprints = {
        "anthropic/claude-opus-4": _fp(
            "anthropic/claude-opus-4",
            "p1",
            [
                "Greetings. I am Claude, crafted by Anthropic.",
                "Hello. I am Claude from Anthropic, with a formal tone.",
                "I am Claude, Anthropic's most capable model.",
            ],
        ),
        "anthropic/claude-sonnet-4": _fp(
            "anthropic/claude-sonnet-4",
            "p1",
            [
                "Hi! I'm Claude, Anthropic's mid-tier model.",
                "Hello! I'm Claude, a helpful assistant from Anthropic.",
                "Hey, I'm Claude made by Anthropic.",
            ],
        ),
    }
    # Gateway responds like Sonnet (casual), but claims Opus
    gateway = _gw(
        "p1",
        [
            "Hi! I'm Claude, a helpful assistant from Anthropic.",
            "Hey, I'm Claude made by Anthropic.",
            "Hello! I'm Claude from Anthropic.",
        ],
    )

    result = run(
        gateway_responses=gateway,
        fingerprints=fingerprints,
        claimed_model_id="anthropic/claude-opus-4",
    )

    # All three samples map to Sonnet (same family) -> score 0.5
    assert result.score == 0.5
    assert result.details["top_guess"] == "anthropic/claude-sonnet-4"


def test_no_reference_fingerprint_fails_gracefully() -> None:
    result = run(
        gateway_responses=_gw("p1", ["hi"]),
        fingerprints={},  # no reference at all
        claimed_model_id="anthropic/claude-opus-4",
    )
    assert result.status == "failed"
    assert result.score == 0.0


def test_no_gateway_responses_fails_gracefully() -> None:
    fingerprints = {
        "anthropic/claude-opus-4": _fp("anthropic/claude-opus-4", "p1", ["I'm Claude"]),
    }
    result = run(
        gateway_responses=[],
        fingerprints=fingerprints,
        claimed_model_id="anthropic/claude-opus-4",
    )
    assert result.status == "failed"
