"""detectors/met.py tests."""

from __future__ import annotations

from api_key_scanner.detectors.met import run
from api_key_scanner.schemas import FingerprintEntry, ProbeResponse


def _fp(
    model_id: str, probe_id: str, outputs: list[str], start_idx: int = 0
) -> list[FingerprintEntry]:
    return [
        FingerprintEntry(
            probe_id=probe_id,
            sample_index=start_idx + i,
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


def test_identical_distributions_score_high() -> None:
    """If gateway outputs sampled from the same distribution, score ~1.0."""
    texts = [
        "The quick brown fox jumps over the lazy dog.",
        "A stitch in time saves nine.",
        "Hello world, this is a test sentence.",
        "The rain in Spain falls mainly on the plain.",
        "To be or not to be, that is the question.",
        "All that glitters is not gold.",
        "A rolling stone gathers no moss.",
        "Actions speak louder than words.",
    ]
    # Split the same text pool randomly between reference and gateway —
    # they're from the same distribution, so MET should NOT reject.
    fingerprints = {
        "anthropic/claude-opus-4": _fp("anthropic/claude-opus-4", "p1", texts[:4], start_idx=0),
    }
    gateway = _gw("p1", texts[4:])

    result = run(
        gateway_responses=gateway,
        fingerprints=fingerprints,
        claimed_model_id="anthropic/claude-opus-4",
        num_permutations=200,  # faster test
    )

    assert result.name == "d2_met"
    assert result.status != "failed"
    # Same distribution -> high p-value -> high score (>= 0.3 easily)
    assert result.score >= 0.3


def test_different_distributions_score_low() -> None:
    """If gateway outputs are visibly different, score low."""
    fingerprints = {
        "anthropic/claude-opus-4": _fp(
            "anthropic/claude-opus-4",
            "p1",
            [
                "I am Claude, Anthropic's flagship model.",
                "Greetings. I am Claude, made by Anthropic.",
                "Hello. I am Claude from Anthropic.",
                "Hi there. I'm Claude, built by Anthropic.",
                "Good day. I'm Claude, crafted by Anthropic.",
            ],
        ),
    }
    gateway = _gw(
        "p1",
        [
            "I am ChatGPT made by OpenAI.",
            "Hi, I'm ChatGPT from OpenAI.",
            "Hello! I'm ChatGPT, OpenAI's assistant.",
            "Greetings, I'm ChatGPT by OpenAI.",
            "Hey there! I am ChatGPT from OpenAI.",
        ],
    )

    result = run(
        gateway_responses=gateway,
        fingerprints=fingerprints,
        claimed_model_id="anthropic/claude-opus-4",
        num_permutations=500,
    )

    assert result.score < 0.3  # strongly rejected
    assert result.details["mean_p_value"] < 0.1


def test_insufficient_samples_fails() -> None:
    fingerprints = {
        "anthropic/claude-opus-4": _fp("anthropic/claude-opus-4", "p1", ["just one"]),
    }
    gateway = _gw("p1", ["only one"])

    result = run(
        gateway_responses=gateway,
        fingerprints=fingerprints,
        claimed_model_id="anthropic/claude-opus-4",
    )
    assert result.status == "failed"


def test_multiple_probes_average() -> None:
    """Across multiple probes, p-values are averaged."""
    fingerprints = {
        "anthropic/claude-opus-4": [
            *_fp("anthropic/claude-opus-4", "p1", [f"probe 1 response {i}" for i in range(5)]),
            *_fp(
                "anthropic/claude-opus-4",
                "p2",
                [f"probe 2 answer {i}" for i in range(5)],
                start_idx=5,
            ),
        ],
    }
    gateway = _gw("p1", [f"probe 1 response {i}" for i in range(5, 10)])
    gateway += _gw("p2", [f"probe 2 answer {i}" for i in range(5, 10)])

    result = run(
        gateway_responses=gateway,
        fingerprints=fingerprints,
        claimed_model_id="anthropic/claude-opus-4",
        num_permutations=200,
    )
    assert result.details["num_probes_tested"] == 2


def test_allowed_probe_ids_keep_d2_on_its_own_probe_set() -> None:
    fingerprints = {
        "anthropic/claude-opus-4": [
            *_fp("anthropic/claude-opus-4", "met-001", [f"alpha {i}" for i in range(5)]),
            *_fp(
                "anthropic/claude-opus-4",
                "llmmap-001",
                [f"beta {i}" for i in range(5)],
                start_idx=5,
            ),
        ],
    }
    gateway = _gw("met-001", [f"alpha {i}" for i in range(5, 10)])
    gateway += _gw("llmmap-001", [f"totally different {i}" for i in range(5)])

    result = run(
        gateway_responses=gateway,
        fingerprints=fingerprints,
        claimed_model_id="anthropic/claude-opus-4",
        num_permutations=200,
        allowed_probe_ids={"met-001"},
    )

    assert result.status != "failed"
    assert result.details["num_probes_tested"] == 1
