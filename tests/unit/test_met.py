"""detectors/met.py tests."""

from __future__ import annotations

from api_key_scanner.detectors.met import (
    _calibrated_similarity_score,
    _fisher_combined_p_value,
    run,
)
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
    assert "combined_p_value" in result.details
    assert "mean_effect_size" in result.details
    assert result.score == result.details["calibrated_similarity"]
    # Same distribution -> high p-value -> high score (>= 0.3 easily)
    assert result.score >= 0.3


def test_different_distributions_score_low() -> None:
    """If gateway outputs come from a clearly different distribution, score low.

    Uses n=10 per side (MET paper's recommended operating point) so the
    permutation test has enough power. Short strings (<50 chars) share
    the trailing -1 padding in unicode codepoint space, which makes the
    Hamming kernel less sensitive for tiny samples; n=10 comfortably
    exceeds that threshold.
    """
    fingerprints = {
        "anthropic/claude-opus-4": _fp(
            "anthropic/claude-opus-4",
            "p1",
            [
                "The quick brown fox jumps over the lazy dog again and again.",
                "Programming languages evolve rapidly in response to new needs.",
                "Machine learning models require careful tuning of hyperparameters.",
                "Software engineering balances design with practical constraints.",
                "Data structures fundamentally determine algorithmic efficiency.",
                "Network protocols encode reliability over unreliable channels.",
                "Compilers translate high-level intent to machine instructions.",
                "Distributed systems face inherent tradeoffs in consistency.",
                "Operating systems orchestrate access to shared resources.",
                "Cryptographic primitives build foundations of modern security.",
            ],
        ),
    }
    # A visibly different distribution: numeric / symbolic content
    gateway = _gw(
        "p1",
        [
            "3141592653589793238462643383279502884197169399375105820974944",
            "2718281828459045235360287471352662497757247093699959574966967",
            "1414213562373095048801688724209698078569671875376948073176679",
            "1732050807568877293527446341505872366942805253810380628055806",
            "2236067977499789696409173668731276235440618359611525724270897",
            "1618033988749894848204586834365638117720309179805762862135448",
            "0577215664901532860606512090082402431042159335939923598805767",
            "4669201609102990671853203820466201617258185577475768632745651",
            "1202056903159594285399738161511449990764986292340498881792271",
            "0915965594177219015054603514932384110774149374281672134266498",
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
    assert result.details["combined_p_value"] < 0.1
    assert result.details["mean_effect_size"] > 0.0


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


def test_multiple_probes_combines_p_values() -> None:
    """Across multiple probes, p-values are retained and combined."""
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
    assert 0.0 <= result.details["combined_p_value"] <= 1.0
    assert result.details["legacy_mean_p_score"] >= result.score


def test_fisher_combined_p_value_matches_single_probe() -> None:
    assert _fisher_combined_p_value([0.25]) == 0.25


def test_calibrated_score_avoids_mean_p_saturation() -> None:
    score = _calibrated_similarity_score(combined_p_value=0.55, mean_effect_size=0.25)
    assert 0.0 < score < 1.0
