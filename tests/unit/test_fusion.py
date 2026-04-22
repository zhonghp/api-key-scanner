"""detectors/fusion.py tests."""

from __future__ import annotations

from api_key_scanner.detectors.fusion import (
    DEFAULT_PRIOR,
    combine,
    confidence,
    label,
)
from api_key_scanner.schemas import DetectorResult


def _d(name: str, score: float, status: str = "ok", weight: float | None = None) -> DetectorResult:
    # Let fusion.py use its own weight config when not specified
    weight_map = {"d1_banner_match": 0.45, "d2_met": 0.40, "d4_metadata": 0.15}
    return DetectorResult(
        name=name,
        score=score,
        weight=weight if weight is not None else weight_map.get(name, 0.0),
        status=status,
    )


def test_all_high_scores_give_high_posterior() -> None:
    detectors = [
        _d("d1_banner_match", 1.0),
        _d("d2_met", 0.95),
        _d("d4_metadata", 0.9),
    ]
    score = combine(detectors)
    # prior 0.85 + all evidence supportive -> very close to 1
    assert score > 0.98


def test_all_low_scores_give_low_posterior() -> None:
    detectors = [
        _d("d1_banner_match", 0.0),
        _d("d2_met", 0.05),
        _d("d4_metadata", 0.2),
    ]
    score = combine(detectors)
    # Strongly contradictory evidence -> should drop well below prior
    assert score < 0.5


def test_prior_preserved_with_neutral_evidence() -> None:
    detectors = [_d("d1_banner_match", 0.5), _d("d2_met", 0.5), _d("d4_metadata", 0.5)]
    score = combine(detectors)
    # weighted=0.5 -> posterior = prior * 0.5 / (prior * 0.5 + (1-prior)*0.5)
    #                        = prior
    assert abs(score - DEFAULT_PRIOR) < 0.01


def test_failed_detectors_excluded_and_weights_renormalized() -> None:
    detectors = [
        _d("d1_banner_match", 0.9),
        _d("d2_met", 0.0, status="failed"),
        _d("d4_metadata", 0.9),
    ]
    score = combine(detectors)
    # Even though d2 failed, d1 + d4 are high -> score should still be high
    assert score > 0.9


def test_all_failed_returns_zero() -> None:
    detectors = [
        _d("d1_banner_match", 0.0, status="failed"),
        _d("d2_met", 0.0, status="failed"),
        _d("d4_metadata", 0.0, status="failed"),
    ]
    score = combine(detectors)
    assert score == 0.0


def test_label_thresholds() -> None:
    d_ok = [_d("d1_banner_match", 1.0), _d("d2_met", 1.0), _d("d4_metadata", 1.0)]
    assert label(0.95, d_ok) == "ok"
    assert label(0.80, d_ok) == "suspicious"
    assert label(0.50, d_ok) == "likely_substituted"


def test_label_inconclusive_when_all_failed() -> None:
    d_failed = [
        _d("d1_banner_match", 0.0, status="failed"),
        _d("d2_met", 0.0, status="failed"),
    ]
    assert label(0.0, d_failed) == "inconclusive"


def test_label_inconclusive_when_all_degraded_in_grey_zone() -> None:
    d_deg = [
        _d("d1_banner_match", 0.8, status="degraded"),
        _d("d2_met", 0.8, status="degraded"),
    ]
    assert label(0.80, d_deg) == "inconclusive"


def test_confidence_high_when_two_ok_no_failures() -> None:
    assert (
        confidence(
            [
                _d("d1_banner_match", 0.9, status="ok"),
                _d("d2_met", 0.9, status="ok"),
                _d("d4_metadata", 0.9, status="degraded"),
            ]
        )
        == "high"
    )


def test_confidence_low_when_multiple_failed() -> None:
    assert (
        confidence(
            [
                _d("d1_banner_match", 0.0, status="failed"),
                _d("d2_met", 0.0, status="failed"),
                _d("d4_metadata", 0.9, status="ok"),
            ]
        )
        == "low"
    )
