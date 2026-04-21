"""Bayesian fusion of detector scores + verdict label mapping.

Formulation (design doc §5.4):

    prior = 0.85                         # most gateways are honest
    weights = {d1: 0.45, d2: 0.40, d4: 0.15}
    weighted = Σ score_i * weight_i
    posterior = prior * weighted / (prior * weighted + (1-prior) * (1-weighted))

This is a simple log-odds update but written in probability space for
readability. The resulting posterior is the `trust_score` in [0, 1].

Thresholds are Phase 1 defaults; §9 of the phase-1 plan requires a
calibration pass over positive/negative samples before shipping.
"""

from __future__ import annotations

from api_key_scanner.schemas import (
    Confidence,
    DetectorResult,
    VerdictLabel,
)

# Calibration targets from design doc §5.4 / §9.4
DEFAULT_WEIGHTS: dict[str, float] = {
    "d1_llmmap": 0.45,
    "d2_met": 0.40,
    "d4_metadata": 0.15,
}
DEFAULT_PRIOR: float = 0.85

# Verdict thresholds (design doc §4.4 / §5.4)
THRESHOLD_OK = 0.90
THRESHOLD_SUSPICIOUS = 0.70


def combine(
    detectors: list[DetectorResult],
    *,
    prior: float = DEFAULT_PRIOR,
    weights: dict[str, float] | None = None,
) -> float:
    """Fuse detector scores into a single trust_score in [0, 1].

    Detectors with status='failed' are excluded entirely. If all detectors
    fail, returns 0.0 (the caller should then mark verdict=inconclusive).
    Weights are renormalized across active detectors so one failure
    doesn't drag the score down artificially.
    """
    w = weights or DEFAULT_WEIGHTS
    active = [d for d in detectors if d.status != "failed"]
    if not active:
        return 0.0

    total_weight = sum(w.get(d.name, 0.0) for d in active)
    if total_weight <= 0:
        return 0.0

    weighted = sum(d.score * w.get(d.name, 0.0) for d in active) / total_weight

    # Avoid degenerate 0/0 when weighted is 0 or 1
    weighted = min(max(weighted, 1e-6), 1.0 - 1e-6)

    posterior = prior * weighted / (prior * weighted + (1.0 - prior) * (1.0 - weighted))
    return round(posterior, 4)


def label(trust_score: float, detectors: list[DetectorResult]) -> VerdictLabel:
    """Map (score, detector statuses) to a verdict label."""
    if not detectors:
        return "inconclusive"

    # If all detectors failed, the score isn't meaningful
    all_failed = all(d.status == "failed" for d in detectors)
    if all_failed:
        return "inconclusive"

    # If the active detectors all degraded AND score is borderline, flag as inconclusive
    active = [d for d in detectors if d.status != "failed"]
    all_degraded = all(d.status == "degraded" for d in active)
    if all_degraded and THRESHOLD_SUSPICIOUS <= trust_score < THRESHOLD_OK:
        return "inconclusive"

    if trust_score >= THRESHOLD_OK:
        return "ok"
    if trust_score >= THRESHOLD_SUSPICIOUS:
        return "suspicious"
    return "likely_substituted"


def confidence(detectors: list[DetectorResult]) -> Confidence:
    """Confidence in the verdict based on detector health."""
    if not detectors:
        return "low"

    statuses = [d.status for d in detectors]
    ok_count = sum(1 for s in statuses if s == "ok")
    degraded_count = sum(1 for s in statuses if s == "degraded")
    failed_count = sum(1 for s in statuses if s == "failed")

    if ok_count >= 2 and failed_count == 0:
        return "high"
    if ok_count >= 1 and failed_count <= 1:
        return "medium"
    if failed_count >= 2 or (failed_count == 1 and degraded_count >= 1):
        return "low"
    return "medium"
