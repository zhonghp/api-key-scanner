"""D2 Model Equality Testing (MET).

Per-probe two-sample hypothesis test:

    H0: gateway output distribution == reference output distribution
    H1: different distributions

Statistic: official-style normalized Hamming-kernel MMD on unicode-codepoint
sequences padded to a shared length ``L``. P-value: exact permutation for
small label spaces, otherwise sampled permutation (default ``b=100``). Each
probe is tested independently, then p-values are combined with Fisher's method
and paired with a non-negative MMD effect size to produce a calibrated
similarity score.

The detector still reports ``mean_p_value`` for backward-compatible
diagnostics, but the main ``score`` is no longer ``2 * mean_p``. That
legacy mapping saturated at 1.0 whenever mean p-value exceeded 0.5,
which hid hard same-family confusions in small cheap-budget samples.

The Hamming / permutation machinery is adapted from the MIT-licensed
reference implementation at https://github.com/i-gao/model-equality-testing;
see ``detectors/_met_kernels.py`` for the attribution notice.
"""

from __future__ import annotations

import math
import random
from dataclasses import dataclass

from api_key_scanner.detectors._met_kernels import (
    pad_unicode,
    two_sample_permutation_pvalue,
)
from api_key_scanner.schemas import DetectorResult, FingerprintEntry, ProbeResponse

_DEFAULT_PERMUTATIONS = 100
_DEFAULT_PAD_LENGTH = 50  # MET paper: L=50 chars for Wikipedia continuation
_RNG_SEED = 20260420
_MIN_P_VALUE = 1e-12


@dataclass
class _ProbePValue:
    probe_id: str
    p_value: float
    mmd_squared: float
    effect_size: float
    num_gateway: int
    num_reference: int
    pvalue_method: str
    num_resamples: int
    permutation_space_size: int


def _clamp_probability(value: float) -> float:
    return min(1.0, max(_MIN_P_VALUE, value))


def _fisher_combined_p_value(p_values: list[float]) -> float:
    """Combine per-probe p-values using Fisher's method.

    For a chi-square distribution with even degrees of freedom ``2k``:
    ``P(ChiSq(2k) >= x) = exp(-x/2) * sum((x/2)^i / i!, i=0..k-1)``.
    This keeps the implementation dependency-light without scipy.
    """
    if not p_values:
        return 0.0

    fisher_lambda = -sum(math.log(_clamp_probability(p)) for p in p_values)
    term = 1.0
    total = 1.0
    for i in range(1, len(p_values)):
        term *= fisher_lambda / i
        total += term

    return min(1.0, max(0.0, math.exp(-fisher_lambda) * total))


def _calibrated_similarity_score(*, combined_p_value: float, mean_effect_size: float) -> float:
    """Map p-value and normalized MMD effect size to a similarity score.

    This is a lightweight heuristic until release-level reference-vs-reference
    calibration data is available. It deliberately avoids the old hard
    saturation at ``mean_p >= 0.5``.
    """
    p_component = math.sqrt(min(1.0, max(0.0, combined_p_value)))
    effect_component = 1.0 / (1.0 + 2.0 * max(0.0, mean_effect_size))
    score = 0.75 * p_component + 0.25 * effect_component
    return round(min(1.0, max(0.0, score)), 4)


def run(
    *,
    gateway_responses: list[ProbeResponse],
    fingerprints: dict[str, list[FingerprintEntry]],
    claimed_model_id: str,
    num_permutations: int = _DEFAULT_PERMUTATIONS,
    min_samples_per_side: int = 3,
    pad_length: int = _DEFAULT_PAD_LENGTH,
    allowed_probe_ids: set[str] | None = None,
) -> DetectorResult:
    """Run D2 MET.

    Args:
        gateway_responses: gateway samples (all probes, all samples).
        fingerprints: canonical_id -> reference entries.
        claimed_model_id: canonical id; we test gateway vs THIS model's refs.
        num_permutations: number of permutation resamples (default 100).
        min_samples_per_side: skip probes with fewer samples on either side.
        pad_length: unicode codepoint length to pad/truncate completions to
            (default 50; matches MET paper's Wikipedia task L).
        allowed_probe_ids: if set, restrict both gateway samples and reference
            entries to probes whose id is in this set. Callers should pass the
            ids of probes whose ``expected_detectors`` contains ``"d2"`` so D2
            only sees MET-style continuation probes (not banner probes whose
            T=0 samples would produce degenerate zero-variance distributions).

    Returns:
        DetectorResult with name='d2_met', calibrated score in [0, 1],
        weight=0.40.
    """
    if claimed_model_id not in fingerprints or not fingerprints[claimed_model_id]:
        return DetectorResult(
            name="d2_met",
            score=0.0,
            weight=0.40,
            status="failed",
            details={"reason": f"no reference fingerprints for {claimed_model_id}"},
        )

    gw_by_probe: dict[str, list[str]] = {}
    for r in gateway_responses:
        if (
            r.output
            and not r.error
            and (allowed_probe_ids is None or r.probe_id in allowed_probe_ids)
        ):
            gw_by_probe.setdefault(r.probe_id, []).append(r.output)

    ref_by_probe: dict[str, list[str]] = {}
    for entry in fingerprints[claimed_model_id]:
        if entry.output and (allowed_probe_ids is None or entry.probe_id in allowed_probe_ids):
            ref_by_probe.setdefault(entry.probe_id, []).append(entry.output)

    per_probe: list[_ProbePValue] = []
    rng = random.Random(_RNG_SEED)

    for probe_id, gw_samples in gw_by_probe.items():
        ref_samples = ref_by_probe.get(probe_id)
        if not ref_samples:
            continue
        if len(gw_samples) < min_samples_per_side or len(ref_samples) < min_samples_per_side:
            continue

        gw_seqs = [pad_unicode(s, pad_length) for s in gw_samples]
        ref_seqs = [pad_unicode(s, pad_length) for s in ref_samples]

        test_result = two_sample_permutation_pvalue(
            gw_seqs,
            ref_seqs,
            b=num_permutations,
            rng=rng,
        )
        mmd2 = test_result.observed_mmd_squared
        effect_size = max(0.0, mmd2)
        per_probe.append(
            _ProbePValue(
                probe_id=probe_id,
                p_value=test_result.p_value,
                mmd_squared=mmd2,
                effect_size=effect_size,
                num_gateway=len(gw_samples),
                num_reference=len(ref_samples),
                pvalue_method=test_result.method,
                num_resamples=test_result.num_resamples,
                permutation_space_size=test_result.permutation_space_size,
            )
        )

    if not per_probe:
        return DetectorResult(
            name="d2_met",
            score=0.0,
            weight=0.40,
            status="failed",
            details={"reason": (f"no probe had >= {min_samples_per_side} samples on both sides")},
        )

    p_values = [p.p_value for p in per_probe]
    mean_p = sum(p_values) / len(per_probe)
    combined_p = _fisher_combined_p_value(p_values)
    mean_mmd2 = sum(p.mmd_squared for p in per_probe) / len(per_probe)
    mean_effect_size = sum(p.effect_size for p in per_probe) / len(per_probe)
    legacy_mean_p_score = min(1.0, 2.0 * mean_p)
    score = _calibrated_similarity_score(
        combined_p_value=combined_p,
        mean_effect_size=mean_effect_size,
    )
    status = "ok" if len(per_probe) >= 3 else "degraded"
    pvalue_methods = sorted({p.pvalue_method for p in per_probe})
    pvalue_method = pvalue_methods[0] if len(pvalue_methods) == 1 else "mixed"

    return DetectorResult(
        name="d2_met",
        score=score,
        weight=0.40,
        status=status,
        details={
            "num_probes_tested": len(per_probe),
            "score_method": "fisher_pvalue_plus_mmd_effect_heuristic_v2",
            "mmd_variant": "official_style_normalized_ustat_v1",
            "pvalue_method": pvalue_method,
            "calibrated_similarity": score,
            "combined_p_value": combined_p,
            "mean_p_value": mean_p,
            "min_p_value": min(p.p_value for p in per_probe),
            "mean_mmd_statistic": mean_mmd2,
            "mean_mmd_squared": mean_mmd2,
            "mean_effect_size": mean_effect_size,
            "legacy_mean_p_score": legacy_mean_p_score,
            "pad_length": pad_length,
            "num_permutations": num_permutations,
            "per_probe": [
                {
                    "probe_id": p.probe_id,
                    "p_value": round(p.p_value, 4),
                    "mmd_squared": round(p.mmd_squared, 4),
                    "mmd_statistic": round(p.mmd_squared, 4),
                    "effect_size": round(p.effect_size, 4),
                    "n_gateway": p.num_gateway,
                    "n_reference": p.num_reference,
                    "pvalue_method": p.pvalue_method,
                    "num_resamples": p.num_resamples,
                    "permutation_space_size": p.permutation_space_size,
                }
                for p in per_probe
            ],
        },
    )
