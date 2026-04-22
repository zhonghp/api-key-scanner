"""D2 · Model Equality Testing (MET).

Per-probe two-sample hypothesis test:

    H0: gateway output distribution == reference output distribution
    H1: different distributions

Statistic: MMD² with Hamming kernel on unicode-codepoint sequences
padded to a shared length ``L``. P-value: permutation test
(default ``b=100``, matching the upstream ``demo.ipynb``).

Per-probe p-values are averaged into a single D2 score. Under H₀
they are ~uniform in ``[0, 1]`` (mean ~0.5), so
``score = clamp(2 * mean_p, 0, 1)`` gives ~1.0 for identical
distributions and collapses toward 0 as distributions diverge.

The MMD² / Hamming / permutation machinery is vendored from the
MIT-licensed reference implementation at
https://github.com/i-gao/model-equality-testing — see
``detectors/_met_kernels.py`` for the attribution notice and exact
upstream file paths.
"""

from __future__ import annotations

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


@dataclass
class _ProbePValue:
    probe_id: str
    p_value: float
    mmd_squared: float
    num_gateway: int
    num_reference: int


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
        DetectorResult with name='d2_met', score in [0, 1], weight=0.40.
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

        p_val, mmd2 = two_sample_permutation_pvalue(gw_seqs, ref_seqs, b=num_permutations, rng=rng)
        per_probe.append(
            _ProbePValue(
                probe_id=probe_id,
                p_value=p_val,
                mmd_squared=mmd2,
                num_gateway=len(gw_samples),
                num_reference=len(ref_samples),
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

    mean_p = sum(p.p_value for p in per_probe) / len(per_probe)
    score = min(1.0, 2.0 * mean_p)
    status = "ok" if len(per_probe) >= 3 else "degraded"

    return DetectorResult(
        name="d2_met",
        score=score,
        weight=0.40,
        status=status,
        details={
            "num_probes_tested": len(per_probe),
            "mean_p_value": mean_p,
            "min_p_value": min(p.p_value for p in per_probe),
            "pad_length": pad_length,
            "num_permutations": num_permutations,
            "per_probe": [
                {
                    "probe_id": p.probe_id,
                    "p_value": round(p.p_value, 4),
                    "mmd_squared": round(p.mmd_squared, 4),
                    "n_gateway": p.num_gateway,
                    "n_reference": p.num_reference,
                }
                for p in per_probe
            ],
        },
    )
