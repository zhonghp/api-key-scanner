"""D2 · Model Equality Testing via MMD² two-sample test.

For each probe, we have:
  - gateway sample set X  (the endpoint under test)
  - reference sample set Y (the claimed model's fingerprint)

H0: X and Y come from the same distribution
H1: X and Y come from different distributions

We compute the biased MMD² estimator with a char-n-gram cosine kernel,
then obtain an empirical p-value by permutation test (default 500 perms).
Per-probe p-values are averaged into a single D2 score: identical
distributions produce uniform p-values in [0,1] (mean ~0.5), so we scale
score = clamp(2 * mean_p, 0, 1) so that identical -> ~1.0 and divergent -> ~0.

Reference: Model Equality Testing (Gao et al. ICLR'25). Our char-n-gram
kernel is a lightweight substitute for the paper's string kernel; upgrade
to the `model-equality-testing` PyPI package when it stabilises.
"""

from __future__ import annotations

import math
import random
from collections import Counter
from collections.abc import Sequence
from dataclasses import dataclass

from api_key_scanner.schemas import DetectorResult, FingerprintEntry, ProbeResponse

_NGRAM_N = 3
_DEFAULT_PERMUTATIONS = 500
_RNG_SEED = 20260420  # deterministic so the same inputs give the same p


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
) -> DetectorResult:
    """Run D2 MET.

    Args:
        gateway_responses: gateway samples (all probes, all samples).
        fingerprints: canonical_id -> reference entries.
        claimed_model_id: canonical id; we test gateway vs THIS model's refs.
        num_permutations: permutation test count (default 500).
        min_samples_per_side: skip probes with fewer samples on either side.

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

    # Group gateway outputs by probe_id
    gw_by_probe: dict[str, list[str]] = {}
    for r in gateway_responses:
        if r.output and not r.error:
            gw_by_probe.setdefault(r.probe_id, []).append(r.output)

    # Group reference outputs by probe_id
    ref_by_probe: dict[str, list[str]] = {}
    for entry in fingerprints[claimed_model_id]:
        if entry.output:
            ref_by_probe.setdefault(entry.probe_id, []).append(entry.output)

    per_probe: list[_ProbePValue] = []
    rng = random.Random(_RNG_SEED)

    for probe_id, gw_samples in gw_by_probe.items():
        ref_samples = ref_by_probe.get(probe_id)
        if not ref_samples:
            continue
        if len(gw_samples) < min_samples_per_side or len(ref_samples) < min_samples_per_side:
            continue

        p_val, mmd2 = _mmd_permutation_test(
            gw_samples, ref_samples, num_permutations=num_permutations, rng=rng
        )
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


def _mmd_permutation_test(
    x: Sequence[str],
    y: Sequence[str],
    *,
    num_permutations: int,
    rng: random.Random,
) -> tuple[float, float]:
    """Return (p_value, observed_mmd_squared).

    Uses a precomputed Gram matrix over the union (X ∪ Y) so each permutation
    only re-indexes, not re-kernelizes.
    """
    pooled = list(x) + list(y)
    n_x = len(x)
    n_y = len(y)
    n = n_x + n_y

    # Precompute n-gram vectors + self-norms once
    vecs = [_ngram_vector(s) for s in pooled]
    norms = [_l2(v) for v in vecs]

    # Gram matrix K[i, j] = cosine(vecs[i], vecs[j])
    gram: list[list[float]] = [[0.0] * n for _ in range(n)]
    for i in range(n):
        gram[i][i] = 1.0 if norms[i] > 0 else 0.0
        for j in range(i + 1, n):
            k = _cosine_from_precomputed(vecs[i], vecs[j], norms[i], norms[j])
            gram[i][j] = k
            gram[j][i] = k

    x_idx = list(range(n_x))
    y_idx = list(range(n_x, n))
    observed = _mmd_squared_from_gram(gram, x_idx, y_idx)

    ge_count = 0
    all_idx = list(range(n))
    for _ in range(num_permutations):
        shuffled = all_idx[:]
        rng.shuffle(shuffled)
        perm_x = shuffled[:n_x]
        perm_y = shuffled[n_x:]
        m = _mmd_squared_from_gram(gram, perm_x, perm_y)
        if m >= observed:
            ge_count += 1

    # Add 1 to numerator + denominator to avoid p=0 (standard correction)
    p_value = (ge_count + 1) / (num_permutations + 1)
    return p_value, observed


def _mmd_squared_from_gram(gram: list[list[float]], x_idx: list[int], y_idx: list[int]) -> float:
    """Biased MMD² estimator from Gram matrix slices.

    MMD²(X, Y) = mean K(xi, xj) + mean K(yi, yj) - 2 * mean K(xi, yj)
    """
    nx = len(x_idx)
    ny = len(y_idx)
    if nx == 0 or ny == 0:
        return 0.0

    xx = sum(gram[i][j] for i in x_idx for j in x_idx) / (nx * nx)
    yy = sum(gram[i][j] for i in y_idx for j in y_idx) / (ny * ny)
    xy = sum(gram[i][j] for i in x_idx for j in y_idx) / (nx * ny)
    return max(0.0, xx + yy - 2.0 * xy)


def _ngram_vector(text: str, n: int = _NGRAM_N) -> Counter[str]:
    if not text:
        return Counter()
    if len(text) < n:
        return Counter([text])
    return Counter(text[i : i + n] for i in range(len(text) - n + 1))


def _l2(v: Counter[str]) -> float:
    return math.sqrt(sum(x * x for x in v.values()))


def _cosine_from_precomputed(a: Counter[str], b: Counter[str], na: float, nb: float) -> float:
    if na <= 0 or nb <= 0:
        return 0.0
    # Iterate over the smaller Counter for the dot product
    if len(a) > len(b):
        a, b = b, a
    dot = sum(a[k] * b[k] for k in a.keys() & b.keys())
    return dot / (na * nb)
