"""MMD two-sample test kernels for D2 MET.

Vendored (with attribution) from the MIT-licensed reference implementation at:

    https://github.com/i-gao/model-equality-testing

Specifically, this file re-expresses:

* ``model_equality_testing/src/tests.py``: ``_mmd`` and ``mmd_hamming``
  using a normalized Hamming kernel and off-diagonal same-sample terms.
* ``model_equality_testing/src/pvalue.py``: ``two_sample_permutation_pvalue``.

The implementation stays dependency-light (pure Python, no numpy / torch).
Each permutation test operates on one probe/prompt, so the prompt-aware
masking in upstream ``_mmd`` is a no-op for this per-probe path. For small
samples, we enumerate every label assignment exactly instead of sampling
random permutations.
"""

from __future__ import annotations

import random
from dataclasses import dataclass
from itertools import combinations
from math import comb

_DEFAULT_EXACT_PERMUTATION_THRESHOLD = 50_000


@dataclass(frozen=True)
class PermutationTestResult:
    """Result of one two-sample permutation test."""

    p_value: float
    observed_mmd_squared: float
    method: str
    num_resamples: int
    permutation_space_size: int


def pad_unicode(text: str, length: int) -> tuple[int, ...]:
    """Convert ``text`` to a length-``length`` tuple of unicode codepoints.

    Characters past ``length`` are truncated. Short strings are right-padded
    with ``-1``, the sentinel used by upstream ``tokenize_unicode`` /
    ``pad_to_length`` helpers.
    """
    codepoints = [ord(ch) for ch in text[:length]]
    if len(codepoints) < length:
        codepoints.extend(-1 for _ in range(length - len(codepoints)))
    return tuple(codepoints)


def hamming_gram(sequences: list[tuple[int, ...]]) -> list[list[float]]:
    """Full normalized Hamming Gram matrix over ``sequences``.

    ``K[i, j] = mean_l 1[sequences[i][l] == sequences[j][l]]``. This is
    equivalent to upstream diagonal normalization for fixed-length Hamming
    kernels: self-similarity is ``1.0`` instead of the raw sequence length.
    """
    n = len(sequences)
    if n == 0:
        return []

    length = len(sequences[0])
    if any(len(seq) != length for seq in sequences):
        raise ValueError("all sequences must share the same padded length")
    normalizer = float(length) if length else 1.0

    gram: list[list[float]] = [[0.0] * n for _ in range(n)]
    for i in range(n):
        gram[i][i] = 1.0 if length else 0.0
        seq_i = sequences[i]
        for j in range(i + 1, n):
            seq_j = sequences[j]
            matches = 0
            for k in range(length):
                if seq_i[k] == seq_j[k]:
                    matches += 1
            gram[i][j] = matches / normalizer
            gram[j][i] = gram[i][j]
    return gram


def mmd_squared(gram: list[list[float]], x_idx: list[int], y_idx: list[int]) -> float:
    """Official-style MMD statistic from a precomputed Gram matrix.

    ``XX`` and ``YY`` self-matches on the diagonal are excluded, matching
    upstream ``_mmd`` for one prompt. The statistic is not clamped:
    finite-sample U-statistic estimates can be negative under H0, and those
    values carry information for permutation ordering.
    """
    n = len(x_idx)
    m = len(y_idx)
    if n < 2 or m < 2:
        return 0.0

    xx = sum(gram[i][j] for i in x_idx for j in x_idx if i != j) / (n * (n - 1))
    yy = sum(gram[i][j] for i in y_idx for j in y_idx if i != j) / (m * (m - 1))
    xy = sum(gram[i][j] for i in x_idx for j in y_idx) / (n * m)
    return xx + yy - 2.0 * xy


def two_sample_permutation_pvalue(
    x_sequences: list[tuple[int, ...]],
    y_sequences: list[tuple[int, ...]],
    *,
    b: int,
    rng: random.Random,
    exact_threshold: int = _DEFAULT_EXACT_PERMUTATION_THRESHOLD,
) -> PermutationTestResult:
    """Permutation-based p-value for the two-sample MMD test.

    Precompute the pooled Hamming Gram matrix once, then every permutation
    only re-indexes into it. If the full label-assignment space is small
    enough, enumerate it exactly. Otherwise sample ``b`` random permutations.

    For sampled permutations the ``+1`` / ``+1`` correction is the standard
    Phipson-Smyth convention that avoids ``p = 0`` when no null permutation
    exceeds the observed statistic. Exact enumeration does not need that
    correction because the observed assignment is included.
    """
    if b < 1:
        raise ValueError("b must be >= 1")

    pooled = list(x_sequences) + list(y_sequences)
    n_x = len(x_sequences)
    n_total = len(pooled)

    gram = hamming_gram(pooled)

    x_idx = list(range(n_x))
    y_idx = list(range(n_x, n_total))
    observed = mmd_squared(gram, x_idx, y_idx)

    all_idx = list(range(n_total))
    permutation_space_size = comb(n_total, n_x)

    if permutation_space_size <= exact_threshold:
        ge_count = 0
        for perm_x_tuple in combinations(all_idx, n_x):
            perm_x = list(perm_x_tuple)
            perm_x_set = set(perm_x)
            perm_y = [idx for idx in all_idx if idx not in perm_x_set]
            if mmd_squared(gram, perm_x, perm_y) >= observed:
                ge_count += 1

        return PermutationTestResult(
            p_value=ge_count / permutation_space_size,
            observed_mmd_squared=observed,
            method="exact_permutation",
            num_resamples=permutation_space_size,
            permutation_space_size=permutation_space_size,
        )

    ge_count = 0
    for _ in range(b):
        shuffled = all_idx[:]
        rng.shuffle(shuffled)
        perm_x = shuffled[:n_x]
        perm_y = shuffled[n_x:]
        if mmd_squared(gram, perm_x, perm_y) >= observed:
            ge_count += 1

    return PermutationTestResult(
        p_value=(ge_count + 1) / (b + 1),
        observed_mmd_squared=observed,
        method="sampled_permutation_phipson_smyth",
        num_resamples=b,
        permutation_space_size=permutation_space_size,
    )
