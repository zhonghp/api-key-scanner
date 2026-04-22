"""MMD² two-sample test kernels for D2 MET.

Vendored (with attribution) from the MIT-licensed reference
implementation at:

    https://github.com/i-gao/model-equality-testing

Specifically, this file re-expresses:

  * ``model_equality_testing/src/tests.py`` — ``_mmd`` and
    ``mmd_hamming`` (biased MMD² estimator + Hamming kernel).
  * ``model_equality_testing/src/pvalue.py`` —
    ``two_sample_permutation_pvalue``.

We reimplemented both in pure Python (no numpy / torch) to keep the
MCP server dependency-light. The behaviour matches the single-prompt
path of the upstream for each probe we test (our per-probe setup
means each permutation test operates on one prompt, so the
prompt-aware masking in the upstream ``_mmd`` is a no-op here).

Original license (MIT):

    Copyright (c) 2024 Irena Gao.
    See https://github.com/i-gao/model-equality-testing/blob/main/model_equality_testing/LICENSE

If you change the semantics here, also note it in
``docs/2026-04-22-probes-与比对策略优化方案.md`` so downstream
re-sync with upstream stays deliberate.
"""

from __future__ import annotations

import random


def pad_unicode(text: str, length: int) -> tuple[int, ...]:
    """Convert ``text`` to a length-``length`` tuple of unicode codepoints.

    Characters past ``length`` are truncated. Short strings are right-
    padded with ``-1`` (the same sentinel the upstream package uses in
    its ``tokenize_unicode`` + ``pad_to_length`` helpers).

    Operating in codepoint space (rather than token space) is
    deliberate: MET audits traverse heterogeneous tokenizers across
    providers, so codepoints give a provider-independent alignment for
    the Hamming kernel.
    """
    codepoints = [ord(ch) for ch in text[:length]]
    if len(codepoints) < length:
        codepoints.extend(-1 for _ in range(length - len(codepoints)))
    return tuple(codepoints)


def hamming_gram(sequences: list[tuple[int, ...]]) -> list[list[float]]:
    """Full Hamming Gram matrix over ``sequences``.

    ``K[i, j] = sum_l 1[sequences[i][l] == sequences[j][l]]``.
    Assumes all sequences share the same length (``caller`` pads via
    :func:`pad_unicode`). The diagonal is the shared length — the
    kernel's intrinsic self-similarity.
    """
    n = len(sequences)
    if n == 0:
        return []
    length = len(sequences[0])

    gram: list[list[float]] = [[0.0] * n for _ in range(n)]
    for i in range(n):
        gram[i][i] = float(length)
        seq_i = sequences[i]
        for j in range(i + 1, n):
            seq_j = sequences[j]
            matches = 0
            for k in range(length):
                if seq_i[k] == seq_j[k]:
                    matches += 1
            gram[i][j] = float(matches)
            gram[j][i] = float(matches)
    return gram


def mmd_squared(
    gram: list[list[float]], x_idx: list[int], y_idx: list[int]
) -> float:
    """Biased MMD² estimator from a precomputed Gram matrix.

    ``MMD²(X, Y) = (1/n²) ΣᵢⱼK(xᵢ,xⱼ) + (1/m²) ΣᵢⱼK(yᵢ,yⱼ) -
    (2/nm) ΣᵢⱼK(xᵢ,yⱼ)``.

    Clamped at 0 — finite-sample biased estimator can be slightly
    negative under H₀, and a negative MMD² has no useful interpretation
    for permutation ordering.
    """
    n = len(x_idx)
    m = len(y_idx)
    if n == 0 or m == 0:
        return 0.0

    xx = sum(gram[i][j] for i in x_idx for j in x_idx) / (n * n)
    yy = sum(gram[i][j] for i in y_idx for j in y_idx) / (m * m)
    xy = sum(gram[i][j] for i in x_idx for j in y_idx) / (n * m)
    return max(0.0, xx + yy - 2.0 * xy)


def two_sample_permutation_pvalue(
    x_sequences: list[tuple[int, ...]],
    y_sequences: list[tuple[int, ...]],
    *,
    b: int,
    rng: random.Random,
) -> tuple[float, float]:
    """Permutation-based p-value for the two-sample MMD² test.

    Precomputes the pooled Hamming Gram matrix once, then each of the
    ``b`` permutations only re-indexes into it — no rekernelization
    per permutation. Matches the upstream algorithm in
    ``model_equality_testing/src/pvalue.py`` except for that
    efficiency detail.

    Returns ``(p_value, observed_mmd²)``. The ``+1`` / ``+1``
    correction on the p-value is the standard Phipson-Smyth convention
    that avoids ``p = 0`` when no null permutation exceeds the
    observed statistic.
    """
    pooled = list(x_sequences) + list(y_sequences)
    n_x = len(x_sequences)
    n_total = len(pooled)

    gram = hamming_gram(pooled)

    x_idx = list(range(n_x))
    y_idx = list(range(n_x, n_total))
    observed = mmd_squared(gram, x_idx, y_idx)

    ge_count = 0
    all_idx = list(range(n_total))
    for _ in range(b):
        shuffled = all_idx[:]
        rng.shuffle(shuffled)
        perm_x = shuffled[:n_x]
        perm_y = shuffled[n_x:]
        if mmd_squared(gram, perm_x, perm_y) >= observed:
            ge_count += 1

    p_value = (ge_count + 1) / (b + 1)
    return p_value, observed
