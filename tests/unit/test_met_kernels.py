"""detectors/_met_kernels.py — direct tests of the vendored MET math.

These tests exercise the algorithmic invariants documented in the
MET paper (and in the upstream ``model_equality_testing`` package we
vendored from). If any of them fail the divergence from upstream is
real — investigate before patching.
"""

from __future__ import annotations

import random

from api_key_scanner.detectors._met_kernels import (
    hamming_gram,
    mmd_squared,
    pad_unicode,
    two_sample_permutation_pvalue,
)


# -- pad_unicode --------------------------------------------------------------


def test_pad_unicode_exact_length_round_trip() -> None:
    cps = pad_unicode("hello", length=5)
    assert cps == (ord("h"), ord("e"), ord("l"), ord("l"), ord("o"))


def test_pad_unicode_short_strings_right_padded_with_minus_one() -> None:
    cps = pad_unicode("hi", length=5)
    assert cps == (ord("h"), ord("i"), -1, -1, -1)


def test_pad_unicode_long_strings_are_truncated() -> None:
    cps = pad_unicode("hello world", length=5)
    assert cps == (ord("h"), ord("e"), ord("l"), ord("l"), ord("o"))


def test_pad_unicode_handles_non_ascii_codepoints() -> None:
    cps = pad_unicode("你好", length=3)
    assert cps == (ord("你"), ord("好"), -1)


# -- hamming_gram -------------------------------------------------------------


def test_hamming_gram_diagonal_equals_length() -> None:
    seqs = [pad_unicode("hello", 5), pad_unicode("world", 5), pad_unicode("", 5)]
    gram = hamming_gram(seqs)
    for i in range(len(seqs)):
        assert gram[i][i] == 5.0


def test_hamming_gram_is_symmetric() -> None:
    seqs = [pad_unicode(w, 10) for w in ["alpha", "beta", "gamma", "delta"]]
    gram = hamming_gram(seqs)
    for i in range(len(seqs)):
        for j in range(len(seqs)):
            assert gram[i][j] == gram[j][i]


def test_hamming_gram_counts_positional_matches() -> None:
    # "abc" vs "axc" => match positions 0 and 2 = 2 matches
    seqs = [pad_unicode("abc", 3), pad_unicode("axc", 3)]
    gram = hamming_gram(seqs)
    assert gram[0][1] == 2.0


# -- mmd_squared --------------------------------------------------------------


def test_mmd_squared_is_zero_when_x_equals_y() -> None:
    seqs = [pad_unicode(s, 5) for s in ["hello", "world", "hello", "world"]]
    gram = hamming_gram(seqs)
    # x_idx == y_idx -> (1/n² ΣK) + (1/n² ΣK) - (2/n² ΣK) = 0
    x_idx = [0, 1]
    y_idx = [0, 1]
    assert mmd_squared(gram, x_idx, y_idx) == 0.0


def test_mmd_squared_clamps_to_zero() -> None:
    # Biased estimator can be slightly negative; clamp is documented.
    seqs = [pad_unicode(s, 5) for s in ["aaaaa", "bbbbb", "aaaaa", "bbbbb"]]
    gram = hamming_gram(seqs)
    result = mmd_squared(gram, [0, 1], [2, 3])
    assert result >= 0.0


def test_mmd_squared_empty_sample_returns_zero() -> None:
    gram = hamming_gram([pad_unicode("abc", 3)])
    assert mmd_squared(gram, x_idx=[], y_idx=[0]) == 0.0
    assert mmd_squared(gram, x_idx=[0], y_idx=[]) == 0.0


# -- two_sample_permutation_pvalue ---------------------------------------------


def test_pvalue_is_high_when_distributions_match() -> None:
    """Draws from the same pool -> p-value ~uniform -> ~0.5 on average."""
    pool = [
        pad_unicode(s, 30)
        for s in [
            "the first sample of alpha text",
            "the second sample of alpha text",
            "the third sample of alpha text",
            "the fourth sample of alpha text",
            "the fifth sample of alpha text",
            "the sixth sample of alpha text",
            "the seventh sample of alpha text",
            "the eighth sample of alpha text",
            "the ninth sample of alpha text",
            "the tenth sample of alpha text",
        ]
    ]
    x, y = pool[:5], pool[5:]
    rng = random.Random(42)
    p_value, mmd2 = two_sample_permutation_pvalue(x, y, b=200, rng=rng)
    # Same distribution — p should NOT reject; expect p > 0.1 comfortably
    assert p_value > 0.1
    assert mmd2 >= 0.0


def test_pvalue_is_low_when_distributions_clearly_differ() -> None:
    x = [pad_unicode(f"abcdefghij{i}" * 5, 50) for i in range(10)]
    y = [pad_unicode(str(i) * 50, 50) for i in range(10)]
    rng = random.Random(42)
    p_value, mmd2 = two_sample_permutation_pvalue(x, y, b=500, rng=rng)
    # Radically different distributions -> p should be tiny
    assert p_value < 0.05
    assert mmd2 > 0.0


def test_pvalue_deterministic_under_fixed_rng() -> None:
    x = [pad_unicode(f"alpha-{i}", 20) for i in range(5)]
    y = [pad_unicode(f"beta-{i}", 20) for i in range(5)]
    p1, _ = two_sample_permutation_pvalue(x, y, b=100, rng=random.Random(123))
    p2, _ = two_sample_permutation_pvalue(x, y, b=100, rng=random.Random(123))
    assert p1 == p2


def test_pvalue_respects_phipson_smyth_correction() -> None:
    # Even with zero permutations exceeding observed, p = 1/(b+1) > 0
    rng = random.Random(42)
    x = [pad_unicode("xxxxxxxxxx", 10)] * 3
    y = [pad_unicode("yyyyyyyyyy", 10)] * 3
    p_value, _ = two_sample_permutation_pvalue(x, y, b=50, rng=rng)
    assert p_value >= 1 / 51  # minimum under the +1/+1 correction
