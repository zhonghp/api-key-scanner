"""Direct tests for the D2 MET kernel implementation."""

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
    text = "你好"
    cps = pad_unicode(text, length=3)
    assert cps == (ord(text[0]), ord(text[1]), -1)


# -- hamming_gram -------------------------------------------------------------


def test_hamming_gram_diagonal_equals_one() -> None:
    seqs = [pad_unicode("hello", 5), pad_unicode("world", 5), pad_unicode("", 5)]
    gram = hamming_gram(seqs)
    for i in range(len(seqs)):
        assert gram[i][i] == 1.0


def test_hamming_gram_is_symmetric() -> None:
    seqs = [pad_unicode(w, 10) for w in ["alpha", "beta", "gamma", "delta"]]
    gram = hamming_gram(seqs)
    for i in range(len(seqs)):
        for j in range(len(seqs)):
            assert gram[i][j] == gram[j][i]


def test_hamming_gram_counts_normalized_positional_matches() -> None:
    # "abc" vs "axc" => match positions 0 and 2 = 2 / 3.
    seqs = [pad_unicode("abc", 3), pad_unicode("axc", 3)]
    gram = hamming_gram(seqs)
    assert gram[0][1] == 2 / 3


def test_hamming_gram_rejects_mismatched_lengths() -> None:
    try:
        hamming_gram([(1, 2), (1, 2, 3)])
    except ValueError as exc:
        assert "same padded length" in str(exc)
    else:  # pragma: no cover - defensive
        raise AssertionError("expected ValueError")


# -- mmd_squared --------------------------------------------------------------


def test_mmd_squared_uses_off_diagonal_terms() -> None:
    seqs = [pad_unicode(s, 5) for s in ["aaaaa", "bbbbb", "aaaaa", "bbbbb"]]
    gram = hamming_gram(seqs)
    # With diagonal removed, the two same-distribution groups can produce a
    # negative finite-sample U-statistic instead of being clamped to zero.
    assert mmd_squared(gram, [0, 1], [2, 3]) < 0.0


def test_mmd_squared_positive_when_groups_are_far_apart() -> None:
    seqs = [pad_unicode(s, 5) for s in ["aaaaa", "aaaab", "xxxxx", "xxxxy"]]
    gram = hamming_gram(seqs)
    assert mmd_squared(gram, [0, 1], [2, 3]) > 0.0


def test_mmd_squared_tiny_sample_returns_zero() -> None:
    gram = hamming_gram([pad_unicode("abc", 3)])
    assert mmd_squared(gram, x_idx=[], y_idx=[0]) == 0.0
    assert mmd_squared(gram, x_idx=[0], y_idx=[]) == 0.0
    assert mmd_squared(gram, x_idx=[0], y_idx=[0]) == 0.0


# -- two_sample_permutation_pvalue --------------------------------------------


def test_pvalue_uses_exact_permutation_for_small_label_space() -> None:
    x = [pad_unicode(f"alpha-{i}", 20) for i in range(3)]
    y = [pad_unicode(f"beta-{i}", 20) for i in range(3)]
    result = two_sample_permutation_pvalue(x, y, b=100, rng=random.Random(42))
    assert result.method == "exact_permutation"
    assert result.num_resamples == 20
    assert result.permutation_space_size == 20
    assert 0.0 <= result.p_value <= 1.0


def test_pvalue_is_high_when_distributions_match() -> None:
    """Draws from the same pool should not be rejected."""
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
    result = two_sample_permutation_pvalue(pool[:5], pool[5:], b=200, rng=random.Random(42))
    assert result.p_value > 0.1


def test_pvalue_is_low_when_distributions_clearly_differ() -> None:
    x = [pad_unicode(f"abcdefghij{i}" * 5, 50) for i in range(10)]
    y = [pad_unicode(str(i) * 50, 50) for i in range(10)]
    result = two_sample_permutation_pvalue(x, y, b=500, rng=random.Random(42))
    assert result.p_value < 0.05
    assert result.observed_mmd_squared > 0.0


def test_sampled_pvalue_deterministic_under_fixed_rng() -> None:
    x = [pad_unicode(f"alpha-{i}", 20) for i in range(5)]
    y = [pad_unicode(f"beta-{i}", 20) for i in range(5)]
    r1 = two_sample_permutation_pvalue(x, y, b=100, rng=random.Random(123), exact_threshold=0)
    r2 = two_sample_permutation_pvalue(x, y, b=100, rng=random.Random(123), exact_threshold=0)
    assert r1.p_value == r2.p_value
    assert r1.method == "sampled_permutation_phipson_smyth"


def test_sampled_pvalue_respects_phipson_smyth_correction() -> None:
    rng = random.Random(42)
    x = [pad_unicode("xxxxxxxxxx", 10)] * 3
    y = [pad_unicode("yyyyyyyyyy", 10)] * 3
    result = two_sample_permutation_pvalue(x, y, b=50, rng=rng, exact_threshold=0)
    assert result.p_value >= 1 / 51
