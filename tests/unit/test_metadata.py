"""detectors/metadata.py tests."""

from __future__ import annotations

import pytest

from api_key_scanner.detectors.metadata import run
from api_key_scanner.schemas import FingerprintEntry, ProbeResponse


def _gw(
    probe_id: str,
    output: str,
    *,
    response_ms: int | None = None,
    system_fingerprint: str | None = None,
    error: str | None = None,
    output_tokens: int | None = None,
    prompt_tokens: int | None = None,
    total_tokens: int | None = None,
) -> ProbeResponse:
    return ProbeResponse(
        probe_id=probe_id,
        sample_index=0,
        output=output if not error else "",
        prompt_tokens=prompt_tokens,
        response_ms=response_ms,
        system_fingerprint=system_fingerprint,
        error=error,
        output_tokens=output_tokens,
        total_tokens=total_tokens,
    )


def _ref(
    probe_id: str,
    output: str,
    *,
    response_ms: int | None = None,
    system_fingerprint: str | None = None,
    output_tokens: int | None = None,
    prompt_tokens: int | None = None,
    total_tokens: int | None = None,
) -> FingerprintEntry:
    return FingerprintEntry(
        probe_id=probe_id,
        sample_index=0,
        output=output,
        prompt_tokens=prompt_tokens,
        response_ms=response_ms,
        system_fingerprint=system_fingerprint,
        output_tokens=output_tokens,
        total_tokens=total_tokens,
        collected_at="2026-04-20T00:00:00Z",
    )


def test_no_errors_scores_high() -> None:
    gateway = [
        _gw("p1", "ok", response_ms=300, system_fingerprint="fp1"),
        _gw("p1", "ok", response_ms=320, system_fingerprint="fp1"),
        _gw("p2", "ok", response_ms=310, system_fingerprint="fp1"),
    ]
    fingerprints = {
        "x": [
            _ref("p1", "ok", response_ms=310, system_fingerprint="fp1"),
            _ref("p1", "ok", response_ms=320, system_fingerprint="fp1"),
            _ref("p2", "ok", response_ms=315, system_fingerprint="fp1"),
        ],
    }
    result = run(
        gateway_responses=gateway,
        fingerprints=fingerprints,
        claimed_model_id="x",
    )
    assert result.name == "d4_metadata"
    assert result.score > 0.8
    assert result.status == "ok"


def test_high_error_rate_drops_score() -> None:
    gateway = [
        _gw("p1", "", error="http 500"),
        _gw("p1", "", error="http 500"),
        _gw("p1", "ok", response_ms=300),
    ]
    result = run(
        gateway_responses=gateway,
        fingerprints={"x": [_ref("p1", "ok", response_ms=300)]},
        claimed_model_id="x",
    )
    # High error rate signal active -> score reduced
    signal_map = {s["name"]: s["score"] for s in result.details["signals"]}
    assert signal_map["error_rate"] <= 0.6


def test_mismatched_fingerprint_signals_suspicion() -> None:
    gateway = [
        _gw("p1", "ok", system_fingerprint="bogus_fp_XYZ"),
        _gw("p1", "ok", system_fingerprint="bogus_fp_XYZ"),
    ]
    fingerprints = {
        "x": [
            _ref("p1", "ok", system_fingerprint="real_fp_ABC"),
            _ref("p1", "ok", system_fingerprint="real_fp_ABC"),
        ],
    }
    result = run(gateway_responses=gateway, fingerprints=fingerprints, claimed_model_id="x")
    signal_map = {s["name"]: s["score"] for s in result.details["signals"]}
    assert signal_map.get("fingerprint_stability", 1.0) <= 0.3


def test_extreme_latency_deviation_drops_score() -> None:
    gateway = [
        _gw("p1", "ok", response_ms=5000),  # 10x reference median
        _gw("p1", "ok", response_ms=5100),
        _gw("p1", "ok", response_ms=4900),
    ]
    fingerprints = {
        "x": [
            _ref("p1", "ok", response_ms=500),
            _ref("p1", "ok", response_ms=520),
            _ref("p1", "ok", response_ms=480),
        ],
    }
    result = run(gateway_responses=gateway, fingerprints=fingerprints, claimed_model_id="x")
    signal_map = {s["name"]: s["score"] for s in result.details["signals"]}
    assert signal_map.get("latency_envelope", 1.0) <= 0.5


def test_empty_inputs_return_neutral() -> None:
    result = run(
        gateway_responses=[],
        fingerprints={},
        claimed_model_id="x",
    )
    # All signals skip -> falls back to neutral 0.7
    assert result.status == "degraded"
    assert result.score == 0.7


def test_replay_diversity_signal_flags_identical_high_temperature_outputs() -> None:
    gateway = [
        ProbeResponse(probe_id="met-001", sample_index=i, output="same replayed output")
        for i in range(5)
    ]
    fingerprints = {
        "x": [
            FingerprintEntry(
                probe_id="met-001",
                sample_index=i,
                output=f"reference variant {i}",
                collected_at="2026-04-20T00:00:00Z",
            )
            for i in range(5)
        ]
    }

    result = run(gateway_responses=gateway, fingerprints=fingerprints, claimed_model_id="x")
    signal_map = {s["name"]: s["score"] for s in result.details["signals"]}
    assert signal_map.get("replay_diversity", 1.0) <= 0.4


def test_token_count_consistency_flags_mismatched_gateway_counts() -> None:
    tiktoken = pytest.importorskip("tiktoken")
    try:
        enc = tiktoken.encoding_for_model("gpt-4o")
    except Exception:
        enc = tiktoken.get_encoding("o200k_base")

    texts = [f"hello world {i}" for i in range(3)]
    fingerprints = {
        "openai/gpt-4o": [_ref("p1", text, output_tokens=len(enc.encode(text))) for text in texts]
    }
    gateway = [_gw("p1", text, output_tokens=len(enc.encode(text)) + 10) for text in texts]

    result = run(
        gateway_responses=gateway,
        fingerprints=fingerprints,
        claimed_model_id="openai/gpt-4o",
    )
    signal_map = {s["name"]: s["score"] for s in result.details["signals"]}
    assert signal_map.get("token_count_consistency", 1.0) <= 0.3


def test_token_count_consistency_is_neutral_when_gateway_matches_reference_mismatch_rate() -> None:
    tiktoken = pytest.importorskip("tiktoken")
    try:
        enc = tiktoken.encoding_for_model("gpt-4o")
    except Exception:
        enc = tiktoken.get_encoding("o200k_base")

    texts = [f"cached output {i}" for i in range(3)]
    fingerprints = {
        "openai/gpt-4o": [
            _ref("p1", text, output_tokens=len(enc.encode(text)) + 9) for text in texts
        ]
    }
    gateway = [_gw("p1", text, output_tokens=len(enc.encode(text)) + 9) for text in texts]

    result = run(
        gateway_responses=gateway,
        fingerprints=fingerprints,
        claimed_model_id="openai/gpt-4o",
    )
    signal_map = {s["name"]: s["score"] for s in result.details["signals"]}
    assert signal_map.get("token_count_consistency", 0.0) >= 0.7


def test_usage_accounting_flags_inconsistent_totals() -> None:
    gateway = [
        _gw("met-001", "a", prompt_tokens=10, output_tokens=5, total_tokens=20),
        _gw("met-001", "b", prompt_tokens=12, output_tokens=6, total_tokens=18),
        _gw("met-001", "c", prompt_tokens=9, output_tokens=4, total_tokens=30),
    ]

    result = run(gateway_responses=gateway, fingerprints={"x": []}, claimed_model_id="x")
    signal_map = {s["name"]: s["score"] for s in result.details["signals"]}
    assert signal_map.get("usage_accounting", 1.0) <= 0.3
