"""detectors/metadata.py tests."""

from __future__ import annotations

from api_key_scanner.detectors.metadata import run
from api_key_scanner.schemas import FingerprintEntry, ProbeResponse


def _gw(
    probe_id: str,
    output: str,
    *,
    response_ms: int | None = None,
    system_fingerprint: str | None = None,
    error: str | None = None,
) -> ProbeResponse:
    return ProbeResponse(
        probe_id=probe_id,
        sample_index=0,
        output=output if not error else "",
        response_ms=response_ms,
        system_fingerprint=system_fingerprint,
        error=error,
    )


def _ref(
    probe_id: str,
    output: str,
    *,
    response_ms: int | None = None,
    system_fingerprint: str | None = None,
) -> FingerprintEntry:
    return FingerprintEntry(
        probe_id=probe_id,
        sample_index=0,
        output=output,
        response_ms=response_ms,
        system_fingerprint=system_fingerprint,
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
