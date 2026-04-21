"""D4 · Metadata / side-channel checks.

Cheap, orthogonal signals that don't require text analysis:
  1. system_fingerprint stability: OpenAI returns this per response; for
     a given real model it should cluster around a small set of values.
     A gateway routing across multiple models will show higher entropy.
  2. Response latency distribution: real vendor endpoints have a
     characteristic latency envelope; extreme outliers are suspicious.
  3. Failure pattern: high error rate on probes the reference never
     failed on is itself a signal.

Absent a strong signal we return a neutral score (not 0.0); D4 is the
weakest detector and should not dominate fusion. Weight = 0.15.
"""

from __future__ import annotations

import statistics
from collections import Counter

from api_key_scanner.schemas import DetectorResult, FingerprintEntry, ProbeResponse


def run(
    *,
    gateway_responses: list[ProbeResponse],
    fingerprints: dict[str, list[FingerprintEntry]],
    claimed_model_id: str,
) -> DetectorResult:
    """Run D4 metadata checks."""
    ref_entries = fingerprints.get(claimed_model_id, [])

    signals: list[tuple[str, float, str]] = []  # (signal_name, score_0_to_1, reason)

    signals.append(_error_rate_signal(gateway_responses))
    signals.append(_fingerprint_stability_signal(gateway_responses, ref_entries))
    signals.append(_latency_envelope_signal(gateway_responses, ref_entries))

    # Combine: average of active signals (skip neutral ones = score 0.7 sentinel)
    active = [(n, s, r) for (n, s, r) in signals if s >= 0.0]
    if not active:
        return DetectorResult(
            name="d4_metadata",
            score=0.7,
            weight=0.15,
            status="degraded",
            details={"reason": "no active metadata signals"},
        )

    mean_score = sum(s for (_, s, _) in active) / len(active)
    status = "ok" if len(active) >= 2 else "degraded"

    return DetectorResult(
        name="d4_metadata",
        score=mean_score,
        weight=0.15,
        status=status,
        details={
            "signals": [{"name": n, "score": round(s, 3), "reason": r} for (n, s, r) in active]
        },
    )


def _error_rate_signal(gateway_responses: list[ProbeResponse]) -> tuple[str, float, str]:
    if not gateway_responses:
        return ("error_rate", -1.0, "no gateway responses")
    errors = sum(1 for r in gateway_responses if r.error)
    total = len(gateway_responses)
    rate = errors / total
    # Heuristic mapping
    if rate == 0:
        return ("error_rate", 1.0, "no errors")
    if rate < 0.1:
        return ("error_rate", 0.9, f"low error rate {rate:.0%}")
    if rate < 0.3:
        return ("error_rate", 0.6, f"moderate error rate {rate:.0%}")
    return ("error_rate", 0.3, f"high error rate {rate:.0%}")


def _fingerprint_stability_signal(
    gateway_responses: list[ProbeResponse], ref_entries: list[FingerprintEntry]
) -> tuple[str, float, str]:
    gw_fps = [r.system_fingerprint for r in gateway_responses if r.system_fingerprint]
    ref_fps = [e.system_fingerprint for e in ref_entries if e.system_fingerprint]

    if not gw_fps and not ref_fps:
        return ("fingerprint_stability", -1.0, "no system_fingerprint on either side")

    if not gw_fps:
        # Reference has it but gateway doesn't -> either different infra or
        # gateway stripped it. Mild signal.
        return (
            "fingerprint_stability",
            0.5,
            "reference provides system_fingerprint but gateway never does",
        )

    if not ref_fps:
        return (
            "fingerprint_stability",
            0.7,
            "gateway provides system_fingerprint but reference doesn't (vendor asymmetry)",
        )

    gw_set = set(gw_fps)
    ref_set = set(ref_fps)
    overlap = gw_set & ref_set

    if overlap:
        ratio = len(overlap) / len(gw_set)
        return (
            "fingerprint_stability",
            0.5 + 0.5 * ratio,  # map [0, 1] -> [0.5, 1.0]
            f"{len(overlap)}/{len(gw_set)} gateway fingerprints match reference set",
        )

    return (
        "fingerprint_stability",
        0.2,
        f"gateway fingerprints {sorted(gw_set)[:3]} have zero overlap with reference",
    )


def _latency_envelope_signal(
    gateway_responses: list[ProbeResponse], ref_entries: list[FingerprintEntry]
) -> tuple[str, float, str]:
    gw_ms = [r.response_ms for r in gateway_responses if r.response_ms is not None]
    ref_ms = [e.response_ms for e in ref_entries if e.response_ms is not None]

    if len(gw_ms) < 3 or len(ref_ms) < 3:
        return ("latency_envelope", -1.0, "insufficient latency samples")

    ref_median = statistics.median(ref_ms)
    ref_stdev = statistics.pstdev(ref_ms) or 1.0
    gw_median = statistics.median(gw_ms)

    # Normalized z-ish score
    deviation = abs(gw_median - ref_median) / ref_stdev

    if deviation < 1.0:
        return ("latency_envelope", 1.0, f"gateway latency matches reference (z={deviation:.2f})")
    if deviation < 2.5:
        return (
            "latency_envelope",
            0.75,
            f"mild latency deviation (z={deviation:.2f})",
        )
    if deviation < 5.0:
        return (
            "latency_envelope",
            0.5,
            f"significant latency deviation (z={deviation:.2f})",
        )
    return (
        "latency_envelope",
        0.3,
        f"extreme latency deviation (z={deviation:.2f})",
    )


# Utilities used by integration code (not detectors) live here so callers
# can sanity-check token counts without importing tiktoken at the top level.
def prompt_tokens_sanity(
    gateway_responses: list[ProbeResponse], expected_tokenizer_family: str
) -> dict:
    """Diagnostic only; not part of the detector score.

    Returns a summary of how often the gateway's reported output_tokens
    match what a local tokenizer would give for the same text. The local
    tokenizer is resolved from expected_tokenizer_family ('openai/gpt' etc).
    """
    # Deferred import — tiktoken is heavy and we don't need it on every call
    try:
        import tiktoken
    except ImportError:
        return {"status": "skipped", "reason": "tiktoken not available"}

    enc_name = "cl100k_base" if expected_tokenizer_family.startswith("openai") else None
    if not enc_name:
        return {
            "status": "skipped",
            "reason": f"no tokenizer mapping for {expected_tokenizer_family}",
        }

    enc = tiktoken.get_encoding(enc_name)
    mismatches: list[dict] = []
    checks = 0
    for r in gateway_responses:
        if r.output_tokens is None or not r.output:
            continue
        local_count = len(enc.encode(r.output))
        # Allow ±2 tokens of slack for BOS/EOS handling differences
        if abs(local_count - r.output_tokens) > 2:
            mismatches.append(
                {
                    "probe_id": r.probe_id,
                    "sample_index": r.sample_index,
                    "gateway_reported": r.output_tokens,
                    "local_count": local_count,
                }
            )
        checks += 1

    return {
        "status": "ok",
        "checks": checks,
        "mismatches": len(mismatches),
        "mismatch_rate": (len(mismatches) / checks) if checks else 0.0,
        "examples": mismatches[:3],
    }


# Expose the module-level Counter for tests
_Counter = Counter
