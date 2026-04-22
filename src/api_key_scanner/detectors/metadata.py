"""D4 metadata and side-channel checks."""

from __future__ import annotations

import statistics
from collections import Counter
from collections.abc import Sequence
from typing import Any

from api_key_scanner.schemas import DetectorResult, FingerprintEntry, Probe, ProbeResponse


def run(
    *,
    gateway_responses: list[ProbeResponse],
    fingerprints: dict[str, list[FingerprintEntry]],
    claimed_model_id: str,
    probes: list[Probe] | None = None,
) -> DetectorResult:
    """Run D4 metadata checks."""
    ref_entries = fingerprints.get(claimed_model_id, [])

    signals: list[tuple[str, float, str]] = []
    signals.append(_error_rate_signal(gateway_responses))
    signals.append(_fingerprint_stability_signal(gateway_responses, ref_entries))
    signals.append(_latency_envelope_signal(gateway_responses, ref_entries))
    signals.append(_replay_diversity_signal(gateway_responses, ref_entries))
    signals.append(_usage_accounting_signal(gateway_responses, probes))
    signals.append(
        _token_count_consistency_signal(gateway_responses, ref_entries, claimed_model_id)
    )

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
        return (
            "fingerprint_stability",
            0.5,
            "reference provides system_fingerprint but gateway never does",
        )
    if not ref_fps:
        return (
            "fingerprint_stability",
            0.7,
            "gateway provides system_fingerprint but reference does not",
        )

    gw_set = set(gw_fps)
    ref_set = set(ref_fps)
    overlap = gw_set & ref_set
    if overlap:
        ratio = len(overlap) / len(gw_set)
        return (
            "fingerprint_stability",
            0.5 + 0.5 * ratio,
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
    deviation = abs(gw_median - ref_median) / ref_stdev

    if deviation < 1.0:
        return ("latency_envelope", 1.0, f"gateway latency matches reference (z={deviation:.2f})")
    if deviation < 2.5:
        return ("latency_envelope", 0.75, f"mild latency deviation (z={deviation:.2f})")
    if deviation < 5.0:
        return ("latency_envelope", 0.5, f"significant latency deviation (z={deviation:.2f})")
    return ("latency_envelope", 0.3, f"extreme latency deviation (z={deviation:.2f})")


def _replay_diversity_signal(
    gateway_responses: list[ProbeResponse], ref_entries: list[FingerprintEntry]
) -> tuple[str, float, str]:
    gw_groups = _outputs_by_probe(gateway_responses)
    ref_groups = _outputs_by_probe(ref_entries)

    probe_scores: list[float] = []
    suspicious = 0
    for probe_id, gw_outputs in gw_groups.items():
        ref_outputs = ref_groups.get(probe_id)
        if len(gw_outputs) < 3 or ref_outputs is None or len(ref_outputs) < 3:
            continue

        gw_div = _normalized_diversity(gw_outputs)
        ref_div = _normalized_diversity(ref_outputs)
        ratio = gw_div / max(ref_div, 0.05)

        if ratio >= 0.9:
            score = 1.0
        elif ratio >= 0.7:
            score = 0.8
        elif ratio >= 0.5:
            score = 0.6
        elif ratio >= 0.3:
            score = 0.4
            suspicious += 1
        else:
            score = 0.2
            suspicious += 1
        probe_scores.append(score)

    if not probe_scores:
        return ("replay_diversity", -1.0, "no multi-sample probes with reference diversity")

    mean_score = sum(probe_scores) / len(probe_scores)
    if suspicious:
        reason = (
            f"low output diversity on {suspicious}/{len(probe_scores)} multi-sample probes; "
            "possible cached replay"
        )
    else:
        reason = (
            f"output diversity matches reference across {len(probe_scores)} multi-sample probes"
        )
    return ("replay_diversity", mean_score, reason)


def _token_count_consistency_signal(
    gateway_responses: list[ProbeResponse],
    ref_entries: list[FingerprintEntry],
    claimed_model_id: str,
) -> tuple[str, float, str]:
    encoding = _resolve_tokenizer(claimed_model_id)
    if encoding is None:
        return (
            "token_count_consistency",
            -1.0,
            f"no local tokenizer mapping for {claimed_model_id}",
        )

    gw_summary = _token_count_mismatch_summary(gateway_responses, encoding)
    ref_summary = _token_count_mismatch_summary(ref_entries, encoding)
    if gw_summary["checks"] < 3 or ref_summary["checks"] < 3:
        return ("token_count_consistency", -1.0, "insufficient token-count samples")

    gw_rate = gw_summary["mismatch_rate"]
    ref_rate = ref_summary["mismatch_rate"]
    delta = abs(gw_rate - ref_rate)
    gw_minus_ref = gw_rate - ref_rate
    max_rate = max(gw_rate, ref_rate)

    if delta <= 0.05:
        if max_rate >= 0.80:
            score = 0.7
        elif max_rate >= 0.40:
            score = 0.85
        else:
            score = 1.0
    elif gw_minus_ref <= 0.0:
        score = 0.9 if delta <= 0.20 else 0.75
    elif gw_minus_ref <= 0.10:
        score = 0.8
    elif gw_minus_ref <= 0.20:
        score = 0.6
    else:
        score = 0.3

    if delta <= 0.05 and max_rate >= 0.80:
        reason = (
            f"gateway mismatch {gw_rate:.0%} ({gw_summary['checks']} checks), "
            f"reference {ref_rate:.0%} ({ref_summary['checks']} checks); "
            "both diverge from the local tokenizer at the same rate"
        )
    else:
        reason = (
            f"gateway mismatch {gw_rate:.0%} ({gw_summary['checks']} checks), "
            f"reference {ref_rate:.0%} ({ref_summary['checks']} checks)"
        )
    return ("token_count_consistency", score, reason)


def _usage_accounting_signal(
    gateway_responses: list[ProbeResponse],
    probes: list[Probe] | None,
) -> tuple[str, float, str]:
    usage_samples = [
        r
        for r in gateway_responses
        if any(v is not None for v in (r.prompt_tokens, r.output_tokens, r.total_tokens))
    ]
    if len(usage_samples) < 3:
        return ("usage_accounting", -1.0, "insufficient usage samples")

    arithmetic_checks = 0
    arithmetic_failures = 0
    prompt_tokens_by_probe: dict[str, list[int]] = {}

    known_probe_ids = {probe.probe_id for probe in probes} if probes is not None else None

    for item in usage_samples:
        if known_probe_ids is not None and item.probe_id not in known_probe_ids:
            continue
        if item.prompt_tokens is not None:
            prompt_tokens_by_probe.setdefault(item.probe_id, []).append(item.prompt_tokens)
        if (
            item.prompt_tokens is not None
            and item.output_tokens is not None
            and item.total_tokens is not None
        ):
            arithmetic_checks += 1
            if item.prompt_tokens + item.output_tokens != item.total_tokens:
                arithmetic_failures += 1
        elif item.output_tokens is not None and item.total_tokens is not None:
            arithmetic_checks += 1
            if item.total_tokens < item.output_tokens:
                arithmetic_failures += 1

    prompt_stability_checks = 0
    prompt_stability_failures = 0
    for prompt_tokens in prompt_tokens_by_probe.values():
        if len(prompt_tokens) < 2:
            continue
        prompt_stability_checks += 1
        if len(set(prompt_tokens)) != 1:
            prompt_stability_failures += 1

    if arithmetic_checks == 0 and prompt_stability_checks == 0:
        return (
            "usage_accounting",
            -1.0,
            "usage fields present but insufficient for accounting checks",
        )

    arithmetic_rate = arithmetic_failures / arithmetic_checks if arithmetic_checks else 0.0
    prompt_stability_rate = (
        prompt_stability_failures / prompt_stability_checks if prompt_stability_checks else 0.0
    )
    worst_rate = max(arithmetic_rate, prompt_stability_rate)

    if worst_rate == 0.0:
        score = 1.0
    elif worst_rate <= 0.10:
        score = 0.8
    elif worst_rate <= 0.25:
        score = 0.6
    else:
        score = 0.3

    reason = (
        f"usage arithmetic failed on {arithmetic_failures}/{arithmetic_checks or 0} checks; "
        f"prompt token stability failed on {prompt_stability_failures}/{prompt_stability_checks or 0} probes"
    )
    return ("usage_accounting", score, reason)


def prompt_tokens_sanity(
    gateway_responses: list[ProbeResponse], expected_tokenizer_family: str
) -> dict[str, Any]:
    """Diagnostic only; not part of the detector score."""
    encoding = _resolve_tokenizer(expected_tokenizer_family)
    if encoding is None:
        return {
            "status": "skipped",
            "reason": f"no tokenizer mapping for {expected_tokenizer_family}",
        }

    summary = _token_count_mismatch_summary(gateway_responses, encoding)
    return {
        "status": "ok",
        "checks": summary["checks"],
        "mismatches": summary["mismatches"],
        "mismatch_rate": summary["mismatch_rate"],
        "examples": summary["examples"],
    }


_Counter = Counter


def _outputs_by_probe(items: Sequence[ProbeResponse | FingerprintEntry]) -> dict[str, list[str]]:
    grouped: dict[str, list[str]] = {}
    for item in items:
        text = _normalize_output(item.output)
        if text:
            grouped.setdefault(item.probe_id, []).append(text)
    return grouped


def _normalized_diversity(outputs: Sequence[str]) -> float:
    if not outputs:
        return 0.0
    normalized = {_normalize_output(text) for text in outputs if _normalize_output(text)}
    return len(normalized) / len(outputs)


def _normalize_output(text: str) -> str:
    return " ".join(text.strip().lower().split())


def _resolve_tokenizer(expected_tokenizer_family: str) -> Any | None:
    try:
        import tiktoken
    except ImportError:
        return None

    if not expected_tokenizer_family.startswith("openai/"):
        return None

    model_name = expected_tokenizer_family.split("/", 1)[1]
    for candidate in (model_name, "o200k_base", "cl100k_base"):
        try:
            if candidate in ("o200k_base", "cl100k_base"):
                return tiktoken.get_encoding(candidate)
            return tiktoken.encoding_for_model(candidate)
        except Exception:
            continue
    return None


def _token_count_mismatch_summary(
    items: Sequence[ProbeResponse | FingerprintEntry], encoding: Any
) -> dict[str, Any]:
    mismatches: list[dict[str, Any]] = []
    checks = 0

    for item in items:
        if item.output_tokens is None or not item.output:
            continue
        local_count = len(encoding.encode(item.output))
        if abs(local_count - item.output_tokens) > 2:
            mismatches.append(
                {
                    "probe_id": item.probe_id,
                    "sample_index": item.sample_index,
                    "reported": item.output_tokens,
                    "local_count": local_count,
                }
            )
        checks += 1

    return {
        "checks": checks,
        "mismatches": len(mismatches),
        "mismatch_rate": (len(mismatches) / checks) if checks else 0.0,
        "examples": mismatches[:3],
    }
