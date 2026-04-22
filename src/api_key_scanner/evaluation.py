"""Shared verdict evaluation logic for server and offline scripts."""

from __future__ import annotations

from collections import defaultdict

from api_key_scanner import __version__
from api_key_scanner import probes as probes_mod
from api_key_scanner.detectors import fusion, llmmap, met, metadata
from api_key_scanner.schemas import (
    DetectorResult,
    Evidence,
    FingerprintEntry,
    Probe,
    ProbeResponse,
    Verdict,
)

_DETECTOR_ALIASES = {
    "d1": "d1_llmmap",
    "d1_llmmap": "d1_llmmap",
    "d2": "d2_met",
    "d2_met": "d2_met",
    "d4": "d4_metadata",
    "d4_metadata": "d4_metadata",
}


def evaluate_responses(
    *,
    endpoint_url: str,
    claimed_model: str,
    canonical_id: str,
    probe_list: list[Probe],
    responses: list[ProbeResponse],
    fingerprints: dict[str, list[FingerprintEntry]],
    probe_set_version: str,
    duration_ms: int,
    include_raw_responses: bool = False,
) -> Verdict:
    detector_probe_ids = build_detector_probe_ids(probe_list)
    probe_index = {probe.probe_id: probe for probe in probe_list}
    probe_category_by_id = {probe.probe_id: probe.category for probe in probe_list}

    d1 = llmmap.run(
        gateway_responses=responses,
        fingerprints=fingerprints,
        claimed_model_id=canonical_id,
        probe_category_filter=None,
        probe_category_by_id=probe_category_by_id,
        allowed_probe_ids=detector_probe_ids["d1_llmmap"],
    )
    d2 = met.run(
        gateway_responses=responses,
        fingerprints=fingerprints,
        claimed_model_id=canonical_id,
        allowed_probe_ids=detector_probe_ids["d2_met"],
    )
    d4 = metadata.run(
        gateway_responses=responses,
        fingerprints=fingerprints,
        claimed_model_id=canonical_id,
        probes=probe_list,
    )
    detectors = [d1, d2, d4]

    trust_score = fusion.combine(detectors)
    verdict_label = fusion.label(trust_score, detectors)
    conf = fusion.confidence(detectors)
    evidence = build_evidence(
        responses,
        detectors,
        probe_index=probe_index,
        include_raw=include_raw_responses,
    )
    num_failed = sum(1 for r in responses if r.error)

    return Verdict(
        trust_score=trust_score,
        verdict=verdict_label,
        confidence=conf,
        claimed_model=claimed_model,
        resolved_model_id=canonical_id,
        endpoint_url=endpoint_url,
        detectors={d.name: d for d in detectors},
        evidence=evidence,
        probe_set_version=probe_set_version,
        fingerprint_version=probes_mod.current_fingerprint_version(),
        mcp_version=__version__,
        num_probes_sent=len(responses),
        num_probes_failed=num_failed,
        duration_ms=duration_ms,
    )


def build_evidence(
    responses: list[ProbeResponse],
    detectors: list[DetectorResult],
    *,
    probe_index: dict[str, Probe] | None = None,
    include_raw: bool = False,
    max_items: int = 8,
) -> list[Evidence]:
    """Turn detector details + sample data into human-readable evidence items."""
    out: list[Evidence] = []

    error_responses = [r for r in responses if r.error]
    if error_responses:
        sample = error_responses[0]
        error_text = (sample.error or "")[:220]
        out.append(
            Evidence(
                probe_id=sample.probe_id,
                category="metadata",
                observation=(
                    f"{len(error_responses)}/{len(responses)} probes failed. "
                    f"first error: {error_text}"
                ),
                severity="alarm",
            )
        )

    d1 = _find_detector(detectors, "d1_llmmap")
    if d1 and d1.status != "failed":
        top_guess = d1.details.get("top_guess")
        votes = d1.details.get("top_guess_votes", 0)
        total_scored = d1.details.get("num_samples_scored", 0)
        if top_guess and d1.score < 1.0:
            out.append(
                Evidence(
                    probe_id="llmmap-aggregate",
                    category="identification",
                    observation=(
                        f"D1 LLMmap: top-guess is {top_guess} ({votes}/{total_scored} samples), "
                        f"score {d1.score:.2f}"
                    ),
                    severity="alarm" if d1.score == 0.0 else "warn",
                )
            )

    d2 = _find_detector(detectors, "d2_met")
    if d2 and d2.status != "failed":
        per_probe = d2.details.get("per_probe") or []
        per_probe_sorted = sorted(per_probe, key=lambda p: p.get("p_value", 1.0))
        for entry in per_probe_sorted[:2]:
            p_val = entry.get("p_value", 1.0)
            if p_val < 0.1:
                out.append(
                    Evidence(
                        probe_id=entry.get("probe_id", "?"),
                        category=probe_category(
                            probe_index, entry.get("probe_id", "?"), fallback="metadata"
                        ),
                        observation=(
                            f"D2 MET: MMD two-sample test rejected at p={p_val:.3f} "
                            f"(gateway distribution diverges from reference)"
                        ),
                        severity="alarm" if p_val < 0.02 else "warn",
                    )
                )

    d4 = _find_detector(detectors, "d4_metadata")
    if d4 and d4.status != "failed":
        for sig in d4.details.get("signals", []):
            if sig.get("score", 1.0) <= 0.3:
                out.append(
                    Evidence(
                        probe_id="metadata-aggregate",
                        category="metadata",
                        observation=f"D4 {sig['name']}: {sig['reason']}",
                        severity="alarm" if sig["score"] <= 0.3 else "warn",
                    )
                )

    if include_raw:
        for r in responses[:3]:
            if r.output:
                short = r.output[:120] + ("..." if len(r.output) > 120 else "")
                out.append(
                    Evidence(
                        probe_id=r.probe_id,
                        category=probe_category(probe_index, r.probe_id, fallback="identification"),
                        observation=f'sample[{r.sample_index}]: "{short}"',
                        severity="info",
                    )
                )

    return out[:max_items]


def build_detector_probe_ids(probes: list[Probe]) -> dict[str, set[str]]:
    out: dict[str, set[str]] = defaultdict(set)
    for probe in probes:
        for name in normalized_expected_detector_names(probe):
            out[name].add(probe.probe_id)

    for canonical_name in ("d1_llmmap", "d2_met", "d4_metadata"):
        out.setdefault(canonical_name, set())
    return dict(out)


def normalized_expected_detector_names(probe: Probe) -> set[str]:
    raw_names = probe.expected_detectors[:]
    if not raw_names:
        if probe.probe_id.startswith("llmmap-"):
            raw_names.append("d1")
        elif probe.probe_id.startswith("met-"):
            raw_names.append("d2")

    normalized: set[str] = set()
    for raw in raw_names:
        mapped = _DETECTOR_ALIASES.get(raw)
        if mapped is not None:
            normalized.add(mapped)
    return normalized


def probe_category(probe_index: dict[str, Probe] | None, probe_id: str, *, fallback: str) -> str:
    if probe_index is None:
        return fallback
    probe = probe_index.get(probe_id)
    return probe.category if probe is not None else fallback


def _find_detector(detectors: list[DetectorResult], name: str) -> DetectorResult | None:
    for d in detectors:
        if d.name == name:
            return d
    return None
