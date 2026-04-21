"""D1 · LLMmap-style discriminative classification.

For each gateway sample, find the closest reference sample across all
known models using character n-gram cosine similarity. Aggregate votes:
  - claimed_model wins                       -> 1.0 per sample
  - different model, SAME family             -> 0.5 per sample (A2 signal)
  - different model, CROSS-family            -> 0.0 per sample (A1 signal)

The final D1 score is the mean across all llmmap samples. Small sample
counts yield degraded confidence; zero samples -> detector reports 'failed'.

Reference: LLMmap (Pasquini, USENIX Sec'25). We use a lightweight
unsupervised cosine-NN variant instead of a trained classifier; Phase 1
focus is A1 (cross-family), where even this simple approach is strong.
"""

from __future__ import annotations

from collections import Counter
from dataclasses import dataclass

from api_key_scanner.aliases import same_family
from api_key_scanner.schemas import DetectorResult, FingerprintEntry, ProbeResponse

_NGRAM_N = 3


@dataclass
class _Candidate:
    model_id: str
    output: str


def run(
    *,
    gateway_responses: list[ProbeResponse],
    fingerprints: dict[str, list[FingerprintEntry]],
    claimed_model_id: str,
    probe_category_filter: str | None = "identification",
) -> DetectorResult:
    """Run D1 LLMmap.

    Args:
        gateway_responses: all gateway samples collected this run.
        fingerprints: canonical_id -> list of FingerprintEntry (across all probes).
        claimed_model_id: canonical id to compare against.
        probe_category_filter: if set, restrict to probes in this category
            (llmmap probes are typically 'identification' or 'refusal').
            None = use all.

    Returns:
        DetectorResult with name='d1_llmmap', score in [0, 1], weight=0.45.
    """
    # Gate: if we have no reference for the claimed model, we can't do D1
    if claimed_model_id not in fingerprints or not fingerprints[claimed_model_id]:
        return DetectorResult(
            name="d1_llmmap",
            score=0.0,
            weight=0.45,
            status="failed",
            details={"reason": f"no reference fingerprints for {claimed_model_id}"},
        )

    # Group gateway samples by probe_id, filter to llmmap-relevant probes.
    # The caller usually pre-filters with Probe.category, but we also allow
    # the fingerprint entries to carry category info in the future.
    usable_gateway = [r for r in gateway_responses if r.output and not r.error]
    if not usable_gateway:
        return DetectorResult(
            name="d1_llmmap",
            score=0.0,
            weight=0.45,
            status="failed",
            details={"reason": "no usable gateway responses"},
        )

    # Build reference pool, grouped by probe_id then model
    ref_by_probe: dict[str, dict[str, list[str]]] = {}
    for model_id, entries in fingerprints.items():
        for entry in entries:
            if not entry.output:
                continue
            ref_by_probe.setdefault(entry.probe_id, {}).setdefault(model_id, []).append(
                entry.output
            )

    # For each gateway sample, find nearest reference and score
    per_sample_scores: list[float] = []
    vote_counts: Counter[str] = Counter()  # tally of which model the gateway looks like

    for resp in usable_gateway:
        refs = ref_by_probe.get(resp.probe_id)
        if not refs:
            continue

        nn_model = _nearest_model(resp.output, refs)
        if nn_model is None:
            continue

        vote_counts[nn_model] += 1

        if nn_model == claimed_model_id:
            per_sample_scores.append(1.0)
        elif same_family(nn_model, claimed_model_id):
            per_sample_scores.append(0.5)
        else:
            per_sample_scores.append(0.0)

    if not per_sample_scores:
        return DetectorResult(
            name="d1_llmmap",
            score=0.0,
            weight=0.45,
            status="failed",
            details={"reason": "no gateway sample had matching reference probe"},
        )

    score = sum(per_sample_scores) / len(per_sample_scores)
    top_guess, top_count = vote_counts.most_common(1)[0]

    status = "ok" if len(per_sample_scores) >= 3 else "degraded"

    return DetectorResult(
        name="d1_llmmap",
        score=score,
        weight=0.45,
        status=status,
        details={
            "num_samples_scored": len(per_sample_scores),
            "top_guess": top_guess,
            "top_guess_votes": top_count,
            "vote_counts": dict(vote_counts),
            "claimed_wins": vote_counts.get(claimed_model_id, 0),
        },
    )


def _nearest_model(gateway_output: str, refs: dict[str, list[str]]) -> str | None:
    """Return the model whose reference samples are most similar to gateway_output.

    Averages cosine similarity across all refs per model to reduce sampling
    noise; ties broken lexicographically.
    """
    gateway_vec = _ngram_vector(gateway_output)
    if sum(gateway_vec.values()) == 0:
        return None

    best_model: str | None = None
    best_sim = -1.0

    for model_id in sorted(refs.keys()):
        sims = [_cosine(gateway_vec, _ngram_vector(r)) for r in refs[model_id]]
        if not sims:
            continue
        mean_sim = sum(sims) / len(sims)
        if mean_sim > best_sim:
            best_sim = mean_sim
            best_model = model_id

    return best_model


def _ngram_vector(text: str, n: int = _NGRAM_N) -> Counter[str]:
    if len(text) < n:
        return Counter([text]) if text else Counter()
    return Counter(text[i : i + n] for i in range(len(text) - n + 1))


def _cosine(a: Counter[str], b: Counter[str]) -> float:
    if not a or not b:
        return 0.0
    dot = sum(a[k] * b[k] for k in a.keys() & b.keys())
    na = sum(v * v for v in a.values()) ** 0.5
    nb = sum(v * v for v in b.values()) ** 0.5
    return dot / (na * nb) if na and nb else 0.0
