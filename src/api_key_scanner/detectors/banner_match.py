"""D1 · banner-match discriminative classification.

For each gateway sample (typically a short banner / meta / refusal
response), find the closest reference sample across all known models
using character n-gram cosine similarity. Aggregate votes:
  - claimed_model wins                       -> 1.0 per sample
  - different model, SAME family             -> 0.5 per sample (A2 signal)
  - different model, CROSS-family            -> 0.0 per sample (A1 signal)

The final D1 score is the mean across all D1-tagged samples. Small
sample counts yield degraded confidence; zero samples -> detector
reports 'failed'.

**Honest naming note**: this is NOT LLMmap in the paper sense. LLMmap
is a trained 3-layer transformer classifier on top of
multilingual-e5-large-instruct embeddings (see arXiv:2407.15847 and
pasquini-dario/LLMmap). We reuse LLMmap's 8 default queries as our
probe set, but our inference is a lightweight unsupervised cosine-NN
— hence "banner_match". Swapping in the real LLMmap classifier is a
future upgrade; the probe set is designed to stay compatible.
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
    allowed_probe_ids: set[str] | None = None,
) -> DetectorResult:
    """Run D1 banner-match.

    Args:
        gateway_responses: all gateway samples collected this run.
        fingerprints: canonical_id -> list of FingerprintEntry (across all probes).
        claimed_model_id: canonical id to compare against.
        allowed_probe_ids: if set, restrict both gateway samples and reference
            entries to probes whose id is in this set. Callers should pass the
            ids of probes whose ``expected_detectors`` contains ``"d1"`` so D1
            only sees its own data — otherwise MET continuation samples leak in
            and inflate the "num_samples_scored" field misleadingly. ``None``
            means "use all", preserved for back-compat with direct test calls.

    Returns:
        DetectorResult with name='d1_banner_match', score in [0, 1], weight=0.45.
    """
    # Gate: if we have no reference for the claimed model, we can't do D1
    if claimed_model_id not in fingerprints or not fingerprints[claimed_model_id]:
        return DetectorResult(
            name="d1_banner_match",
            score=0.0,
            weight=0.45,
            status="failed",
            details={"reason": f"no reference fingerprints for {claimed_model_id}"},
        )

    usable_gateway = [
        r
        for r in gateway_responses
        if r.output
        and not r.error
        and (allowed_probe_ids is None or r.probe_id in allowed_probe_ids)
    ]
    if not usable_gateway:
        return DetectorResult(
            name="d1_banner_match",
            score=0.0,
            weight=0.45,
            status="failed",
            details={"reason": "no usable gateway responses"},
        )

    # Build reference pool, grouped by probe_id then model. Same filter as
    # gateway side so D1 doesn't cross-compare against ref entries it shouldn't.
    ref_by_probe: dict[str, dict[str, list[str]]] = {}
    for model_id, entries in fingerprints.items():
        for entry in entries:
            if not entry.output:
                continue
            if allowed_probe_ids is not None and entry.probe_id not in allowed_probe_ids:
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
            name="d1_banner_match",
            score=0.0,
            weight=0.45,
            status="failed",
            details={"reason": "no gateway sample had matching reference probe"},
        )

    score = sum(per_sample_scores) / len(per_sample_scores)
    top_guess, top_count = vote_counts.most_common(1)[0]

    status = "ok" if len(per_sample_scores) >= 3 else "degraded"

    return DetectorResult(
        name="d1_banner_match",
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
