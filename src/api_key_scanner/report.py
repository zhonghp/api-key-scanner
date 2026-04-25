"""Verdict -> human-readable markdown report.

Agents calling verify_gateway get back the JSON Verdict for programmatic
use and the rendered markdown here for narration. Keep under ~40 lines of
output; agents append their own context.
"""

from __future__ import annotations

from api_key_scanner.schemas import Verdict

_VERDICT_EMOJI = {
    "ok": "✅",
    "suspicious": "⚠️",
    "likely_substituted": "🚨",
    "inconclusive": "❔",
}
_VERDICT_HEADLINE = {
    "ok": "Consistent with the claimed model",
    "suspicious": "Suspicious — deeper verification recommended",
    "likely_substituted": "Likely substituted — trust score below threshold",
    "inconclusive": "Inconclusive — cannot judge from available evidence",
}


def render_markdown(v: Verdict) -> str:
    """Render a Verdict as a readable markdown report (agent-friendly)."""
    lines: list[str] = []

    # Header
    emoji = _VERDICT_EMOJI.get(v.verdict, "")
    headline = _VERDICT_HEADLINE.get(v.verdict, v.verdict)
    lines.append(f"## {emoji} Trust Score: **{v.trust_score:.2f}** — {headline}")
    lines.append("")
    lines.append(f"- **Endpoint**: `{v.endpoint_url}`")
    lines.append(f"- **Claimed model**: `{v.claimed_model}` (resolved to `{v.resolved_model_id}`)")
    lines.append(f"- **Confidence**: {v.confidence}")
    lines.append(
        f"- **Probes**: {v.num_probes_sent} sent"
        + (f", {v.num_probes_failed} failed" if v.num_probes_failed else "")
    )
    if v.duration_ms:
        lines.append(f"- **Duration**: {v.duration_ms / 1000:.1f}s")
    lines.append("")

    # Detector breakdown
    if v.detectors:
        lines.append("### Detectors")
        for name, d in v.detectors.items():
            status_marker = {"ok": "", "degraded": " (degraded)", "failed": " (failed)"}[d.status]
            lines.append(
                f"- **{name}**{status_marker}: score `{d.score:.2f}` (weight `{d.weight}`)"
            )
            # Surface a single most informative detail, if any
            for key in ("top_guess", "combined_p_value", "mean_p_value", "reason"):
                if key in d.details:
                    lines.append(f"  - {key}: `{d.details[key]}`")
                    break
        lines.append("")

    # Evidence
    if v.evidence:
        lines.append("### Evidence")
        for ev in v.evidence[:10]:  # cap to 10 to stay terse
            sev = {"info": "ℹ️", "warn": "⚠️", "alarm": "🚨"}.get(ev.severity, "")
            lines.append(f"- {sev} **{ev.probe_id}** ({ev.category}): {ev.observation}")
        if len(v.evidence) > 10:
            lines.append(f"- _...and {len(v.evidence) - 10} more_")
        lines.append("")

    # Versions + disclaimer footer
    lines.append("---")
    lines.append(
        f"_mcp v{v.mcp_version} · probe set `{v.probe_set_version}` · "
        f"fingerprint `{v.fingerprint_version}`_"
    )
    lines.append("")
    lines.append(f"> {v.disclaimer}")

    return "\n".join(lines)
