"""report.py tests."""

from __future__ import annotations

from api_key_scanner.report import render_markdown
from api_key_scanner.schemas import DetectorResult, Evidence, Verdict


def _basic_verdict(**overrides) -> Verdict:
    defaults = {
        "trust_score": 0.42,
        "verdict": "likely_substituted",
        "confidence": "medium",
        "claimed_model": "claude-opus-4",
        "resolved_model_id": "anthropic/claude-opus-4",
        "endpoint_url": "https://foo.com/v1",
        "probe_set_version": "v1",
        "fingerprint_version": "v2026.04.20",
        "mcp_version": "0.1.0",
        "num_probes_sent": 30,
        "num_probes_failed": 1,
        "duration_ms": 28500,
    }
    defaults.update(overrides)
    return Verdict(**defaults)


def test_report_contains_headline_and_score() -> None:
    v = _basic_verdict()
    md = render_markdown(v)
    assert "0.42" in md
    assert "likely_substituted".lower() in md.lower() or "Likely substituted" in md
    assert "claude-opus-4" in md
    assert "foo.com/v1" in md


def test_report_includes_detectors_when_present() -> None:
    v = _basic_verdict(
        detectors={
            "d1_llmmap": DetectorResult(
                name="d1_llmmap",
                score=0.0,
                weight=0.45,
                status="ok",
                details={"top_guess": "openai/gpt-4o"},
            ),
        }
    )
    md = render_markdown(v)
    assert "d1_llmmap" in md
    assert "openai/gpt-4o" in md


def test_report_includes_evidence() -> None:
    v = _basic_verdict(
        evidence=[
            Evidence(
                probe_id="llmmap-003",
                category="identification",
                observation="Self-ID says 'GPT' not 'Claude'",
                severity="alarm",
            )
        ]
    )
    md = render_markdown(v)
    assert "llmmap-003" in md
    assert "Self-ID" in md


def test_report_includes_disclaimer_footer() -> None:
    v = _basic_verdict()
    md = render_markdown(v)
    # Disclaimer is always present (default in Verdict)
    assert v.disclaimer.split(".")[0] in md  # first sentence
