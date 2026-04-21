"""Pydantic data models shared across MCP tool, detectors, and report.

Single source of truth. Detectors consume ProbeResponse, produce
DetectorResult; fusion combines those into a Verdict.
"""

from __future__ import annotations

from typing import Any, Literal

from pydantic import BaseModel, Field

Budget = Literal["cheap", "standard", "deep"]
VerdictLabel = Literal["ok", "suspicious", "likely_substituted", "inconclusive"]
Confidence = Literal["high", "medium", "low"]
Severity = Literal["info", "warn", "alarm"]
ProbeCategory = Literal[
    "identification",
    "refusal",
    "knowledge",
    "creative",
    "reasoning",
    "metadata",
]


class ChatMessage(BaseModel):
    role: Literal["system", "user", "assistant"]
    content: str


class SampleParams(BaseModel):
    temperature: float = 0.0
    top_p: float = 1.0
    max_tokens: int = 256
    seed: int | None = None


class Probe(BaseModel):
    """One probe prompt. Sent num_samples times during verification."""

    probe_id: str
    category: ProbeCategory
    messages: list[ChatMessage]
    params: SampleParams = Field(default_factory=SampleParams)
    num_samples: int = 1
    expected_detectors: list[str] = Field(default_factory=list)


class ProbeResponse(BaseModel):
    """One sample response from the target gateway for a given probe."""

    probe_id: str
    sample_index: int
    output: str
    output_tokens: int | None = None
    response_ms: int | None = None
    ttft_ms: int | None = None
    system_fingerprint: str | None = None
    finish_reason: str | None = None
    error: str | None = None  # populated when this sample failed


class FingerprintEntry(BaseModel):
    """One sample in the reference fingerprint JSONL."""

    probe_id: str
    sample_index: int
    output: str
    output_tokens: int | None = None
    response_ms: int | None = None
    ttft_ms: int | None = None
    system_fingerprint: str | None = None
    finish_reason: str | None = None
    collected_at: str  # ISO 8601


class DetectorResult(BaseModel):
    """Output of a single detector."""

    name: str  # "d1_llmmap" | "d2_met" | "d4_metadata"
    score: float  # 0-1, lower = more suspicious
    weight: float  # bayesian fusion weight
    status: Literal["ok", "degraded", "failed"] = "ok"
    details: dict[str, Any] = Field(default_factory=dict)


class Evidence(BaseModel):
    """One human-readable observation backing the verdict."""

    probe_id: str
    category: ProbeCategory
    observation: str
    severity: Severity


class Verdict(BaseModel):
    """Final verdict returned by verify_gateway."""

    trust_score: float  # 0-1, >0.90 ok, 0.70-0.90 suspicious, <0.70 likely_substituted
    verdict: VerdictLabel
    confidence: Confidence

    claimed_model: str
    resolved_model_id: str
    endpoint_url: str

    detectors: dict[str, DetectorResult] = Field(default_factory=dict)
    evidence: list[Evidence] = Field(default_factory=list)

    probe_set_version: str
    fingerprint_version: str
    mcp_version: str

    num_probes_sent: int = 0
    num_probes_failed: int = 0
    duration_ms: int = 0

    disclaimer: str = (
        "This verdict is a statistical inference based on public signed "
        "fingerprints. It does not constitute legal proof. Phase 1 covers "
        "cross-family substitution (A1), system-prompt tampering (A5), and "
        "cached replay (A7). Same-family downgrades and adaptive routing "
        "are explicitly NOT covered in this phase."
    )


class ModelManifestEntry(BaseModel):
    file: str
    sha256: str
    num_probes: int
    num_samples: int
    provenance: dict[str, str]


class Manifest(BaseModel):
    """Structure of the MANIFEST.json inside a fingerprint release."""

    version: str
    probe_set_version: str
    collected_at: str
    collector_version: str
    models: dict[str, ModelManifestEntry]
    probes_snapshot: dict[str, str]  # filename -> sha256
