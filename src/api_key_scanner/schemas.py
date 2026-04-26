"""Pydantic data models shared across MCP tool, detectors, and report.

Single source of truth. Detectors consume ProbeResponse, produce
DetectorResult; fusion combines those into a Verdict.
"""

from __future__ import annotations

from typing import Any, Literal

from pydantic import BaseModel, ConfigDict, Field, field_validator

Budget = Literal["cheap", "standard"]
ApiFormat = Literal["openai", "anthropic", "gemini", "auto"]
AuthScheme = Literal["default", "bearer", "x-api-key", "x-goog-api-key"]
VerdictLabel = Literal["ok", "suspicious", "likely_substituted", "inconclusive"]
Confidence = Literal["high", "medium", "low"]
Severity = Literal["info", "warn", "alarm"]
ReferenceMode = Literal["vendor_direct", "internal_gateway", "unknown"]
PROTECTED_REQUEST_OVERRIDE_KEYS = frozenset(
    {"model", "messages", "stream", "temperature", "top_p", "max_tokens", "seed"}
)
OMITTABLE_REQUEST_PAYLOAD_FIELDS = frozenset({"temperature", "top_p", "max_tokens", "seed"})
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
    reasoning_tokens: int | None = None
    reasoning_content: str | None = None
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
    reasoning_tokens: int | None = None
    reasoning_content: str | None = None
    collected_at: str  # ISO 8601


class DetectorResult(BaseModel):
    """Output of a single detector."""

    name: str  # "d1_banner_match" | "d2_met" | "d4_metadata"
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


def validate_request_overrides_dict(overrides: dict[str, Any]) -> dict[str, Any]:
    for key in overrides:
        if key in PROTECTED_REQUEST_OVERRIDE_KEYS:
            raise ValueError(f"request_overrides cannot override protected payload field {key!r}")
    return overrides


def validate_request_omit_fields(fields: Any) -> list[str]:
    if not isinstance(fields, list):
        raise ValueError("request_omit_fields must be a list of strings")
    normalized: list[str] = []
    seen: set[str] = set()
    for field in fields:
        if not isinstance(field, str):
            raise ValueError("request_omit_fields must be a list of strings")
        if field not in OMITTABLE_REQUEST_PAYLOAD_FIELDS:
            allowed = ", ".join(sorted(OMITTABLE_REQUEST_PAYLOAD_FIELDS))
            raise ValueError(
                f"request_omit_fields contains unsupported field {field!r}; "
                f"allowed values: {allowed}"
            )
        if field not in seen:
            normalized.append(field)
            seen.add(field)
    return normalized


class ModelQualityMetadata(BaseModel):
    probe_set_version: str | None = None
    budget: Budget | None = None
    expected_num_probes: int | None = None
    expected_samples: int | None = None
    actual_samples: int | None = None
    missing_probe_ids: list[str] = Field(default_factory=list)
    incomplete_probe_ids: list[str] = Field(default_factory=list)
    per_probe_expected_samples: dict[str, int] = Field(default_factory=dict)
    per_probe_actual_samples: dict[str, int] = Field(default_factory=dict)
    metadata_anomalies: list[dict[str, Any]] = Field(default_factory=list)


class CollectedFingerprintSidecar(BaseModel):
    model_config = ConfigDict(extra="forbid")

    canonical_id: str
    # Backward-compatible with older sidecars; no longer propagated to MANIFEST.json.
    endpoint: str | None = None
    model_id: str
    budget: Budget
    probe_set_version: str
    reference_mode: ReferenceMode
    request_overrides: dict[str, Any] = Field(default_factory=dict)
    request_omit_fields: list[str] = Field(default_factory=list)
    api_format: ApiFormat = "openai"
    auth_scheme: AuthScheme = "default"
    verification_overrides_required: bool = False
    expected_num_probes: int
    expected_samples: int
    actual_samples: int
    missing_probe_ids: list[str] = Field(default_factory=list)
    incomplete_probe_ids: list[str] = Field(default_factory=list)
    per_probe_expected_samples: dict[str, int] = Field(default_factory=dict)
    per_probe_actual_samples: dict[str, int] = Field(default_factory=dict)
    metadata_anomalies: list[dict[str, Any]] = Field(default_factory=list)
    notes: str | None = None

    @field_validator("request_overrides")
    @classmethod
    def _validate_request_overrides(cls, value: dict[str, Any]) -> dict[str, Any]:
        return validate_request_overrides_dict(value)

    @field_validator("request_omit_fields")
    @classmethod
    def _validate_request_omit_fields(cls, value: list[str]) -> list[str]:
        return validate_request_omit_fields(value)


class ModelManifestEntry(BaseModel):
    file: str
    sha256: str
    size_bytes: int | None = None
    num_probes: int = 0
    num_samples: int
    provenance: dict[str, Any] = Field(default_factory=dict)
    quality: ModelQualityMetadata = Field(default_factory=ModelQualityMetadata)
    request_overrides: dict[str, Any] = Field(default_factory=dict)
    request_omit_fields: list[str] = Field(default_factory=list)
    api_format: ApiFormat = "openai"
    auth_scheme: AuthScheme = "default"
    verification_overrides_required: bool = False

    @field_validator("request_overrides")
    @classmethod
    def _validate_request_overrides(cls, value: dict[str, Any]) -> dict[str, Any]:
        return validate_request_overrides_dict(value)

    @field_validator("request_omit_fields")
    @classmethod
    def _validate_request_omit_fields(cls, value: list[str]) -> list[str]:
        return validate_request_omit_fields(value)


class Manifest(BaseModel):
    """Structure of the MANIFEST.json inside a fingerprint release."""

    version: str
    probe_set_version: str
    collected_at: str
    collector_version: str
    models: dict[str, ModelManifestEntry]
    probes_snapshot: dict[str, str] = Field(default_factory=dict)  # filename -> sha256
