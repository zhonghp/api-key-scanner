"""Batch data generation and offline evaluation helpers."""

from __future__ import annotations

import os
from dataclasses import dataclass
from datetime import datetime, timezone
from pathlib import Path

import yaml
from pydantic import BaseModel, Field

from api_key_scanner import __version__, aliases, evaluation
from api_key_scanner.aliases import UnknownModelError
from api_key_scanner.gateway import ClientConfig, OpenAICompatClient
from api_key_scanner.probes import PROBE_SET_VERSION, load_fingerprints, load_probes
from api_key_scanner.schemas import Budget, Probe, ProbeResponse, Verdict


@dataclass(frozen=True)
class BatchTarget:
    node_name: str
    endpoint_url: str
    key_env: str
    claimed_model: str
    resolved_model_id: str
    request_model: str
    budget: Budget
    extra_headers: dict[str, str] | None = None


class InferenceRunArtifact(BaseModel):
    """One saved batch-generation output record."""

    schema_version: int = 1
    generated_at: str
    node_name: str
    endpoint_url: str
    claimed_model: str
    resolved_model_id: str
    request_model: str
    budget: Budget
    probe_set_version: str
    mcp_version: str
    num_probes_sent: int
    num_probes_failed: int
    probes: list[Probe] = Field(default_factory=list)
    gateway_responses: list[ProbeResponse] = Field(default_factory=list)


def load_batch_targets(path: Path) -> list[BatchTarget]:
    """Load a cross-product of enabled nodes x enabled models."""
    with path.open("r", encoding="utf-8") as f:
        cfg = yaml.safe_load(f) or {}

    generation = cfg.get("generation", {}) or {}
    default_budget: Budget = generation.get("default_budget", "standard")
    nodes = [entry for entry in cfg.get("nodes", []) if entry.get("enabled", True)]
    models = [entry for entry in cfg.get("models", []) if entry.get("enabled", True)]

    targets: list[BatchTarget] = []
    for node in nodes:
        for model in models:
            claimed_model = model["claimed_model"]
            resolved_model = aliases.to_canonical(claimed_model)
            request_model = model.get("request_model", claimed_model)
            targets.append(
                BatchTarget(
                    node_name=node["name"],
                    endpoint_url=node["endpoint"],
                    key_env=node["key_env"],
                    claimed_model=claimed_model,
                    resolved_model_id=resolved_model,
                    request_model=request_model,
                    budget=model.get("budget", default_budget),
                    extra_headers=node.get("extra_headers"),
                )
            )
    return targets


def filter_batch_targets(
    targets: list[BatchTarget],
    *,
    only_nodes: set[str] | None = None,
    only_models: set[str] | None = None,
) -> list[BatchTarget]:
    """Filter batch targets by node/model selections."""
    out = targets
    if only_nodes:
        out = [target for target in out if target.node_name in only_nodes]
    if only_models:
        out = [target for target in out if target.claimed_model in only_models]
    return out


def artifact_filename(target: BatchTarget) -> str:
    """Default file name for one artifact."""
    stamp = _utc_now_compact()
    node = _safe_name(target.node_name)
    model = _safe_name(target.resolved_model_id.replace("/", "__"))
    return f"{stamp}__{node}__{model}.json"


def save_artifact(artifact: InferenceRunArtifact, path: Path) -> None:
    """Write one artifact JSON."""
    path.parent.mkdir(parents=True, exist_ok=True)
    path.write_text(artifact.model_dump_json(indent=2), encoding="utf-8")


def load_artifact(path: Path) -> InferenceRunArtifact:
    """Load one artifact JSON."""
    return InferenceRunArtifact.model_validate_json(path.read_text(encoding="utf-8"))


def collect_artifact_paths(inputs: list[Path]) -> list[Path]:
    """Expand files/directories into sorted artifact json paths."""
    paths: list[Path] = []
    for item in inputs:
        if item.is_dir():
            paths.extend(sorted(item.glob("*.json")))
        elif item.is_file():
            paths.append(item)
    return paths


async def collect_target_artifact(target: BatchTarget) -> InferenceRunArtifact:
    """Run one batch target and return its raw probe outputs."""
    api_key = os.environ.get(target.key_env)
    if not api_key:
        raise RuntimeError(f"environment variable '{target.key_env}' is not set")

    probes = load_probes(target.budget)
    client = OpenAICompatClient(
        ClientConfig(
            endpoint_url=target.endpoint_url,
            api_key=api_key,
            model=target.request_model,
            concurrency=3,
            max_retries=3,
            extra_headers=target.extra_headers,
        )
    )
    responses = await client.run_probes(probes)

    return InferenceRunArtifact(
        generated_at=_utc_now_iso(),
        node_name=target.node_name,
        endpoint_url=target.endpoint_url,
        claimed_model=target.claimed_model,
        resolved_model_id=target.resolved_model_id,
        request_model=target.request_model,
        budget=target.budget,
        probe_set_version=PROBE_SET_VERSION,
        mcp_version=__version__,
        num_probes_sent=len(responses),
        num_probes_failed=sum(1 for response in responses if response.error),
        probes=probes,
        gateway_responses=responses,
    )


def evaluate_artifact(
    artifact: InferenceRunArtifact,
    *,
    include_raw_responses: bool = False,
    fingerprint_dir: Path | str | None = None,
) -> Verdict:
    """Run the current evaluation logic over a saved artifact."""
    fingerprints = load_fingerprints(artifact.resolved_model_id, fingerprint_dir=fingerprint_dir)
    return evaluation.evaluate_responses(
        endpoint_url=artifact.endpoint_url,
        claimed_model=artifact.claimed_model,
        canonical_id=artifact.resolved_model_id,
        probe_list=artifact.probes,
        responses=artifact.gateway_responses,
        fingerprints=fingerprints,
        probe_set_version=artifact.probe_set_version,
        duration_ms=0,
        include_raw_responses=include_raw_responses,
    )


def validate_targets_against_aliases(targets: list[BatchTarget]) -> list[str]:
    """Return any canonical-id alignment errors."""
    errors: list[str] = []
    for target in targets:
        try:
            resolved = aliases.to_canonical(target.claimed_model)
        except UnknownModelError:
            errors.append(f"{target.claimed_model!r}: not in aliases.json")
            continue
        if resolved != target.resolved_model_id:
            errors.append(
                f"{target.claimed_model!r}: resolves to {resolved!r}, "
                f"but target stored {target.resolved_model_id!r}"
            )
    return errors


def _safe_name(text: str) -> str:
    return "".join(ch if ch.isalnum() or ch in ("-", "_", ".") else "_" for ch in text)


def _utc_now_iso() -> str:
    return datetime.now(timezone.utc).isoformat().replace("+00:00", "Z")


def _utc_now_compact() -> str:
    return datetime.now(timezone.utc).strftime("%Y%m%dT%H%M%SZ")
