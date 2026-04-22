"""batch_eval.py tests."""

from __future__ import annotations

import json

from api_key_scanner import batch_eval
from api_key_scanner.schemas import ChatMessage, Probe, ProbeResponse, SampleParams


def test_load_batch_targets_builds_node_model_cross_product(tmp_path) -> None:
    cfg = tmp_path / "batch.yaml"
    cfg.write_text(
        """
generation:
  default_budget: cheap
nodes:
  - name: node-a
    endpoint: https://node-a.example.com/v1
    key_env: NODE_A_KEY
    enabled: true
  - name: node-b
    endpoint: https://node-b.example.com/v1
    key_env: NODE_B_KEY
    enabled: true
models:
  - claimed_model: gpt-5.4
    request_model: gpt-5.4
    enabled: true
  - claimed_model: gpt-5.4-mini
    enabled: true
"""
    )

    targets = batch_eval.load_batch_targets(cfg)
    assert len(targets) == 4
    assert {target.node_name for target in targets} == {"node-a", "node-b"}
    assert {target.claimed_model for target in targets} == {"gpt-5.4", "gpt-5.4-mini"}
    assert all(target.budget == "cheap" for target in targets)


def test_filter_batch_targets_applies_node_and_model_filters() -> None:
    targets = [
        batch_eval.BatchTarget(
            node_name="node-a",
            endpoint_url="https://a.example.com/v1",
            key_env="A_KEY",
            claimed_model="gpt-5.4",
            resolved_model_id="openai/gpt-5.4",
            request_model="gpt-5.4",
            budget="cheap",
        ),
        batch_eval.BatchTarget(
            node_name="node-b",
            endpoint_url="https://b.example.com/v1",
            key_env="B_KEY",
            claimed_model="gpt-5.4-mini",
            resolved_model_id="openai/gpt-5.4-mini",
            request_model="gpt-5.4-mini",
            budget="cheap",
        ),
    ]

    filtered = batch_eval.filter_batch_targets(
        targets,
        only_nodes={"node-a"},
        only_models={"gpt-5.4"},
    )
    assert [target.node_name for target in filtered] == ["node-a"]


def test_artifact_roundtrip_and_evaluation(tmp_path, monkeypatch) -> None:
    probes = [
        Probe(
            probe_id="llmmap-test-001",
            category="identification",
            messages=[ChatMessage(role="user", content="who are you")],
            params=SampleParams(),
            num_samples=1,
            expected_detectors=["d1"],
        ),
        Probe(
            probe_id="met-test-001",
            category="creative",
            messages=[ChatMessage(role="user", content="write a poem")],
            params=SampleParams(temperature=0.7),
            num_samples=3,
            expected_detectors=["d2"],
        ),
    ]
    responses = [
        ProbeResponse(
            probe_id="llmmap-test-001",
            sample_index=0,
            output="llmmap-test-001 output 0",
            output_tokens=4,
            response_ms=110,
        ),
        *[
            ProbeResponse(
                probe_id="met-test-001",
                sample_index=i,
                output=f"met-test-001 output {i}",
                prompt_tokens=10,
                output_tokens=4,
                total_tokens=14,
                response_ms=120 + i,
            )
            for i in range(3)
        ],
    ]
    artifact = batch_eval.InferenceRunArtifact(
        generated_at="2026-04-22T00:00:00Z",
        node_name="node-a",
        endpoint_url="https://node-a.example.com/v1",
        claimed_model="gpt-5.4",
        resolved_model_id="openai/gpt-5.4",
        request_model="gpt-5.4",
        budget="cheap",
        probe_set_version="v1",
        mcp_version="0.1.4",
        num_probes_sent=len(responses),
        num_probes_failed=0,
        probes=probes,
        gateway_responses=responses,
    )
    path = tmp_path / "artifact.json"
    batch_eval.save_artifact(artifact, path)

    fp_dir = tmp_path / "fp" / "openai"
    fp_dir.mkdir(parents=True)
    fp_lines = []
    for response in responses:
        fp_lines.append(
            json.dumps(
                {
                    "probe_id": response.probe_id,
                    "sample_index": response.sample_index,
                    "output": response.output,
                    "prompt_tokens": response.prompt_tokens,
                    "output_tokens": response.output_tokens,
                    "total_tokens": response.total_tokens,
                    "response_ms": response.response_ms,
                    "finish_reason": "stop",
                    "collected_at": "2026-04-22T00:00:00Z",
                }
            )
        )
    (fp_dir / "gpt-5.4.jsonl").write_text("\n".join(fp_lines) + "\n", encoding="utf-8")
    monkeypatch.setenv("APIGUARD_FINGERPRINT_VERSION", "fingerprint-2026-04-21-signed")

    loaded = batch_eval.load_artifact(path)
    verdict = batch_eval.evaluate_artifact(loaded, fingerprint_dir=tmp_path / "fp")

    assert loaded.node_name == "node-a"
    assert verdict.verdict == "ok"
    assert verdict.num_probes_sent == len(responses)
