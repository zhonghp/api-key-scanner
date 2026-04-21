"""End-to-end integration tests for verify_gateway.

Full pipeline with:
  - bundled probe set (`cheap` budget for speed)
  - fixture fingerprint directory written to a tmp_path
  - respx-mocked gateway replying with model-characteristic strings

Two scenarios:
  1. Gateway returns Opus-style replies, claims opus -> trust_score high
  2. Gateway returns GPT-style replies, still claims opus -> trust_score low
"""

from __future__ import annotations

import json
from pathlib import Path

import httpx
import pytest
import respx

from api_key_scanner import fingerprint_fetch, server
from api_key_scanner.server import verify_gateway

pytestmark = pytest.mark.integration

_CLAUDE_RESPONSES = [
    "I'm Claude, an AI assistant made by Anthropic.",
    "I am Claude, a helpful AI assistant created by Anthropic.",
    "Hello! I'm Claude, built by Anthropic to be helpful, harmless, and honest.",
    "I'm Claude, an AI assistant from Anthropic. I'm happy to help.",
    "I am Claude, Anthropic's AI assistant. How can I assist you today?",
    "I am Claude by Anthropic. Happy to help with whatever you need.",
    "I'm Claude. Anthropic made me to be a helpful AI assistant.",
    "Hi, I'm Claude, an AI made by Anthropic. What can I do for you?",
]

_GPT_RESPONSES = [
    "I'm ChatGPT, a large language model developed by OpenAI.",
    "I am ChatGPT, an AI language model created by OpenAI to help answer questions.",
    "Hi there! I'm ChatGPT, an assistant made by OpenAI.",
    "I am ChatGPT, a language model trained by OpenAI.",
    "Hello! I'm ChatGPT, developed by OpenAI to help you.",
    "I'm ChatGPT by OpenAI. How can I assist you?",
    "I'm ChatGPT, an OpenAI language model.",
    "Hi, I'm ChatGPT, an AI model from OpenAI.",
]


def _write_fingerprint_file(path: Path, probe_responses: dict[str, list[str]]) -> None:
    """Write a fingerprint JSONL file given probe_id -> list of outputs."""
    path.parent.mkdir(parents=True, exist_ok=True)
    with path.open("w") as f:
        for probe_id, outputs in probe_responses.items():
            for i, out in enumerate(outputs):
                entry = {
                    "probe_id": probe_id,
                    "sample_index": i,
                    "output": out,
                    "output_tokens": len(out.split()),
                    "response_ms": 400 + (i * 20),
                    "system_fingerprint": None,
                    "finish_reason": "stop",
                    "collected_at": "2026-04-20T08:00:00Z",
                }
                f.write(json.dumps(entry) + "\n")


def _make_fingerprint_dir(tmp_path: Path) -> Path:
    """Create a minimal fingerprint directory covering Opus + GPT-4o.

    Each model file has 8 Opus-style or GPT-style samples for each of the
    ids the `cheap` budget will actually query.
    """
    fp_dir = tmp_path / "fingerprints"

    # cheap budget: 3 llmmap probes + 1 met probe
    probes_for_cheap = ["llmmap-001", "llmmap-002", "llmmap-003", "met-001"]

    claude_samples = {pid: list(_CLAUDE_RESPONSES) for pid in probes_for_cheap}
    gpt_samples = {pid: list(_GPT_RESPONSES) for pid in probes_for_cheap}

    _write_fingerprint_file(fp_dir / "anthropic" / "claude-opus-4.jsonl", claude_samples)
    _write_fingerprint_file(fp_dir / "openai" / "gpt-4o.jsonl", gpt_samples)

    return fp_dir


def _mock_gateway_response(content: str) -> dict:
    return {
        "choices": [{"message": {"content": content}, "finish_reason": "stop"}],
        "usage": {"completion_tokens": 20, "prompt_tokens": 50, "total_tokens": 70},
        "system_fingerprint": None,
    }


@respx.mock
async def test_honest_gateway_scores_high(tmp_path: Path, monkeypatch: pytest.MonkeyPatch) -> None:
    """Gateway replies like Claude, claims Claude -> high trust."""
    fp_dir = _make_fingerprint_dir(tmp_path)
    monkeypatch.setenv("APIGUARD_FINGERPRINT_DIR", str(fp_dir))
    monkeypatch.setenv("MY_KEY", "sk-test-placeholder")

    # Round-robin through Claude responses
    idx = [0]

    def handler(_request: httpx.Request) -> httpx.Response:
        content = _CLAUDE_RESPONSES[idx[0] % len(_CLAUDE_RESPONSES)]
        idx[0] += 1
        return httpx.Response(200, json=_mock_gateway_response(content))

    respx.post("https://fake.example.com/v1/chat/completions").mock(side_effect=handler)

    result = await verify_gateway(
        endpoint_url="https://fake.example.com/v1",
        claimed_model="claude-opus-4",
        api_key_env_var="MY_KEY",
        budget="cheap",
    )

    assert result["verdict"] in ("ok", "suspicious"), (
        f"Expected honest gateway to pass but got {result['verdict']} "
        f"(trust={result['trust_score']}, detectors={result['detectors']})"
    )
    assert result["trust_score"] >= 0.7
    assert result["resolved_model_id"] == "anthropic/claude-opus-4"
    assert result["num_probes_failed"] == 0


@respx.mock
async def test_substituted_gateway_scores_low(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    """Gateway replies like GPT but claims Claude -> low trust, likely_substituted."""
    fp_dir = _make_fingerprint_dir(tmp_path)
    monkeypatch.setenv("APIGUARD_FINGERPRINT_DIR", str(fp_dir))
    monkeypatch.setenv("MY_KEY", "sk-test-placeholder")

    idx = [0]

    def handler(_request: httpx.Request) -> httpx.Response:
        content = _GPT_RESPONSES[idx[0] % len(_GPT_RESPONSES)]
        idx[0] += 1
        return httpx.Response(200, json=_mock_gateway_response(content))

    respx.post("https://fake.example.com/v1/chat/completions").mock(side_effect=handler)

    result = await verify_gateway(
        endpoint_url="https://fake.example.com/v1",
        claimed_model="claude-opus-4",
        api_key_env_var="MY_KEY",
        budget="cheap",
    )

    assert result["verdict"] in ("likely_substituted", "suspicious"), (
        f"Expected substituted gateway to be flagged but got {result['verdict']} "
        f"(trust={result['trust_score']})"
    )
    assert result["trust_score"] < 0.75
    # D1 should name the true model
    d1 = result["detectors"]["d1_llmmap"]
    assert d1["details"].get("top_guess") == "openai/gpt-4o"
    # Evidence should include an alarm item
    alarms = [e for e in result["evidence"] if e["severity"] == "alarm"]
    assert len(alarms) >= 1


@respx.mock
async def test_gateway_network_error_is_inconclusive(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    fp_dir = _make_fingerprint_dir(tmp_path)
    monkeypatch.setenv("APIGUARD_FINGERPRINT_DIR", str(fp_dir))
    monkeypatch.setenv("MY_KEY", "sk-test-placeholder")

    respx.post("https://fake.example.com/v1/chat/completions").mock(
        side_effect=httpx.ConnectError("connection refused")
    )

    result = await verify_gateway(
        endpoint_url="https://fake.example.com/v1",
        claimed_model="claude-opus-4",
        api_key_env_var="MY_KEY",
        budget="cheap",
    )
    # All probes fail -> detectors can't score -> inconclusive
    assert result["verdict"] in ("inconclusive", "likely_substituted")


@respx.mock
async def test_autofetch_supplies_fingerprint_dir_when_env_unset(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    """verify_gateway without APIGUARD_FINGERPRINT_DIR should auto-fetch."""
    fp_dir = _make_fingerprint_dir(tmp_path)
    # Unset explicit override and clear the process-level cache
    monkeypatch.delenv("APIGUARD_FINGERPRINT_DIR", raising=False)
    monkeypatch.setattr(server, "_RESOLVED_FINGERPRINT_DIR", None)
    monkeypatch.setenv("MY_KEY", "sk-test-placeholder")

    fake_tag = "fingerprint-2026-04-21-signed"

    async def fake_ensure(**_kwargs: object) -> fingerprint_fetch.FetchResult:
        return fingerprint_fetch.FetchResult(path=fp_dir, tag=fake_tag, from_cache=False)

    monkeypatch.setattr(fingerprint_fetch, "ensure_fingerprints", fake_ensure)

    idx = [0]

    def handler(_request: httpx.Request) -> httpx.Response:
        content = _CLAUDE_RESPONSES[idx[0] % len(_CLAUDE_RESPONSES)]
        idx[0] += 1
        return httpx.Response(200, json=_mock_gateway_response(content))

    respx.post("https://fake.example.com/v1/chat/completions").mock(side_effect=handler)

    result = await verify_gateway(
        endpoint_url="https://fake.example.com/v1",
        claimed_model="claude-opus-4",
        api_key_env_var="MY_KEY",
        budget="cheap",
    )

    assert result["verdict"] in ("ok", "suspicious")
    assert result["fingerprint_version"] == fake_tag, (
        f"Expected Verdict to carry the auto-fetched tag, got {result.get('fingerprint_version')!r}"
    )
