"""gateway.py tests using respx for httpx mocking.

We never hit a real network. All tests verify behavior against controlled
mock responses, including retry logic, error handling, and the critical
privacy guardrail: the API key must not appear in any returned ProbeResponse
field.
"""

from __future__ import annotations

import httpx
import pytest
import respx

from api_key_scanner.gateway import ClientConfig, OpenAICompatClient
from api_key_scanner.schemas import ChatMessage, Probe, SampleParams


def _make_probe(probe_id: str = "t-1", num_samples: int = 1) -> Probe:
    return Probe(
        probe_id=probe_id,
        category="identification",
        messages=[ChatMessage(role="user", content="Hello?")],
        params=SampleParams(temperature=0.0, max_tokens=50),
        num_samples=num_samples,
    )


def _make_client(max_retries: int = 0) -> OpenAICompatClient:
    return OpenAICompatClient(
        ClientConfig(
            endpoint_url="https://fake.example.com/v1",
            api_key="sk-test-placeholder",
            model="test-model",
            concurrency=2,
            max_retries=max_retries,
        )
    )


@respx.mock
async def test_happy_path_returns_parsed_response() -> None:
    respx.post("https://fake.example.com/v1/chat/completions").respond(
        json={
            "choices": [{"message": {"content": "Hi!"}, "finish_reason": "stop"}],
            "usage": {
                "completion_tokens": 2,
                "prompt_tokens": 5,
                "total_tokens": 7,
                "completion_tokens_details": {"reasoning_tokens": 3},
            },
            "system_fingerprint": "fp_abc123",
        }
    )

    client = _make_client()
    results = await client.run_probes([_make_probe()])

    assert len(results) == 1
    r = results[0]
    assert r.output == "Hi!"
    assert r.output_tokens == 2
    assert r.finish_reason == "stop"
    assert r.system_fingerprint == "fp_abc123"
    assert r.reasoning_tokens == 3
    assert r.error is None
    assert r.response_ms is not None and r.response_ms >= 0
    assert r.ttft_ms is None  # Phase 1: no streaming


@respx.mock
async def test_num_samples_fans_out_requests() -> None:
    route = respx.post("https://fake.example.com/v1/chat/completions").respond(
        json={
            "choices": [{"message": {"content": "ok"}, "finish_reason": "stop"}],
            "usage": {"completion_tokens": 1, "prompt_tokens": 1, "total_tokens": 2},
        }
    )
    client = _make_client()
    results = await client.run_probes([_make_probe(num_samples=5)])
    assert len(results) == 5
    assert route.call_count == 5
    assert {r.sample_index for r in results} == {0, 1, 2, 3, 4}


@respx.mock
async def test_retries_on_429_then_succeeds() -> None:
    route = respx.post("https://fake.example.com/v1/chat/completions")
    route.side_effect = [
        httpx.Response(429, text="rate limited"),
        httpx.Response(
            200,
            json={
                "choices": [{"message": {"content": "ok"}, "finish_reason": "stop"}],
                "usage": {"completion_tokens": 1, "prompt_tokens": 1, "total_tokens": 2},
            },
        ),
    ]

    client = _make_client(max_retries=2)
    results = await client.run_probes([_make_probe()])

    assert len(results) == 1
    assert results[0].output == "ok"
    assert results[0].error is None
    assert route.call_count == 2


@respx.mock
async def test_non_retryable_4xx_becomes_error() -> None:
    respx.post("https://fake.example.com/v1/chat/completions").respond(
        401, text='{"error":"bad key"}'
    )
    client = _make_client(max_retries=2)
    results = await client.run_probes([_make_probe()])

    assert len(results) == 1
    assert results[0].output == ""
    assert results[0].error is not None
    assert "401" in results[0].error


@respx.mock
async def test_api_key_never_appears_in_response() -> None:
    """Critical privacy guardrail: the raw key must not leak via errors."""
    secret = "sk-live-very-secret-DO-NOT-LEAK"

    def handler(request: httpx.Request) -> httpx.Response:
        # Echo auth header in the error to simulate a chatty backend
        return httpx.Response(
            403, text=f"Forbidden: got header {request.headers.get('Authorization')}"
        )

    respx.post("https://fake.example.com/v1/chat/completions").mock(side_effect=handler)
    client = OpenAICompatClient(
        ClientConfig(
            endpoint_url="https://fake.example.com/v1",
            api_key=secret,
            model="test-model",
            max_retries=0,
        )
    )
    results = await client.run_probes([_make_probe()])

    assert len(results) == 1
    # The key value must not be in the returned error string,
    # even if the backend echoed the Authorization header back.
    # (Gateway client truncates and doesn't include the request body or
    # headers in the error message.)
    dumped = results[0].model_dump_json()
    assert secret not in dumped, "API key leaked into ProbeResponse!"


@respx.mock
async def test_empty_choices_flagged_as_error() -> None:
    respx.post("https://fake.example.com/v1/chat/completions").respond(
        json={"choices": [], "usage": {}}
    )
    client = _make_client()
    results = await client.run_probes([_make_probe()])

    assert results[0].output == ""
    assert results[0].error is not None
    assert "empty" in results[0].error.lower()


def test_insecure_ssl_env_var_flag(monkeypatch) -> None:
    """APIGUARD_INSECURE_SSL=1 flips verify off; default is True."""
    from api_key_scanner.gateway import _should_verify_ssl

    monkeypatch.delenv("APIGUARD_INSECURE_SSL", raising=False)
    assert _should_verify_ssl() is True

    for truthy in ("1", "true", "TRUE", "yes", "on"):
        monkeypatch.setenv("APIGUARD_INSECURE_SSL", truthy)
        assert _should_verify_ssl() is False, f"{truthy!r} should disable verify"

    for falsy in ("0", "false", "", "no", "off"):
        monkeypatch.setenv("APIGUARD_INSECURE_SSL", falsy)
        assert _should_verify_ssl() is True, f"{falsy!r} should leave verify on"


def test_completions_path_resolution() -> None:
    def path_for(base: str) -> str:
        c = OpenAICompatClient(ClientConfig(endpoint_url=base, api_key="x", model="m"))
        return c._completions_path

    assert path_for("https://api.openai.com/v1") == "https://api.openai.com/v1/chat/completions"
    assert path_for("https://api.openai.com/v1/") == "https://api.openai.com/v1/chat/completions"
    assert (
        path_for("https://gw.example.com/v1/chat/completions")
        == "https://gw.example.com/v1/chat/completions"
    )


def test_request_overrides_merge_nested_fields() -> None:
    client = OpenAICompatClient(
        ClientConfig(
            endpoint_url="https://fake.example.com/v1",
            api_key="sk-test-placeholder",
            model="test-model",
            request_overrides={
                "reasoning_effort": "minimal",
                "thinking_config": {"thinking_budget": 0},
            },
        )
    )
    payload = client._build_payload(_make_probe())
    assert payload["reasoning_effort"] == "minimal"
    assert payload["thinking_config"] == {"thinking_budget": 0}
    assert payload["model"] == "test-model"


def test_request_overrides_can_switch_to_max_completion_tokens() -> None:
    client = OpenAICompatClient(
        ClientConfig(
            endpoint_url="https://fake.example.com/v1",
            api_key="sk-test-placeholder",
            model="test-model",
            request_overrides={"max_completion_tokens": 2048},
        )
    )
    payload = client._build_payload(_make_probe())
    assert "max_tokens" not in payload
    assert payload["max_completion_tokens"] == 2048


def test_request_omit_fields_remove_configured_defaults() -> None:
    client = OpenAICompatClient(
        ClientConfig(
            endpoint_url="https://fake.example.com/v1",
            api_key="sk-test-placeholder",
            model="test-model",
            request_omit_fields=["temperature", "seed"],
        )
    )
    probe = Probe(
        probe_id="t-omit",
        category="identification",
        messages=[ChatMessage(role="user", content="Hello?")],
        params=SampleParams(temperature=0.0, max_tokens=50, seed=1234),
        num_samples=1,
    )
    payload = client._build_payload(probe)
    assert "temperature" not in payload
    assert "seed" not in payload
    assert payload["top_p"] == 1.0
    assert payload["max_tokens"] == 50


@pytest.mark.parametrize(
    ("override_key", "override_value"),
    [
        ("model", "other-model"),
        ("temperature", 0.7),
        ("top_p", 0.5),
        ("max_tokens", 10),
        ("seed", 1234),
    ],
)
def test_request_overrides_cannot_override_protected_fields(
    override_key: str, override_value: object
) -> None:
    with pytest.raises(ValueError, match="protected payload field"):
        OpenAICompatClient(
            ClientConfig(
                endpoint_url="https://fake.example.com/v1",
                api_key="sk-test-placeholder",
                model="test-model",
                request_overrides={override_key: override_value},
            )
        )


def test_request_omit_fields_reject_unsupported_field() -> None:
    with pytest.raises(ValueError, match="unsupported field 'messages'"):
        OpenAICompatClient(
            ClientConfig(
                endpoint_url="https://fake.example.com/v1",
                api_key="sk-test-placeholder",
                model="test-model",
                request_omit_fields=["messages"],
            )
        )
