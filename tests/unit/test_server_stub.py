"""Smoke tests for the MCP server wiring.

These cover schema + env-var guard behavior. End-to-end orchestration
(probes + gateway + detectors + fusion) lives in tests/integration/.
"""

from __future__ import annotations

import os

import pytest

from api_key_scanner import __version__
from api_key_scanner.schemas import Verdict
from api_key_scanner.server import verify_gateway


@pytest.fixture(autouse=True)
def _clear_known_env(monkeypatch: pytest.MonkeyPatch) -> None:
    for var in ("MY_TEST_KEY", "APIGUARD_FINGERPRINT_DIR"):
        monkeypatch.delenv(var, raising=False)


def test_verdict_schema_roundtrip() -> None:
    v = Verdict(
        trust_score=0.5,
        verdict="suspicious",
        confidence="medium",
        claimed_model="claude-opus-4",
        resolved_model_id="anthropic/claude-opus-4",
        endpoint_url="https://example.com/v1",
        probe_set_version="v1",
        fingerprint_version="v2026.04.20",
        mcp_version=__version__,
    )
    dumped = v.model_dump()
    assert dumped["trust_score"] == 0.5
    assert dumped["verdict"] == "suspicious"
    Verdict.model_validate(dumped)


async def test_missing_env_var_returns_inconclusive() -> None:
    result = await verify_gateway(
        endpoint_url="https://example.com/v1",
        claimed_model="claude-opus-4",
        api_key_env_var="MY_TEST_KEY",  # explicitly not set (per fixture)
    )
    assert result["verdict"] == "inconclusive"
    assert "MY_TEST_KEY" in result["disclaimer"]
    assert "sk-" not in result["disclaimer"]  # sanity


async def test_verdict_has_stable_shape(monkeypatch: pytest.MonkeyPatch) -> None:
    """Even on the no-fingerprints-configured path, the Verdict shape is stable."""
    monkeypatch.setenv("MY_TEST_KEY", "sk-placeholder-not-a-real-key")
    # APIGUARD_FINGERPRINT_DIR intentionally unset -> inconclusive with guidance
    result = await verify_gateway(
        endpoint_url="https://example.com/v1",
        claimed_model="claude-opus-4",
        api_key_env_var="MY_TEST_KEY",
    )
    for key in (
        "trust_score",
        "verdict",
        "confidence",
        "claimed_model",
        "resolved_model_id",
        "endpoint_url",
        "detectors",
        "evidence",
        "probe_set_version",
        "fingerprint_version",
        "mcp_version",
        "num_probes_sent",
        "num_probes_failed",
        "cost_usd_estimate",
        "duration_ms",
        "disclaimer",
    ):
        assert key in result, f"Verdict missing stable field: {key}"

    assert result["verdict"] == "inconclusive"
    assert result["mcp_version"] == __version__
    assert "APIGUARD_FINGERPRINT_DIR" in result["disclaimer"]


async def test_verdict_never_leaks_key(monkeypatch: pytest.MonkeyPatch) -> None:
    """The raw key must not appear anywhere in the returned Verdict."""
    secret = "sk-live-super-secret-token-abcd1234"
    monkeypatch.setenv("MY_TEST_KEY", secret)
    result = await verify_gateway(
        endpoint_url="https://example.com/v1",
        claimed_model="claude-opus-4",
        api_key_env_var="MY_TEST_KEY",
    )
    import json

    assert secret not in json.dumps(result)


def test_dotenv_loader_noop_when_env_unset(monkeypatch: pytest.MonkeyPatch) -> None:
    """No APIGUARD_DOTENV_PATH set -> loader does nothing."""
    from api_key_scanner.server import _load_dotenv_if_requested

    monkeypatch.delenv("APIGUARD_DOTENV_PATH", raising=False)
    monkeypatch.delenv("SOME_LOADER_TEST_VAR", raising=False)
    _load_dotenv_if_requested()
    assert "SOME_LOADER_TEST_VAR" not in os.environ


def test_dotenv_loader_reads_explicit_path(monkeypatch: pytest.MonkeyPatch, tmp_path) -> None:
    """APIGUARD_DOTENV_PATH=<file> -> values from file populate os.environ."""
    from api_key_scanner.server import _load_dotenv_if_requested

    env_file = tmp_path / ".env"
    env_file.write_text("DOTENV_LOADER_TEST_FROM_FILE=hello\n")

    monkeypatch.setenv("APIGUARD_DOTENV_PATH", str(env_file))
    monkeypatch.delenv("DOTENV_LOADER_TEST_FROM_FILE", raising=False)
    _load_dotenv_if_requested()

    assert os.environ.get("DOTENV_LOADER_TEST_FROM_FILE") == "hello"


def test_dotenv_loader_does_not_override(monkeypatch: pytest.MonkeyPatch, tmp_path) -> None:
    """Shell env (including .mcp.json env) must win over .env."""
    from api_key_scanner.server import _load_dotenv_if_requested

    env_file = tmp_path / ".env"
    env_file.write_text("DOTENV_PRIORITY_TEST=from_file\n")

    monkeypatch.setenv("APIGUARD_DOTENV_PATH", str(env_file))
    monkeypatch.setenv("DOTENV_PRIORITY_TEST", "from_shell")
    _load_dotenv_if_requested()

    # Shell value preserved
    assert os.environ["DOTENV_PRIORITY_TEST"] == "from_shell"


def test_dotenv_loader_missing_file_warns_not_crash(
    monkeypatch: pytest.MonkeyPatch, tmp_path
) -> None:
    """If the pointed-to file doesn't exist, loader warns and continues."""
    from api_key_scanner.server import _load_dotenv_if_requested

    monkeypatch.setenv("APIGUARD_DOTENV_PATH", str(tmp_path / "does-not-exist.env"))
    # Should not raise
    _load_dotenv_if_requested()
