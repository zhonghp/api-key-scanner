"""Smoke tests for the MCP server wiring.

These cover schema + env-var guard behavior. End-to-end orchestration
(probes + gateway + detectors + fusion) lives in tests/integration/.
"""

from __future__ import annotations

import os

import pytest

from api_key_scanner import __version__
from api_key_scanner.probes import load_probes
from api_key_scanner.schemas import Verdict
from api_key_scanner.server import _build_detector_probe_ids, verify_gateway


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


def test_dotenv_loader_uses_default_path_when_env_unset(
    monkeypatch: pytest.MonkeyPatch, tmp_path
) -> None:
    """When APIGUARD_DOTENV_PATH is unset, ~/.api-key-scanner/.env is loaded."""
    from api_key_scanner import server

    monkeypatch.delenv("APIGUARD_DOTENV_PATH", raising=False)
    monkeypatch.delenv("DEFAULT_DOTENV_TEST_KEY", raising=False)

    fake_home_env = tmp_path / ".env"
    fake_home_env.write_text("DEFAULT_DOTENV_TEST_KEY=from_default\n")
    monkeypatch.setattr(server, "_DEFAULT_DOTENV_PATH", fake_home_env)

    server._load_dotenv_if_requested()
    assert os.environ.get("DEFAULT_DOTENV_TEST_KEY") == "from_default"


def test_dotenv_loader_skips_default_when_missing(
    monkeypatch: pytest.MonkeyPatch, tmp_path
) -> None:
    """No env var AND no default file -> silent no-op, no error."""
    from api_key_scanner import server

    monkeypatch.delenv("APIGUARD_DOTENV_PATH", raising=False)
    monkeypatch.setattr(server, "_DEFAULT_DOTENV_PATH", tmp_path / "does-not-exist.env")
    server._load_dotenv_if_requested()  # must not raise


def test_detector_probe_ids_are_split_by_expected_detector() -> None:
    probes = load_probes("cheap")
    detector_probe_ids = _build_detector_probe_ids(probes)

    assert detector_probe_ids["d1_llmmap"]
    assert detector_probe_ids["d2_met"]
    assert detector_probe_ids["d1_llmmap"].isdisjoint(detector_probe_ids["d2_met"])


async def test_list_supported_models_returns_manifest_contents(
    monkeypatch: pytest.MonkeyPatch, tmp_path
) -> None:
    """With a manifest present, list_supported_models reports the models."""
    import json as _json

    from api_key_scanner import server
    from api_key_scanner.server import list_supported_models

    fp_dir = tmp_path / "fingerprints" / "fingerprint-2026-04-21"
    fp_dir.mkdir(parents=True)
    (fp_dir / "MANIFEST.json").write_text(
        _json.dumps(
            {
                "models": {
                    "openai/gpt-5.4": {"file": "openai/gpt-5.4.jsonl", "sha256": "x"},
                    "openai/gpt-5.4-mini": {"file": "openai/gpt-5.4-mini.jsonl", "sha256": "y"},
                }
            }
        )
    )
    monkeypatch.setenv("APIGUARD_FINGERPRINT_DIR", str(fp_dir))
    monkeypatch.setattr(server, "_RESOLVED_FINGERPRINT_DIR", None)
    monkeypatch.setenv("APIGUARD_FINGERPRINT_VERSION", "fingerprint-2026-04-21")

    result = await list_supported_models()
    assert result["status"] == "ok"
    assert result["fingerprint_tag"] == "fingerprint-2026-04-21"
    assert result["models"] == ["openai/gpt-5.4", "openai/gpt-5.4-mini"]


async def test_list_supported_models_unavailable_when_no_fingerprints(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    """No fetch possible and no explicit dir -> status=unavailable."""
    from api_key_scanner import fingerprint_fetch, server
    from api_key_scanner.server import list_supported_models

    monkeypatch.delenv("APIGUARD_FINGERPRINT_DIR", raising=False)
    monkeypatch.setattr(server, "_RESOLVED_FINGERPRINT_DIR", None)
    monkeypatch.setattr(server, "_LAST_FETCH_ERROR", None)

    async def _fail(**_kwargs: object) -> object:
        raise fingerprint_fetch.FingerprintFetchError("network", "simulated")

    monkeypatch.setattr(fingerprint_fetch, "ensure_fingerprints", _fail)

    result = await list_supported_models()
    assert result["status"] == "unavailable"
    assert result["models"] == []
    assert "network" in result["reason"]


def test_fingerprint_missing_error_lists_available_models(
    monkeypatch: pytest.MonkeyPatch, tmp_path
) -> None:
    """When claimed_model isn't covered, the error names what IS covered."""
    import json as _json

    from api_key_scanner import probes as probes_mod

    fp_dir = tmp_path / "fp"
    (fp_dir / "openai").mkdir(parents=True)
    # Write a minimal valid FingerprintEntry jsonl
    (fp_dir / "openai" / "gpt-5.4.jsonl").write_text(
        _json.dumps(
            {
                "probe_id": "llmmap-001",
                "sample_index": 0,
                "output": "hi",
                "output_tokens": 1,
                "response_ms": 100,
                "system_fingerprint": None,
                "finish_reason": "stop",
                "collected_at": "2026-04-21T00:00:00Z",
            }
        )
        + "\n"
    )

    with pytest.raises(probes_mod.FingerprintDataMissingError) as exc_info:
        probes_mod.load_fingerprints("openai/gpt-4o", fingerprint_dir=fp_dir)

    msg = str(exc_info.value)
    assert "openai/gpt-4o" in msg
    assert "openai/gpt-5.4" in msg
    assert "list_supported_models" in msg
