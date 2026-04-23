"""Unit tests for scripts/ (collect_all / generate_manifest / validate_fingerprints).

We cannot hit real APIs in unit tests, so we:
  - exercise argparse / config-loading logic directly
  - test manifest and validator roundtrips with hand-written fixtures
"""

from __future__ import annotations

import json
import os
import subprocess
import sys
from pathlib import Path

import pytest

from api_key_scanner import probes as probes_mod

_REPO_ROOT = Path(__file__).resolve().parents[2]
_SCRIPTS = _REPO_ROOT / "scripts"


def _run_script(script: str, *args: str) -> subprocess.CompletedProcess:
    """Run a script via python to capture stdout/stderr + exit code."""
    env = dict(os.environ)
    src = str(_REPO_ROOT / "src")
    env["PYTHONPATH"] = src if not env.get("PYTHONPATH") else src + os.pathsep + env["PYTHONPATH"]
    return subprocess.run(
        [sys.executable, str(_SCRIPTS / script), *args],
        capture_output=True,
        text=True,
        cwd=_REPO_ROOT,
        env=env,
    )


def _write_fp(path: Path, probe_id: str = "llmmap-v2-01", n: int = 1) -> None:
    """Write a minimal valid fingerprint JSONL file."""
    path.parent.mkdir(parents=True, exist_ok=True)
    with path.open("w", encoding="utf-8") as f:
        for i in range(n):
            f.write(
                json.dumps(
                    {
                        "probe_id": probe_id,
                        "sample_index": i,
                        "output": f"sample {i} of {probe_id}",
                        "output_tokens": 5,
                        "response_ms": 400 + i,
                        "ttft_ms": None,
                        "system_fingerprint": None,
                        "finish_reason": "stop",
                        "collected_at": "2026-04-21T00:00:00Z",
                    }
                )
                + "\n"
            )


def _write_sidecar(path: Path, **overrides: object) -> None:
    base = {
        "canonical_id": "openai/gpt-4o",
        "model_id": "gpt-4o",
        "budget": "cheap",
        "probe_set_version": "v2",
        "reference_mode": "vendor_direct",
        "request_overrides": {},
        "request_omit_fields": [],
        "verification_overrides_required": False,
        "expected_num_probes": 1,
        "expected_samples": 1,
        "actual_samples": 1,
        "missing_probe_ids": [],
        "incomplete_probe_ids": [],
        "per_probe_expected_samples": {"llmmap-v2-01": 1},
        "per_probe_actual_samples": {"llmmap-v2-01": 1},
        "metadata_anomalies": [],
    }
    base.update(overrides)
    path.with_suffix(".meta.json").write_text(json.dumps(base), encoding="utf-8")


# ---- generate_manifest ----------------------------------------------------


def test_generate_manifest_produces_valid_json(tmp_path: Path) -> None:
    fp_dir = tmp_path / "fp"
    _write_fp(fp_dir / "openai" / "gpt-4o.jsonl")
    _write_sidecar(fp_dir / "openai" / "gpt-4o.jsonl")

    result = _run_script("generate_manifest.py", str(fp_dir))
    assert result.returncode == 0, result.stderr

    manifest = json.loads((fp_dir / "MANIFEST.json").read_text())
    assert "version" in manifest
    assert "models" in manifest
    assert "openai/gpt-4o" in manifest["models"]
    entry = manifest["models"]["openai/gpt-4o"]
    assert entry["file"] == "openai/gpt-4o.jsonl"
    assert len(entry["sha256"]) == 64
    assert entry["num_samples"] == 1
    assert entry["num_probes"] == 1
    assert entry["quality"]["expected_samples"] == 1
    assert entry["provenance"]["reference_mode"] == "vendor_direct"
    assert "endpoint" not in entry["provenance"]
    assert entry["request_omit_fields"] == []
    assert manifest["probes_snapshot"] == probes_mod.bundled_probes_snapshot("v2")


def test_generate_manifest_skips_orphan_models(tmp_path: Path) -> None:
    """A canonical id not in aliases.json must not land in the manifest."""
    fp_dir = tmp_path / "fp"
    _write_fp(fp_dir / "openai" / "gpt-4o.jsonl")
    _write_sidecar(fp_dir / "openai" / "gpt-4o.jsonl")
    _write_fp(fp_dir / "unknownvendor" / "totally-fake.jsonl")

    result = _run_script("generate_manifest.py", str(fp_dir))
    assert result.returncode == 0
    assert "totally-fake" in result.stderr

    manifest = json.loads((fp_dir / "MANIFEST.json").read_text())
    assert "openai/gpt-4o" in manifest["models"]
    assert "unknownvendor/totally-fake" not in manifest["models"]


def test_generate_manifest_require_models_gate(tmp_path: Path) -> None:
    """--require-models exits non-zero when fewer models found than requested."""
    fp_dir = tmp_path / "fp"
    _write_fp(fp_dir / "openai" / "gpt-4o.jsonl")
    _write_sidecar(fp_dir / "openai" / "gpt-4o.jsonl")

    result = _run_script("generate_manifest.py", str(fp_dir), "--require-models", "5")
    assert result.returncode == 1
    assert "found 1 models but --require-models=5" in result.stderr


def test_generate_manifest_rejects_invalid_sidecar(tmp_path: Path) -> None:
    fp_dir = tmp_path / "fp"
    jsonl = fp_dir / "openai" / "gpt-4o.jsonl"
    _write_fp(jsonl)
    _write_sidecar(jsonl, expected_samples="oops")

    result = _run_script("generate_manifest.py", str(fp_dir))
    assert result.returncode == 2
    assert "sidecar schema validation" in result.stderr


def test_generate_manifest_ignores_legacy_sidecar_endpoint(tmp_path: Path) -> None:
    fp_dir = tmp_path / "fp"
    jsonl = fp_dir / "openai" / "gpt-4o.jsonl"
    _write_fp(jsonl)
    _write_sidecar(jsonl, endpoint="https://legacy.example.com/v1")

    result = _run_script("generate_manifest.py", str(fp_dir))
    assert result.returncode == 0, result.stderr

    manifest = json.loads((fp_dir / "MANIFEST.json").read_text(encoding="utf-8"))
    provenance = manifest["models"]["openai/gpt-4o"]["provenance"]
    assert provenance["model_id"] == "gpt-4o"
    assert "endpoint" not in provenance


# ---- validate_fingerprints -----------------------------------------------


def test_validate_happy_path(tmp_path: Path) -> None:
    fp_dir = tmp_path / "fp"
    _write_fp(fp_dir / "openai" / "gpt-4o.jsonl", n=3)
    _write_sidecar(
        fp_dir / "openai" / "gpt-4o.jsonl",
        expected_samples=3,
        actual_samples=3,
        per_probe_expected_samples={"llmmap-v2-01": 3},
        per_probe_actual_samples={"llmmap-v2-01": 3},
    )

    assert _run_script("generate_manifest.py", str(fp_dir)).returncode == 0
    result = _run_script("validate_fingerprints.py", str(fp_dir))
    assert result.returncode == 0, result.stderr
    assert "schema: ok" in result.stderr
    assert "alignment: ok" in result.stderr
    assert "manifest: ok" in result.stderr


def test_validate_catches_sha_mismatch(tmp_path: Path) -> None:
    fp_dir = tmp_path / "fp"
    jsonl = fp_dir / "openai" / "gpt-4o.jsonl"
    _write_fp(jsonl)
    _write_sidecar(jsonl)

    assert _run_script("generate_manifest.py", str(fp_dir)).returncode == 0
    with jsonl.open("a", encoding="utf-8") as f:
        f.write(
            json.dumps(
                {
                    "probe_id": "llmmap-v2-01",
                    "sample_index": 99,
                    "output": "TAMPERED",
                    "output_tokens": 1,
                    "response_ms": 1,
                    "finish_reason": "stop",
                    "collected_at": "2026-04-21T00:00:00Z",
                }
            )
            + "\n"
        )

    result = _run_script("validate_fingerprints.py", str(fp_dir))
    assert result.returncode == 1
    assert "sha256 mismatch" in result.stderr


def test_validate_catches_orphan_file(tmp_path: Path) -> None:
    fp_dir = tmp_path / "fp"
    _write_fp(fp_dir / "unknownvendor" / "totally-fake.jsonl")

    result = _run_script("validate_fingerprints.py", str(fp_dir), "--skip-manifest")
    assert result.returncode == 1
    assert "not in aliases.json" in result.stderr


def test_validate_catches_schema_error(tmp_path: Path) -> None:
    fp_dir = tmp_path / "fp"
    bad = fp_dir / "openai" / "gpt-4o.jsonl"
    bad.parent.mkdir(parents=True)
    bad.write_text('{"probe_id":"x","this is not valid json at all\n', encoding="utf-8")

    result = _run_script("validate_fingerprints.py", str(fp_dir), "--skip-manifest")
    assert result.returncode == 1
    assert "schema FAILED" in result.stderr


def test_validate_require_complete_catches_missing_samples(tmp_path: Path) -> None:
    fp_dir = tmp_path / "fp"
    jsonl = fp_dir / "openai" / "gpt-4o.jsonl"
    _write_fp(jsonl, n=1)
    _write_sidecar(
        jsonl,
        expected_samples=2,
        actual_samples=1,
        per_probe_expected_samples={"llmmap-v2-01": 2},
        per_probe_actual_samples={"llmmap-v2-01": 1},
        incomplete_probe_ids=["llmmap-v2-01"],
    )

    assert _run_script("generate_manifest.py", str(fp_dir)).returncode == 0
    result = _run_script("validate_fingerprints.py", str(fp_dir), "--require-complete")
    assert result.returncode == 1
    assert "incomplete fingerprint" in result.stderr


def test_validate_require_clean_metadata_catches_anomaly(tmp_path: Path) -> None:
    fp_dir = tmp_path / "fp"
    jsonl = fp_dir / "openai" / "gpt-4o.jsonl"
    _write_fp(jsonl)
    _write_sidecar(
        jsonl,
        metadata_anomalies=[
            {
                "kind": "output_tokens_exceeds_max_tokens",
                "probe_id": "llmmap-v2-01",
                "sample_index": 0,
            }
        ],
    )

    assert _run_script("generate_manifest.py", str(fp_dir)).returncode == 0
    result = _run_script(
        "validate_fingerprints.py",
        str(fp_dir),
        "--require-clean-metadata",
    )
    assert result.returncode == 1
    assert "metadata anomalies present" in result.stderr


def test_validate_require_clean_metadata_catches_reasoning_tokens(tmp_path: Path) -> None:
    fp_dir = tmp_path / "fp"
    jsonl = fp_dir / "openai" / "gpt-4o.jsonl"
    _write_fp(jsonl)
    _write_sidecar(
        jsonl,
        metadata_anomalies=[
            {
                "kind": "reasoning_tokens_present",
                "probe_id": "llmmap-v2-01",
                "sample_index": 0,
                "reasoning_tokens": 8,
            }
        ],
    )

    assert _run_script("generate_manifest.py", str(fp_dir)).returncode == 0
    result = _run_script(
        "validate_fingerprints.py",
        str(fp_dir),
        "--require-clean-metadata",
    )
    assert result.returncode == 1
    assert "metadata anomalies present" in result.stderr


# ---- collect_all (arg handling only; API calls mocked elsewhere) ---------


def test_collect_all_rejects_unknown_canonical_id(tmp_path: Path) -> None:
    cfg = tmp_path / "models.yaml"
    cfg.write_text(
        """
collection:
  default_budget: cheap
models:
  - canonical_id: bogus/does-not-exist
    endpoint: https://example.com/v1
    model_id: bogus
    key_env: OPENAI_API_KEY
    enabled: true
""",
        encoding="utf-8",
    )
    out_dir = tmp_path / "out"
    result = _run_script(
        "collect_all.py",
        "--config",
        str(cfg),
        "--out",
        str(out_dir),
        "--env-file",
        "/dev/null",
    )
    assert result.returncode == 2, result.stderr
    assert "bogus/does-not-exist" in result.stderr
    assert "not in aliases.json" in result.stderr


def test_collect_all_no_enabled_targets(tmp_path: Path) -> None:
    cfg = tmp_path / "models.yaml"
    cfg.write_text(
        """
collection:
  probe_set_version: v2
  default_budget: cheap
models: []
""",
        encoding="utf-8",
    )
    result = _run_script(
        "collect_all.py",
        "--config",
        str(cfg),
        "--out",
        str(tmp_path / "out"),
        "--env-file",
        "/dev/null",
    )
    assert result.returncode == 0
    assert "no enabled targets" in result.stderr


def test_collect_all_rejects_probe_set_mismatch(tmp_path: Path) -> None:
    cfg = tmp_path / "models.yaml"
    cfg.write_text(
        """
collection:
  probe_set_version: v1
  default_budget: cheap
models: []
""",
        encoding="utf-8",
    )
    result = _run_script(
        "collect_all.py",
        "--config",
        str(cfg),
        "--out",
        str(tmp_path / "out"),
        "--env-file",
        "/dev/null",
    )
    assert result.returncode == 2
    assert "probe_set_version mismatch" in result.stderr


def test_collect_all_missing_config_file(tmp_path: Path) -> None:
    result = _run_script(
        "collect_all.py",
        "--config",
        str(tmp_path / "does-not-exist.yaml"),
        "--out",
        str(tmp_path / "out"),
        "--env-file",
        "/dev/null",
    )
    assert result.returncode == 2
    assert "not found" in result.stderr


def test_collect_all_rejects_protected_request_override(tmp_path: Path) -> None:
    cfg = tmp_path / "models.yaml"
    cfg.write_text(
        """
collection:
  probe_set_version: v2
  default_budget: cheap
models:
  - canonical_id: openai/gpt-4o
    endpoint: https://example.com/v1
    model_id: gpt-4o
    key_env: OPENAI_API_KEY
    request_overrides:
      temperature: 0.7
""",
        encoding="utf-8",
    )
    result = _run_script(
        "collect_all.py",
        "--config",
        str(cfg),
        "--out",
        str(tmp_path / "out"),
        "--env-file",
        "/dev/null",
    )
    assert result.returncode == 2
    assert "protected payload field 'temperature'" in result.stderr


def test_collect_all_rejects_invalid_request_omit_field(tmp_path: Path) -> None:
    cfg = tmp_path / "models.yaml"
    cfg.write_text(
        """
collection:
  probe_set_version: v2
  default_budget: cheap
models:
  - canonical_id: openai/gpt-4o
    endpoint: https://example.com/v1
    model_id: gpt-4o
    key_env: OPENAI_API_KEY
    request_omit_fields:
      - messages
""",
        encoding="utf-8",
    )
    result = _run_script(
        "collect_all.py",
        "--config",
        str(cfg),
        "--out",
        str(tmp_path / "out"),
        "--env-file",
        "/dev/null",
    )
    assert result.returncode == 2
    assert "unsupported field 'messages'" in result.stderr


def test_models_yaml_is_valid(tmp_path: Path) -> None:
    """The shipped models.yaml must parse and reference only known canonical ids."""
    import yaml

    from api_key_scanner import aliases
    from api_key_scanner.aliases import UnknownModelError

    with (_REPO_ROOT / "models.yaml").open("r", encoding="utf-8") as f:
        cfg = yaml.safe_load(f)

    assert "models" in cfg
    errors: list[str] = []
    for entry in cfg["models"]:
        cid = entry["canonical_id"]
        try:
            resolved = aliases.to_canonical(cid)
        except UnknownModelError as exc:
            errors.append(f"{cid}: {exc}")
            continue
        if resolved != cid:
            errors.append(f"{cid}: resolves to {resolved}")
    assert not errors, "models.yaml <-> aliases.json drift:\n  " + "\n  ".join(errors)


@pytest.mark.parametrize(
    "script",
    [
        "collect_all.py",
        "generate_manifest.py",
        "validate_fingerprints.py",
        "generate_supported_models.py",
    ],
)
def test_scripts_have_help(script: str) -> None:
    """Every script surfaces --help without error."""
    result = _run_script(script, "--help")
    assert result.returncode == 0, result.stderr
    assert "usage" in result.stdout.lower()


def test_collect_all_help_does_not_expose_metadata_anomaly_flag() -> None:
    result = _run_script("collect_all.py", "--help")
    assert result.returncode == 0, result.stderr
    assert "--fail-on-metadata-anomaly" not in result.stdout


# ---- generate_supported_models -------------------------------------------


def test_generate_supported_models_builds_table(tmp_path: Path) -> None:
    """Manifest + models.yaml -> markdown with one row per manifest model."""
    manifest = tmp_path / "MANIFEST.json"
    manifest.write_text(
        json.dumps(
            {
                "collected_at": "2026-04-21T08:56:13.616901+00:00",
                "probe_set_version": "v2",
                "models": {
                    "openai/gpt-5.4": {
                        "file": "openai/gpt-5.4.jsonl",
                        "num_samples": 58,
                        "sha256": "x" * 64,
                    },
                    "openai/gpt-5": {
                        "file": "openai/gpt-5.jsonl",
                        "num_samples": 57,
                        "sha256": "y" * 64,
                    },
                },
            }
        ),
        encoding="utf-8",
    )
    models_yaml = tmp_path / "models.yaml"
    models_yaml.write_text(
        "models:\n"
        "  - canonical_id: openai/gpt-5.4\n"
        "    model_id: gpt-5.4\n"
        "    endpoint: https://gw.example.com/v1\n"
        "  - canonical_id: openai/gpt-5\n"
        "    model_id: gpt-5\n"
        "    endpoint: https://gw.example.com/v1\n",
        encoding="utf-8",
    )
    out = tmp_path / "SUPPORTED_MODELS.md"
    result = _run_script(
        "generate_supported_models.py",
        "--manifest",
        str(manifest),
        "--models-yaml",
        str(models_yaml),
        "--release-tag",
        "fingerprint-2026-04-21-test",
        "--out",
        str(out),
    )
    assert result.returncode == 0, result.stderr

    content = out.read_text(encoding="utf-8")
    assert "fingerprint-2026-04-21-test" in content
    assert "2026-04-21" in content
    assert "`openai/gpt-5.4`" in content
    assert "`openai/gpt-5`" in content
    assert "`gpt-5.4`" in content
    assert "https://gw.example.com/v1" in content
    assert "| 58 |" in content
    assert "| 57 |" in content
    assert "`v2`" in content
    assert "Probe 集" in content


def test_generate_supported_models_missing_endpoint_uses_question_mark(
    tmp_path: Path,
) -> None:
    """A canonical id in the manifest but not in models.yaml still renders."""
    manifest = tmp_path / "MANIFEST.json"
    manifest.write_text(
        json.dumps(
            {
                "collected_at": "2026-04-21T00:00:00+00:00",
                "models": {
                    "some/orphan": {
                        "file": "some/orphan.jsonl",
                        "num_samples": 10,
                        "sha256": "z" * 64,
                    }
                },
            }
        ),
        encoding="utf-8",
    )
    models_yaml = tmp_path / "models.yaml"
    models_yaml.write_text("models: []\n", encoding="utf-8")
    out = tmp_path / "SUPPORTED_MODELS.md"

    result = _run_script(
        "generate_supported_models.py",
        "--manifest",
        str(manifest),
        "--models-yaml",
        str(models_yaml),
        "--release-tag",
        "fingerprint-2026-04-21-test",
        "--out",
        str(out),
    )
    assert result.returncode == 0, result.stderr
    content = out.read_text(encoding="utf-8")
    assert "`some/orphan`" in content
    assert "| `?` | `?` |" in content
