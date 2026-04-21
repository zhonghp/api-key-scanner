"""Unit tests for scripts/ (collect_all / generate_manifest / validate_fingerprints).

We can't hit real APIs in unit tests, so we:
  - exercise the argparse / config-loading logic directly
  - test the alignment-checker + manifest hash/validate roundtrip with
    hand-written JSONL fixtures on tmp_path
"""

from __future__ import annotations

import json
import subprocess
import sys
from pathlib import Path

import pytest

_REPO_ROOT = Path(__file__).resolve().parents[2]
_SCRIPTS = _REPO_ROOT / "scripts"


def _run_script(script: str, *args: str) -> subprocess.CompletedProcess:
    """Run a script in-process via python to capture stdout/stderr + exit code."""
    return subprocess.run(
        [sys.executable, str(_SCRIPTS / script), *args],
        capture_output=True,
        text=True,
        cwd=_REPO_ROOT,
    )


def _write_fp(path: Path, probe_id: str = "llmmap-001", n: int = 1) -> None:
    """Write a minimal valid fingerprint JSONL file."""
    path.parent.mkdir(parents=True, exist_ok=True)
    with path.open("w") as f:
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


# ---- generate_manifest ----------------------------------------------------


def test_generate_manifest_produces_valid_json(tmp_path: Path) -> None:
    fp_dir = tmp_path / "fp"
    _write_fp(fp_dir / "openai" / "gpt-4o.jsonl")

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


def test_generate_manifest_skips_orphan_models(tmp_path: Path) -> None:
    """A canonical id not in aliases.json must not land in the manifest."""
    fp_dir = tmp_path / "fp"
    _write_fp(fp_dir / "openai" / "gpt-4o.jsonl")
    _write_fp(fp_dir / "unknownvendor" / "totally-fake.jsonl")

    result = _run_script("generate_manifest.py", str(fp_dir))
    assert result.returncode == 0
    assert "totally-fake" in result.stderr  # warned

    manifest = json.loads((fp_dir / "MANIFEST.json").read_text())
    assert "openai/gpt-4o" in manifest["models"]
    assert "unknownvendor/totally-fake" not in manifest["models"]


def test_generate_manifest_require_models_gate(tmp_path: Path) -> None:
    """--require-models exits non-zero when fewer models found than requested."""
    fp_dir = tmp_path / "fp"
    _write_fp(fp_dir / "openai" / "gpt-4o.jsonl")

    result = _run_script("generate_manifest.py", str(fp_dir), "--require-models", "5")
    assert result.returncode == 1
    assert "found 1 models but --require-models=5" in result.stderr


# ---- validate_fingerprints -----------------------------------------------


def test_validate_happy_path(tmp_path: Path) -> None:
    fp_dir = tmp_path / "fp"
    _write_fp(fp_dir / "openai" / "gpt-4o.jsonl", n=3)

    # Generate manifest first
    assert _run_script("generate_manifest.py", str(fp_dir)).returncode == 0
    # Validate
    result = _run_script("validate_fingerprints.py", str(fp_dir))
    assert result.returncode == 0, result.stderr
    assert "schema: ok" in result.stderr
    assert "alignment: ok" in result.stderr
    assert "manifest: ok" in result.stderr


def test_validate_catches_sha_mismatch(tmp_path: Path) -> None:
    fp_dir = tmp_path / "fp"
    jsonl = fp_dir / "openai" / "gpt-4o.jsonl"
    _write_fp(jsonl)

    # Generate manifest, then tamper with the JSONL
    assert _run_script("generate_manifest.py", str(fp_dir)).returncode == 0
    with jsonl.open("a") as f:
        f.write(
            json.dumps(
                {
                    "probe_id": "llmmap-001",
                    "sample_index": 99,
                    "output": "TAMPERED",
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
    bad.write_text('{"probe_id":"x","this is not valid json at all\n')

    result = _run_script("validate_fingerprints.py", str(fp_dir), "--skip-manifest")
    assert result.returncode == 1
    assert "schema FAILED" in result.stderr


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
"""
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
  default_budget: cheap
models: []
"""
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


# ---- generate_supported_models -------------------------------------------


def test_generate_supported_models_builds_table(tmp_path: Path) -> None:
    """Manifest + models.yaml -> markdown with one row per manifest model."""
    manifest = tmp_path / "MANIFEST.json"
    manifest.write_text(
        json.dumps(
            {
                "collected_at": "2026-04-21T08:56:13.616901+00:00",
                "models": {
                    "openai/gpt-5.4": {
                        "file": "openai/gpt-5.4.jsonl",
                        "num_samples": 58,
                        "sha256": "x" * 64,
                    },
                    "openai/gpt-5.4-mini": {
                        "file": "openai/gpt-5.4-mini.jsonl",
                        "num_samples": 57,
                        "sha256": "y" * 64,
                    },
                },
            }
        )
    )
    models_yaml = tmp_path / "models.yaml"
    models_yaml.write_text(
        "models:\n"
        "  - canonical_id: openai/gpt-5.4\n"
        "    model_id: gpt-5.4\n"
        "    endpoint: https://gw.example.com/v1\n"
        "  - canonical_id: openai/gpt-5.4-mini\n"
        "    model_id: gpt-5.4-mini\n"
        "    endpoint: https://gw.example.com/v1\n"
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
    assert "2026-04-21" in content  # date pulled from collected_at
    assert "`openai/gpt-5.4`" in content
    assert "`openai/gpt-5.4-mini`" in content
    assert "`gpt-5.4`" in content
    assert "https://gw.example.com/v1" in content
    assert "| 58 |" in content
    assert "| 57 |" in content


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
        )
    )
    models_yaml = tmp_path / "models.yaml"
    models_yaml.write_text("models: []\n")
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
    assert "| `?` | `?` |" in content  # missing model_id + endpoint both rendered as ?
