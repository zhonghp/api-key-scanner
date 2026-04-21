"""Unit tests for fingerprint_fetch.

All HTTP is mocked via respx. Sigstore verification is monkey-patched
because we don't have a real signing key in tests — we exercise the
integration (download → pass bytes to verifier → on exception raise
FingerprintFetchError) but not the Sigstore library itself.
"""

from __future__ import annotations

import hashlib
import json
import time
from pathlib import Path

import pytest
import respx

from api_key_scanner import fingerprint_fetch
from api_key_scanner.fingerprint_fetch import (
    FetchResult,
    FingerprintFetchError,
    _prune_old_generations,
    ensure_fingerprints,
)

REPO = "zhonghp/api-key-scanner"
TAG = "fingerprint-2026-04-21-signed"


# --- fixtures ---------------------------------------------------------------


@pytest.fixture(autouse=True)
def _clear_env(monkeypatch: pytest.MonkeyPatch) -> None:
    for var in (
        "APIGUARD_FINGERPRINT_DIR",
        "APIGUARD_FINGERPRINT_RELEASE",
        "APIGUARD_FINGERPRINT_REPO",
        "APIGUARD_FINGERPRINT_AUTO_UPDATE",
        "APIGUARD_OFFLINE",
    ):
        monkeypatch.delenv(var, raising=False)


@pytest.fixture
def fake_cache(tmp_path: Path) -> Path:
    return tmp_path / "cache"


@pytest.fixture
def stub_sigstore(monkeypatch: pytest.MonkeyPatch) -> None:
    """Replace _verify_sigstore with a no-op so we never touch the real verifier."""
    monkeypatch.setattr(fingerprint_fetch, "_verify_sigstore", lambda **kw: None)


# --- helpers ----------------------------------------------------------------


def _build_manifest(models: dict[str, bytes]) -> tuple[bytes, dict[str, bytes]]:
    """Return (manifest_bytes, asset_name -> content) for a toy release."""
    manifest: dict[str, object] = {
        "version": "v2026.04.21",
        "probe_set_version": "v1",
        "collected_at": "2026-04-21T00:00:00+00:00",
        "collector_version": "0.1.0",
        "models": {
            canonical: {
                "file": f"{canonical}.jsonl",
                "sha256": hashlib.sha256(content).hexdigest(),
                "size_bytes": len(content),
                "num_samples": 1,
                "provenance": {"collector_version": "0.1.0"},
            }
            for canonical, content in models.items()
        },
        "probes_snapshot": {},
    }
    assets = {f"{canonical.split('/')[-1]}.jsonl": content for canonical, content in models.items()}
    manifest_bytes = json.dumps(manifest).encode()
    return manifest_bytes, assets


def _mock_release(
    tag: str,
    manifest_bytes: bytes,
    sigstore_bytes: bytes,
    jsonl_assets: dict[str, bytes],
    *,
    sig_name: str = "MANIFEST.json.sigstore.json",
) -> None:
    """Wire up respx routes for one release. Assumes respx.mock already active."""
    base_dl = f"https://github.com/{REPO}/releases/download/{tag}"
    assets_list = [
        {"name": "MANIFEST.json", "browser_download_url": f"{base_dl}/MANIFEST.json"},
        {"name": sig_name, "browser_download_url": f"{base_dl}/{sig_name}"},
    ]
    for name in jsonl_assets:
        assets_list.append({"name": name, "browser_download_url": f"{base_dl}/{name}"})

    respx.get(f"https://api.github.com/repos/{REPO}/releases/tags/{tag}").respond(
        json={"tag_name": tag, "assets": assets_list}
    )
    respx.get(f"{base_dl}/MANIFEST.json").respond(content=manifest_bytes)
    respx.get(f"{base_dl}/{sig_name}").respond(content=sigstore_bytes)
    for name, content in jsonl_assets.items():
        respx.get(f"{base_dl}/{name}").respond(content=content)


def _mock_release_list(releases: list[str]) -> None:
    data = [
        {"tag_name": tag, "assets": [], "published_at": "2026-04-21T00:00:00Z"} for tag in releases
    ]
    respx.get(f"https://api.github.com/repos/{REPO}/releases?per_page=30").respond(json=data)


# --- happy path -------------------------------------------------------------


@respx.mock
async def test_pinned_tag_happy_path(fake_cache: Path, stub_sigstore: None) -> None:
    gpt54 = b'{"probe_id": "llmmap-001", "samples": []}\n'
    mini = b'{"probe_id": "llmmap-002", "samples": []}\n'
    manifest, jsonl_assets = _build_manifest({"openai/gpt-5.4": gpt54, "openai/gpt-5.4-mini": mini})
    _mock_release(TAG, manifest, b"fake-sigstore-bundle", jsonl_assets)

    result = await ensure_fingerprints(repo=REPO, pinned_tag=TAG, cache_root=fake_cache)

    assert isinstance(result, FetchResult)
    assert result.tag == TAG
    assert result.from_cache is False
    assert result.path == fake_cache / "fingerprints" / TAG
    assert (result.path / "openai" / "gpt-5.4.jsonl").read_bytes() == gpt54
    assert (result.path / "openai" / "gpt-5.4-mini.jsonl").read_bytes() == mini
    assert (result.path / "MANIFEST.json").read_bytes() == manifest
    # state.json written
    state = json.loads((fake_cache / "fingerprints" / ".state.json").read_text())
    assert state["active_tag"] == TAG


@respx.mock
async def test_picks_latest_fingerprint_tag(fake_cache: Path, stub_sigstore: None) -> None:
    # Mix in a non-fingerprint release (v0.1.0) — it must be ignored.
    _mock_release_list(["v0.1.0", "fingerprint-2026-04-14", "fingerprint-2026-04-21-signed"])
    gpt54 = b'{"probe_id": "p", "samples": []}\n'
    manifest, jsonl_assets = _build_manifest({"openai/gpt-5.4": gpt54})
    _mock_release(TAG, manifest, b"sig", jsonl_assets)

    result = await ensure_fingerprints(repo=REPO, cache_root=fake_cache)
    assert result.tag == TAG


# --- cache hits -------------------------------------------------------------


@respx.mock
async def test_cache_hit_same_tag_no_network_downloads(
    fake_cache: Path, stub_sigstore: None
) -> None:
    # First call populates the cache.
    gpt54 = b"line\n"
    manifest, jsonl_assets = _build_manifest({"openai/gpt-5.4": gpt54})
    _mock_release(TAG, manifest, b"sig", jsonl_assets)
    await ensure_fingerprints(repo=REPO, pinned_tag=TAG, cache_root=fake_cache)

    # Second call: the tag endpoint should still succeed, but we should NOT
    # redownload any assets.
    asset_routes = [r for r in respx.routes if "/releases/download/" in str(r.pattern)]
    for r in asset_routes:
        r.reset()

    result = await ensure_fingerprints(repo=REPO, pinned_tag=TAG, cache_root=fake_cache)
    assert result.from_cache is True
    for r in asset_routes:
        assert r.call_count == 0, f"unexpected re-download of {r.pattern}"


async def test_offline_with_cache_returns_cached(fake_cache: Path, stub_sigstore: None) -> None:
    # Populate cache manually so no network is needed.
    fp_root = fake_cache / "fingerprints"
    (fp_root / TAG / "openai").mkdir(parents=True)
    (fp_root / TAG / "openai" / "gpt-5.4.jsonl").write_bytes(b"line\n")
    (fp_root / ".state.json").write_text(
        json.dumps({"active_tag": TAG, "last_checked_at": "2026-04-21T00:00:00+00:00"})
    )

    with respx.mock() as mocked:
        result = await ensure_fingerprints(repo=REPO, offline=True, cache_root=fake_cache)
        assert mocked.calls.call_count == 0
    assert result.tag == TAG
    assert result.from_cache is True


async def test_offline_without_cache_raises(tmp_path: Path) -> None:
    with pytest.raises(FingerprintFetchError) as exc_info:
        await ensure_fingerprints(offline=True, cache_root=tmp_path / "empty")
    assert exc_info.value.kind == "offline_no_cache"


# --- auto-update ------------------------------------------------------------


@respx.mock
async def test_auto_update_picks_new_tag(fake_cache: Path, stub_sigstore: None) -> None:
    old_tag = "fingerprint-2026-04-14"
    new_tag = "fingerprint-2026-04-21-signed"

    # seed cache with old tag
    fp_root = fake_cache / "fingerprints"
    (fp_root / old_tag / "openai").mkdir(parents=True)
    (fp_root / old_tag / "openai" / "gpt-5.4.jsonl").write_bytes(b"old\n")
    (fp_root / ".state.json").write_text(
        json.dumps({"active_tag": old_tag, "last_checked_at": "..."})
    )

    _mock_release_list([old_tag, new_tag])
    new_content = b"new\n"
    manifest, jsonl = _build_manifest({"openai/gpt-5.4": new_content})
    _mock_release(new_tag, manifest, b"sig", jsonl)

    result = await ensure_fingerprints(repo=REPO, cache_root=fake_cache)
    assert result.tag == new_tag
    assert result.from_cache is False
    assert (fp_root / new_tag / "openai" / "gpt-5.4.jsonl").read_bytes() == new_content


@respx.mock
async def test_auto_update_false_sticks_with_cached(fake_cache: Path, stub_sigstore: None) -> None:
    old_tag = "fingerprint-2026-04-14"
    new_tag = TAG
    fp_root = fake_cache / "fingerprints"
    (fp_root / old_tag / "openai").mkdir(parents=True)
    (fp_root / old_tag / "openai" / "gpt-5.4.jsonl").write_bytes(b"old\n")
    (fp_root / ".state.json").write_text(
        json.dumps({"active_tag": old_tag, "last_checked_at": "..."})
    )

    # Only the list endpoint will be hit; no downloads should happen.
    _mock_release_list([old_tag, new_tag])

    result = await ensure_fingerprints(repo=REPO, auto_update=False, cache_root=fake_cache)
    assert result.tag == old_tag
    assert result.from_cache is True


# --- failure modes ----------------------------------------------------------


@respx.mock
async def test_sha256_mismatch_raises_and_leaves_state(
    fake_cache: Path, stub_sigstore: None
) -> None:
    good = b"correct"
    manifest, _jsonl = _build_manifest({"openai/gpt-5.4": good})
    _mock_release(TAG, manifest, b"sig", {"gpt-5.4.jsonl": b"CORRUPTED"})

    with pytest.raises(FingerprintFetchError) as exc_info:
        await ensure_fingerprints(repo=REPO, pinned_tag=TAG, cache_root=fake_cache)
    assert exc_info.value.kind == "hash_mismatch"
    assert not (fake_cache / "fingerprints" / TAG).exists()
    # No state file should have been written.
    assert not (fake_cache / "fingerprints" / ".state.json").exists()


@respx.mock
async def test_sigstore_failure_raises(fake_cache: Path, monkeypatch: pytest.MonkeyPatch) -> None:
    def _raise(**kwargs: object) -> None:
        raise FingerprintFetchError("signature", "cert identity mismatch")

    monkeypatch.setattr(fingerprint_fetch, "_verify_sigstore", _raise)

    manifest, jsonl = _build_manifest({"openai/gpt-5.4": b"data"})
    _mock_release(TAG, manifest, b"bad-sig", jsonl)

    with pytest.raises(FingerprintFetchError) as exc_info:
        await ensure_fingerprints(repo=REPO, pinned_tag=TAG, cache_root=fake_cache)
    assert exc_info.value.kind == "signature"
    assert not (fake_cache / "fingerprints" / TAG).exists()


@respx.mock
async def test_no_fingerprint_releases_raises(fake_cache: Path, stub_sigstore: None) -> None:
    _mock_release_list(["v0.1.0", "v0.0.1"])

    with pytest.raises(FingerprintFetchError) as exc_info:
        await ensure_fingerprints(repo=REPO, cache_root=fake_cache)
    assert exc_info.value.kind == "no_releases"


async def test_invalid_pinned_tag_raises(fake_cache: Path) -> None:
    with pytest.raises(FingerprintFetchError) as exc_info:
        await ensure_fingerprints(repo=REPO, pinned_tag="v0.1.0", cache_root=fake_cache)
    assert exc_info.value.kind == "schema"


@respx.mock
async def test_missing_sigstore_asset_raises(fake_cache: Path, stub_sigstore: None) -> None:
    # Manually build a release response without the .sigstore asset.
    respx.get(f"https://api.github.com/repos/{REPO}/releases/tags/{TAG}").respond(
        json={
            "tag_name": TAG,
            "assets": [
                {
                    "name": "MANIFEST.json",
                    "browser_download_url": f"https://example.com/{TAG}/MANIFEST.json",
                }
            ],
        }
    )
    with pytest.raises(FingerprintFetchError) as exc_info:
        await ensure_fingerprints(repo=REPO, pinned_tag=TAG, cache_root=fake_cache)
    assert exc_info.value.kind == "signature"


@respx.mock
async def test_supports_legacy_sigstore_asset_name(fake_cache: Path, stub_sigstore: None) -> None:
    gpt54 = b"data"
    manifest, jsonl = _build_manifest({"openai/gpt-5.4": gpt54})
    _mock_release(TAG, manifest, b"legacy-sig", jsonl, sig_name="MANIFEST.json.sigstore")

    result = await ensure_fingerprints(repo=REPO, pinned_tag=TAG, cache_root=fake_cache)
    assert result.tag == TAG
    assert (result.path / "MANIFEST.json.sigstore").exists()


@respx.mock
async def test_github_api_404_raises_network(fake_cache: Path) -> None:
    respx.get(f"https://api.github.com/repos/{REPO}/releases/tags/{TAG}").respond(
        status_code=404, json={"message": "Not Found"}
    )
    with pytest.raises(FingerprintFetchError) as exc_info:
        await ensure_fingerprints(repo=REPO, pinned_tag=TAG, cache_root=fake_cache)
    assert exc_info.value.kind == "network"


# --- housekeeping -----------------------------------------------------------


def test_prune_keeps_n_generations(tmp_path: Path) -> None:
    fp_root = tmp_path / "fp"
    tags = [
        "fingerprint-2026-04-07",
        "fingerprint-2026-04-14",
        "fingerprint-2026-04-21",
        "fingerprint-2026-04-28",
    ]
    for t in tags:
        (fp_root / t).mkdir(parents=True)
        (fp_root / t / "marker").write_text("x")
    # unrelated dir should survive
    (fp_root / "not-a-fingerprint").mkdir()

    _prune_old_generations(fp_root, keep_tag="fingerprint-2026-04-28", keep_n=2)

    assert (fp_root / "fingerprint-2026-04-28").exists()
    assert (fp_root / "fingerprint-2026-04-21").exists()  # kept as N=2 previous gen
    assert not (fp_root / "fingerprint-2026-04-14").exists()
    assert not (fp_root / "fingerprint-2026-04-07").exists()
    assert (fp_root / "not-a-fingerprint").exists()


def test_gc_partials_removes_old(tmp_path: Path) -> None:
    fp_root = tmp_path
    fresh = fp_root / ".partial-new"
    stale = fp_root / ".partial-old"
    fresh.mkdir()
    stale.mkdir()
    # backdate stale beyond the 1h window
    old_time = time.time() - 2 * 3600
    import os as _os

    _os.utime(stale, (old_time, old_time))

    fingerprint_fetch._gc_partials(fp_root)

    assert fresh.exists()
    assert not stale.exists()
