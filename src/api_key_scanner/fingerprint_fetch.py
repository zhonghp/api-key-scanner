"""Fetch and verify fingerprint snapshots from GitHub Releases.

The server calls :func:`ensure_fingerprints` lazily, on first verify_gateway
use. It returns a local directory suitable for ``probes.load_fingerprints``,
guaranteed to contain a Sigstore-verified ``MANIFEST.json`` and matching
``<vendor>/<model>.jsonl`` files.

Resolution order:

1. If ``APIGUARD_FINGERPRINT_DIR`` is set, the server short-circuits before
   calling this module — explicit path wins over everything.
2. Here, if ``pinned_tag`` is set, fetch that tag verbatim.
3. Else list ``fingerprint-YYYY-MM-DD`` releases and pick the highest date.
4. If the cache already holds the chosen tag and ``auto_update`` is True,
   return the cached directory unchanged.
5. Otherwise download to ``<cache>/.partial-<tag>/``, verify Sigstore,
   verify sha256, and atomically rename to ``<cache>/<tag>/``.

Any failure raises :class:`FingerprintFetchError` with a machine-readable
``kind``. The server logs and degrades to no-fingerprint mode; it never
ships unverified data.
"""

from __future__ import annotations

import asyncio
import hashlib
import json
import logging
import re
import shutil
import time
from dataclasses import dataclass
from datetime import datetime, timezone
from pathlib import Path
from typing import Any, Literal

import httpx
from platformdirs import user_cache_dir

logger = logging.getLogger(__name__)


FetchErrorKind = Literal[
    "network",
    "signature",
    "hash_mismatch",
    "no_releases",
    "offline_no_cache",
    "schema",
]


class FingerprintFetchError(Exception):
    """Any failure during download, verification, or cache persistence."""

    def __init__(self, kind: FetchErrorKind, message: str) -> None:
        self.kind = kind
        super().__init__(f"[{kind}] {message}")


# --- public API --------------------------------------------------------------


@dataclass(frozen=True)
class FetchResult:
    """What ensure_fingerprints returns alongside the directory path."""

    path: Path
    tag: str
    from_cache: bool  # True if no network fetch happened this call


_DEFAULT_REPO = "zhonghp/api-key-scanner"
_TAG_RE = re.compile(r"^fingerprint-(\d{4})-(\d{2})-(\d{2})(?:-[a-z0-9-]+)?$")
_PARTIAL_GC_SECONDS = 3600  # sweep .partial-* dirs older than 1h


async def ensure_fingerprints(
    *,
    repo: str = _DEFAULT_REPO,
    pinned_tag: str | None = None,
    auto_update: bool = True,
    offline: bool = False,
    cache_root: Path | None = None,
) -> FetchResult:
    """Resolve a local dir holding a verified fingerprint snapshot.

    Args:
        repo: GitHub ``owner/name``; defaults to the upstream repo. Overriding
            this also overrides the Sigstore identity we require (the workflow
            path includes the repo slug), so only use it when you truly own
            the fork's signing identity.
        pinned_tag: A specific ``fingerprint-*`` tag to fetch instead of the
            latest. Useful for reproducibility and air-gapped environments.
        auto_update: If True (default), on every call we check GitHub for a
            newer tag than the cached one and upgrade if found.
        offline: If True, never touch the network. Returns the cached tag if
            present, else raises ``FingerprintFetchError(kind="offline_no_cache")``.
        cache_root: Override the cache base directory. Defaults to
            :func:`platformdirs.user_cache_dir` / ``api-key-scanner``.

    Returns:
        A :class:`FetchResult` whose ``path`` points at a directory of the
        form ``<cache_root>/fingerprints/<tag>/<vendor>/<model>.jsonl``,
        ready to be passed to ``probes.load_fingerprints``.

    Raises:
        FingerprintFetchError: any failure (network, signature, hash, schema).
    """
    fp_root = _cache_fp_root(cache_root)
    fp_root.mkdir(parents=True, exist_ok=True)
    _gc_partials(fp_root)

    state = _read_state(fp_root)
    cached_tag = state.get("active_tag")

    if offline:
        if cached_tag is None:
            raise FingerprintFetchError(
                "offline_no_cache",
                "APIGUARD_OFFLINE=1 but no fingerprint cache exists",
            )
        tag_dir = fp_root / cached_tag
        if not tag_dir.is_dir():
            raise FingerprintFetchError(
                "offline_no_cache",
                f"state points to {cached_tag} but directory missing",
            )
        return FetchResult(path=tag_dir, tag=cached_tag, from_cache=True)

    async with httpx.AsyncClient(
        timeout=httpx.Timeout(30.0, connect=10.0),
        follow_redirects=True,
        headers={"Accept": "application/vnd.github+json", "User-Agent": "api-key-scanner"},
    ) as client:
        if pinned_tag is not None:
            chosen_tag = await _resolve_pinned_tag(pinned_tag)
        else:
            chosen_tag = await _resolve_latest_tag(client, repo)

        # auto_update=False pins us to whatever we have cached, regardless of
        # what's on the server.
        if cached_tag is not None and not auto_update:
            tag_dir = fp_root / cached_tag
            if tag_dir.is_dir():
                return FetchResult(path=tag_dir, tag=cached_tag, from_cache=True)

        if cached_tag == chosen_tag:
            tag_dir = fp_root / chosen_tag
            if tag_dir.is_dir():
                return FetchResult(path=tag_dir, tag=chosen_tag, from_cache=True)
            # state says we have it but dir vanished — fall through and refetch

        # Fetch full release details (including assets) for the chosen tag.
        _, assets = await _fetch_release_by_tag(client, repo, chosen_tag)

        final_dir = await _download_and_verify(
            client=client, repo=repo, tag=chosen_tag, assets=assets, fp_root=fp_root
        )

    _write_state(fp_root, active_tag=chosen_tag)
    _prune_old_generations(fp_root, keep_tag=chosen_tag, keep_n=2)
    return FetchResult(path=final_dir, tag=chosen_tag, from_cache=False)


# --- cache layout ------------------------------------------------------------


def _cache_fp_root(override: Path | None) -> Path:
    if override is not None:
        return Path(override).expanduser() / "fingerprints"
    return Path(user_cache_dir("api-key-scanner")) / "fingerprints"


def _state_path(fp_root: Path) -> Path:
    return fp_root / ".state.json"


def _read_state(fp_root: Path) -> dict[str, Any]:
    p = _state_path(fp_root)
    if not p.is_file():
        return {}
    try:
        return json.loads(p.read_text(encoding="utf-8"))
    except (OSError, json.JSONDecodeError):
        logger.warning("cache state file %s is unreadable; ignoring", p)
        return {}


def _write_state(fp_root: Path, *, active_tag: str) -> None:
    tmp = fp_root / ".state.json.tmp"
    payload = {
        "active_tag": active_tag,
        "last_checked_at": datetime.now(timezone.utc).isoformat(),
    }
    tmp.write_text(json.dumps(payload, indent=2), encoding="utf-8")
    tmp.replace(_state_path(fp_root))


def _gc_partials(fp_root: Path) -> None:
    now = time.time()
    for child in fp_root.glob(".partial-*"):
        try:
            if now - child.stat().st_mtime > _PARTIAL_GC_SECONDS:
                shutil.rmtree(child, ignore_errors=True)
        except OSError:
            pass


def _prune_old_generations(fp_root: Path, *, keep_tag: str, keep_n: int) -> None:
    """Keep the active tag plus up to ``keep_n - 1`` previous generations."""
    candidates = [d for d in fp_root.iterdir() if d.is_dir() and _TAG_RE.match(d.name)]
    candidates.sort(key=lambda p: p.name, reverse=True)
    seen_keep = False
    kept = 0
    for d in candidates:
        if d.name == keep_tag:
            seen_keep = True
            kept += 1
            continue
        if seen_keep and kept < keep_n:
            kept += 1
            continue
        shutil.rmtree(d, ignore_errors=True)


# --- GitHub API --------------------------------------------------------------


async def _resolve_latest_tag(client: httpx.AsyncClient, repo: str) -> str:
    """Pick the lexicographically-highest fingerprint-* tag from /releases."""
    url = f"https://api.github.com/repos/{repo}/releases?per_page=30"
    resp = await _github_get_json(client, url)
    if not isinstance(resp, list):
        raise FingerprintFetchError("schema", f"/releases did not return a list: {type(resp)}")

    tags = [r.get("tag_name", "") for r in resp]
    matching = sorted([t for t in tags if _TAG_RE.match(t)], reverse=True)
    if not matching:
        raise FingerprintFetchError("no_releases", f"no fingerprint-* releases in {repo}")
    return matching[0]


async def _resolve_pinned_tag(tag: str) -> str:
    if not _TAG_RE.match(tag):
        raise FingerprintFetchError(
            "schema", f"pinned tag {tag!r} does not match fingerprint-YYYY-MM-DD[-suffix]"
        )
    return tag


async def _fetch_release_by_tag(
    client: httpx.AsyncClient, repo: str, tag: str
) -> tuple[str, list[dict[str, Any]]]:
    url = f"https://api.github.com/repos/{repo}/releases/tags/{tag}"
    resp = await _github_get_json(client, url)
    if not isinstance(resp, dict) or "assets" not in resp:
        raise FingerprintFetchError("schema", f"release {tag} response missing assets")
    return tag, resp["assets"]


async def _github_get_json(client: httpx.AsyncClient, url: str) -> Any:
    body = await _get_with_retry(client, url)
    try:
        return json.loads(body)
    except json.JSONDecodeError as exc:
        raise FingerprintFetchError("schema", f"non-JSON response from {url}: {exc}") from exc


async def _get_with_retry(client: httpx.AsyncClient, url: str) -> bytes:
    """Follow the retry envelope used by gateway.py: same codes, same backoff."""
    last_err: str = "unknown"
    max_retries = 3
    for attempt in range(max_retries + 1):
        try:
            resp = await client.get(url)
        except (httpx.TimeoutException, httpx.NetworkError) as exc:
            last_err = f"{type(exc).__name__}: {exc}"
            if attempt < max_retries:
                await asyncio.sleep(2**attempt)
                continue
            break

        if resp.status_code == 200:
            return resp.content
        if resp.status_code in (408, 429, 500, 502, 503, 504):
            last_err = f"http {resp.status_code}"
            if attempt < max_retries:
                await asyncio.sleep(2**attempt + 0.1 * attempt)
                continue
        # Non-retryable or out of retries.
        raise FingerprintFetchError(
            "network", f"GET {url} -> {resp.status_code}: {resp.text[:200]}"
        )

    raise FingerprintFetchError("network", f"GET {url} failed: {last_err}")


# --- download + verify -------------------------------------------------------


async def _download_and_verify(
    *,
    client: httpx.AsyncClient,
    repo: str,
    tag: str,
    assets: list[dict[str, Any]],
    fp_root: Path,
) -> Path:
    """Download assets into a partial dir, verify, then atomic-rename."""
    asset_urls = {a["name"]: a["browser_download_url"] for a in assets if "name" in a}
    if "MANIFEST.json" not in asset_urls:
        raise FingerprintFetchError("schema", f"release {tag} has no MANIFEST.json asset")
    # sigstore-action v3+ produces .sigstore.json (bundle format); older runs
    # used plain .sigstore. Accept either, prefer the newer name.
    sigstore_asset_name = next(
        (n for n in ("MANIFEST.json.sigstore.json", "MANIFEST.json.sigstore") if n in asset_urls),
        None,
    )
    if sigstore_asset_name is None:
        raise FingerprintFetchError(
            "signature",
            f"release {tag} has no MANIFEST.json.sigstore[.json] asset",
        )

    partial = fp_root / f".partial-{tag}"
    if partial.exists():
        shutil.rmtree(partial, ignore_errors=True)
    partial.mkdir(parents=True)

    try:
        # 1. manifest + signature (download before anything else; they gate everything)
        manifest_bytes = await _get_with_retry(client, asset_urls["MANIFEST.json"])
        sigstore_bytes = await _get_with_retry(client, asset_urls[sigstore_asset_name])
        _verify_sigstore(manifest_bytes=manifest_bytes, sigstore_bytes=sigstore_bytes, repo=repo)

        (partial / "MANIFEST.json").write_bytes(manifest_bytes)
        (partial / sigstore_asset_name).write_bytes(sigstore_bytes)

        # 2. parse manifest
        try:
            manifest = json.loads(manifest_bytes)
        except json.JSONDecodeError as exc:
            raise FingerprintFetchError(
                "schema", f"MANIFEST.json is not valid JSON: {exc}"
            ) from exc
        models = manifest.get("models")
        if not isinstance(models, dict):
            raise FingerprintFetchError("schema", "MANIFEST.json missing 'models' object")

        # 3. each referenced .jsonl
        for canonical_id, entry in models.items():
            rel = entry.get("file")
            expected_sha = entry.get("sha256")
            if not isinstance(rel, str) or not isinstance(expected_sha, str):
                raise FingerprintFetchError(
                    "schema", f"manifest entry {canonical_id} missing file/sha256"
                )
            # Assets are flat at top level: filename is basename of 'file'
            asset_name = Path(rel).name
            if asset_name not in asset_urls:
                raise FingerprintFetchError(
                    "schema",
                    f"manifest references {rel} but release has no {asset_name} asset",
                )
            data = await _get_with_retry(client, asset_urls[asset_name])
            actual_sha = hashlib.sha256(data).hexdigest()
            if actual_sha != expected_sha:
                raise FingerprintFetchError(
                    "hash_mismatch",
                    f"{asset_name}: sha256 {actual_sha} != manifest {expected_sha}",
                )
            target = partial / rel
            target.parent.mkdir(parents=True, exist_ok=True)
            target.write_bytes(data)

        # 4. atomic promote
        final = fp_root / tag
        if final.exists():
            shutil.rmtree(final)
        partial.rename(final)
        return final

    except FingerprintFetchError:
        shutil.rmtree(partial, ignore_errors=True)
        raise
    except Exception as exc:
        shutil.rmtree(partial, ignore_errors=True)
        raise FingerprintFetchError("network", f"unexpected error during fetch: {exc}") from exc


def _verify_sigstore(*, manifest_bytes: bytes, sigstore_bytes: bytes, repo: str) -> None:
    """Enforce cert identity = our workflow + issuer = GitHub Actions OIDC."""
    # Import locally so tests can monkeypatch _verify_sigstore without pulling
    # in the TUF network dance of sigstore.Verifier.production().
    from sigstore.models import Bundle
    from sigstore.verify import Verifier
    from sigstore.verify.policy import Identity

    try:
        bundle = Bundle.from_json(sigstore_bytes)
    except Exception as exc:
        raise FingerprintFetchError("signature", f"invalid .sigstore bundle: {exc}") from exc

    expected_identity = (
        f"https://github.com/{repo}/.github/workflows/"
        "weekly-fingerprint-collect.yml@refs/heads/main"
    )
    policy = Identity(
        identity=expected_identity,
        issuer="https://token.actions.githubusercontent.com",
    )
    try:
        verifier = Verifier.production()
        verifier.verify_artifact(input_=manifest_bytes, bundle=bundle, policy=policy)
    except Exception as exc:
        raise FingerprintFetchError(
            "signature",
            f"Sigstore verification failed (expected identity {expected_identity}): {exc}",
        ) from exc
