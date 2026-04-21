# Changelog

All notable changes to this project will be documented in this file.
The format follows [Keep a Changelog](https://keepachangelog.com/en/1.1.0/);
versions use [Semantic Versioning](https://semver.org/spec/v2.0.0.html).

## [0.1.2] — 2026-04-21

### Added
- **Auto-load `~/.api-key-scanner/.env`** at MCP server startup when
  no `APIGUARD_DOTENV_PATH` is set. Sidesteps the Claude Code env
  snapshot problem: shell exports performed after Claude Code is
  running never reach the MCP subprocess, but a dotfile that the
  server reads on each startup does. Shell env still wins over the
  file — this is a fallback, not an override.

## [0.1.1] — 2026-04-21

### Added
- **Auto-fetch signed fingerprints from GitHub Releases.** On first
  `verify_gateway` call, the MCP server downloads the latest
  `fingerprint-YYYY-MM-DD` release, verifies its Sigstore bundle
  against the weekly workflow's OIDC identity, sha256-checks every
  `.jsonl` against `MANIFEST.json`, and caches the verified data
  under `~/.cache/api-key-scanner/fingerprints/<tag>/` via
  `platformdirs`. No more manual bootstrap needed after
  `/plugin install`.
- New env knobs: `APIGUARD_FINGERPRINT_RELEASE`,
  `APIGUARD_FINGERPRINT_REPO`, `APIGUARD_FINGERPRINT_AUTO_UPDATE`,
  `APIGUARD_OFFLINE`.
- `fingerprint_fetch.ensure_fingerprints()` with
  `FingerprintFetchError(kind=...)` discriminants for
  network/signature/hash/schema failures.

### Fixed
- Weekly workflow now actually publishes the Sigstore bundle
  (`MANIFEST.json.sigstore.json`) to the release. Previously
  `upload-signing-artifacts: false` was suppressing it.

## [Unreleased] — Phase 1 in progress

### Added
- **Batch fingerprint collection pipeline (M3)**
  - `models.yaml` — declarative list of models to collect, with per-entry
    `endpoint` / `model_id` / `key_env` / `budget` / `enabled` fields
  - `scripts/collect_all.py` — weekly collection driver, reads models.yaml
    and iterates all enabled entries
  - `scripts/generate_manifest.py` — produces signed-ready `MANIFEST.json`
    with sha256 of every file and probe-set snapshot hashes
  - `scripts/validate_fingerprints.py` — three-layer check (schema /
    aliases alignment / manifest integrity)
- **GitHub Actions workflows**
  - `ci.yml` — lint + pytest on 3.10/3.11/3.12, MCP protocol smoke test
  - `weekly-fingerprint-collect.yml` — Monday 02:00 UTC cron,
    collect → sign → release to GitHub with Sigstore keyless
  - `release.yml` — PyPI Trusted Publishers on version tag push
- **Alignment choke point**: single `aliases.to_canonical()` used by
  bootstrap / collect_all / verify_gateway / fingerprint loader; `UnknownModelError`
  raised on drift, no silent fallback
- **`aliases.validate_aliases_file()`**: internal consistency check
  (every alias RHS must be in `canonical[]`; every family member too)
- **`APIGUARD_INSECURE_SSL=1`** env var: skip SSL verification for internal
  LLM deployments with self-signed certs
- **`APIGUARD_DOTENV_PATH`** env var: opt-in loading of a `.env` file at
  MCP startup, scoped per-server via `.mcp.json`'s `env` block
- **Probe failure evidence**: when any probe errors, the Verdict's
  `evidence` carries an `alarm`-level item with the sanitized first error
- **Debug logging for network errors** in `gateway.py`: SSL / timeout /
  connect errors are logged to stderr at DEBUG level
- Expanded probe set: 12 LLMmap probes + 8 MET probes (multi-language,
  code, refusal, identification, reasoning)

### Changed
- `bootstrap_fingerprints.py` now reads configuration from `.env` instead
  of CLI flags (see `.env.example` for the variable names)
- `python-dotenv` and `pyyaml` moved to main dependencies (were dev-only)
- Budget caps updated to reflect expanded probe set:
  - `cheap`: 3 llmmap + 1 met (~13 calls, ~$0.05 on gpt-4o)
  - `standard`: 8 llmmap + 5 met (~58 calls, ~$0.30)
  - `deep`: 12 llmmap + 8 met (~92 calls, ~$0.50)

### Security
- `OpenAICompatClient` now scrubs the raw API key from response bodies /
  error strings before returning them as `ProbeResponse.error` — covers
  the case where a backend echoes the `Authorization` header in its
  error body

### Documentation
- `docs/2026-04-20-使用文档.md` — full Chinese usage guide with three
  invocation modes (Claude Code plugin / raw stdio / inline Python)
- `docs/2026-04-20-phase1-技术实现方案.md` — the phase 1 plan this
  changelog tracks against
- `docs/2026-04-20-LLM-API-中转站真伪鉴别方案.md` — end-to-end design

## [0.1.0] — not yet released
First alpha. Target tag once M5 calibration set is in place.
