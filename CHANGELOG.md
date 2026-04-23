# Changelog

All notable changes to this project will be documented in this file.
The format follows [Keep a Changelog](https://keepachangelog.com/en/1.1.0/);
versions use [Semantic Versioning](https://semver.org/spec/v2.0.0.html).

## [0.2.0] — 2026-04-23

### Breaking
- **D1 detector renamed**: Verdict JSON key changed from
  `detectors.d1_llmmap` to `detectors.d1_banner_match`. The current
  D1 implementation is a lightweight cosine-NN banner matcher, not a
  LLMmap-style trained classifier — the rename makes that honest.
  Clients that parse verdict JSON by detector key need to update.
- **`Budget` Literal narrowed** from `["cheap", "standard", "deep"]`
  to `["cheap", "standard"]`. `budget="deep"` is rejected by
  Pydantic. The v2 probe pool (8 LLMmap-style + 25 MET-style) is
  saturated at `standard`, so `deep` had nothing to add.
- **v1 and v2 probe sets are incompatible**. v2 sets a new default
  (`PROBE_SET_VERSION = "v2"`) with new probe IDs; existing v1
  fingerprint releases will not match v2 probes. Fall back to v1 via
  `APIGUARD_PROBE_SET_VERSION=v1` if needed; the v2 fingerprint
  release is produced by the next weekly workflow run.

### Added
- Probe set **v2**:
  - `llmmap_v2.jsonl` — LLMmap `confs/queries/default.json` verbatim
    (8 queries: banner + banner-injection + meta + ethics-T/F + 2
    refusal variants). Per-probe `max_tokens` calibrated (128–512).
  - `met_v2.jsonl` — 25 Wikipedia continuation prompts across 5
    languages (en/de/fr/ru/es), matching Gao et al.'s main MET
    experiment. `temperature=1.0`, `num_samples=10` (N=250).
- `APIGUARD_PROBE_SET_VERSION` env var for rollback / A-B testing.
- `current_probe_set_version()` helper so Verdict reflects the
  version actually used at runtime (not the compile-time default).
- **D2 upgrade**: `detectors/_met_kernels.py` vendors the MMD²
  Hamming kernel + permutation p-value from
  [`i-gao/model-equality-testing`](https://github.com/i-gao/model-equality-testing)
  (MIT-licensed, ~135 LOC pure numpy/Python, no torch dependency).
  `detectors/met.py` rewritten to run MET on padded unicode
  codepoint sequences with `pad_length=50` (MET paper L).
- **D1/D2 isolation by `expected_detectors` tag**: detectors now
  honor an `allowed_probe_ids` filter, and the server builds one per
  detector from each probe's `expected_detectors` list. Prevents D1
  from cross-comparing against MET continuation samples when the
  reference fingerprint happens to include both probe types.
- **Reference-coverage warnings in Verdict**: when the fingerprint
  misses probe ids that the current budget expects (most common
  cause: reference collected at `cheap`, verify running at
  `standard`), the detector status drops to `degraded` and a warn
  evidence item surfaces the missing ids + likely budget-mismatch
  cause. Fixes a silent failure mode where a confident-looking score
  was computed on a small subset of the intended probes.
- **MANIFEST `probe_set_version` binding**: `generate_manifest.py`
  writes the active version; `fingerprint_fetch.ensure_fingerprints`
  takes an optional `expected_probe_set_version` and raises
  `FingerprintFetchError(kind="schema")` on mismatch rather than
  silently loading incompatible data.

### Changed
- Budget reshaped around MET paper protocol:
  - `cheap`: 3 banner probes + 5 MET prompts × 3 samples = 18 calls
    (smoke test).
  - `standard`: 8 banner probes + 25 MET prompts × 10 samples = 258
    calls (full paper protocol). This is ~4.5× the old `standard`;
    verify latency goes from ~30 s to ~3 min.
- **Default budget flipped from `standard` to `cheap`** across the
  MCP tool (`verify_gateway(..., budget="cheap")`), the weekly
  workflow (`models.yaml: default_budget: cheap`), and the loaders
  (`probes.load_probes()`, `scripts/collect_all.py`). Reasoning:
  `standard` now costs ~258 gateway calls (~3 min, ~$0.10 per verify
  on a typical gateway) — enough to surprise users on a first-time
  probe. `cheap` runs in ~3 seconds and catches gross substitutions;
  users escalate to `standard` when a result warrants stronger
  statistical power. Skill copy + README walk the reader through
  the two-stage workflow.

### Fixed
- D1 was silently counting MET continuation samples toward
  `num_samples_scored` whenever the reference fingerprint held both
  probe types — a cheap-budget reference paired with a standard
  verify would produce e.g. `num_samples_scored=53, status=ok` where
  50 of those samples were MET outputs at T=0.7 being nearest-
  neighbor-voted as if they were banner responses. See the isolation
  filter under Added above.

## [0.1.4] — 2026-04-21

### Fixed
- When auto-fetch of fingerprint data fails (network, Sigstore
  verification, schema mismatch), the resulting `inconclusive`
  Verdict now includes the specific failure reason instead of a
  generic "set APIGUARD_FINGERPRINT_DIR" message that implied
  the user was supposed to configure it manually. Users can now
  see, e.g., `auto-fetch detail: signature: cert identity
  mismatch` and know exactly which knob to turn.
- The `FingerprintDataMissingError` message stopped referring to
  the long-shipped "M3 release-fetching implementation" as
  future work.

## [0.1.3] — 2026-04-21

### Removed
- **Cost estimation**. The `cost_usd_estimate` field is gone from
  `Verdict`, along with the hardcoded `_ROUGH_RATES_USD_PER_1K`
  table and the `_estimate_cost_usd` helper. The estimate conflated
  a guessed fixed-50-input-tokens-per-probe assumption with
  hand-maintained vendor prices, giving users a number that could
  easily be wrong by 3-5× and quietly drift as vendors changed
  pricing. Users should consult their provider's billing page
  instead.
- Budget docstrings and skill copy also drop all `$X.XX` figures.

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

## [0.1.0] — not yet released
First alpha. Target tag once M5 calibration set is in place.
