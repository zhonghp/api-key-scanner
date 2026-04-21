# Contributing

This guide is for **developers** who want to run the tool from source,
regenerate fingerprint data, or understand the internals.

End users don't need any of this — the [README](./README.md) covers the
install-and-use flow.

## Repository layout

```
src/api_key_scanner/
  server.py           MCP server + verify_gateway tool
  fingerprint_fetch.py  Auto-fetch + Sigstore verify signed releases
  probes.py           Load probe set + reference fingerprints
  gateway.py          OpenAI-compat HTTP client (retries, key-scrubbing)
  detectors/          D1 LLMmap, D2 MET, D4 Metadata, fusion
  aliases.py          Canonical model-id normalization
  data/               Bundled probes + aliases.json

scripts/
  bootstrap_fingerprints.py   Collect a fingerprint for ONE model
  collect_all.py              Batch collector (reads models.yaml)
  generate_manifest.py        Build MANIFEST.json with sha256
  validate_fingerprints.py    Schema + alignment + hash check

.github/workflows/
  ci.yml                            Lint + pytest (3.10/3.11/3.12)
  weekly-fingerprint-collect.yml    Collect + Sigstore-sign + release
  release.yml                       PyPI + GitHub Release on tag push

tests/
  unit/         Fast, mocked
  integration/  Gateway mocked via respx; fingerprint fixtures in tmp_path
```

## Dev setup

```bash
git clone https://github.com/zhonghp/api-key-scanner.git
cd api-key-scanner
uv sync --all-extras

uv run pytest -q                # full suite
uv run ruff check src tests scripts
uv run ruff format --check src tests scripts
uv run api-key-scanner-mcp      # run the MCP server over stdio
```

## How `verify_gateway` actually works

```
┌─────────────────────────────────────────────────────────────┐
│  Claude Code / opencode / Cursor / any MCP client           │
│         ↓ spawn stdio subprocess                             │
│  api-key-scanner-mcp  (reads gateway key from local env)    │
│         ↓ load signed reference fingerprints                 │
│         ↓ run probe set                                      │
│  Target gateway  (the one you're verifying)                  │
│         ↓ collect responses                                  │
│  D1 LLMmap  +  D2 MET (MMD²)  +  D4 Metadata                │
│         ↓ Bayesian fusion                                    │
│  Verdict { trust_score, verdict, detectors, evidence }       │
└─────────────────────────────────────────────────────────────┘
```

Three detectors run locally against the reference data:

- **D1 · LLMmap** — char-n-gram cosine nearest-neighbor classifier.
  Catches cross-family substitution. Based on
  [LLMmap (USENIX Sec'25)](https://arxiv.org/abs/2407.15847).
- **D2 · Model Equality Testing** — biased MMD² two-sample test with a
  string kernel + permutation p-values. Catches distribution drift.
  Based on [MET (ICLR'25)](https://arxiv.org/abs/2410.20247).
- **D4 · Metadata** — `system_fingerprint` stability, tokenizer
  consistency, latency envelope. Catches cache-replay and backend swaps.

A Bayesian fusion (`prior=0.85`, weights `d1=0.45, d2=0.40, d4=0.15`)
produces a single `trust_score` and verdict label.

## Running the fingerprint collection pipeline locally

You only need this if you're adding a new model to the catalog or
debugging the collector itself. Normal development does not require
running it.

```bash
# 1. Edit models.yaml — list of (canonical_id, endpoint, model_id, key_env)
# 2. Make sure the required API keys are in your shell env or .env
uv run python scripts/collect_all.py --out ./fingerprints --fail-on-empty

# 3. Build the MANIFEST.json
uv run python scripts/generate_manifest.py ./fingerprints

# 4. Three-layer integrity check
uv run python scripts/validate_fingerprints.py ./fingerprints
```

In production this runs via `.github/workflows/weekly-fingerprint-collect.yml`.
It is **manual-dispatch only** at the moment (we removed the weekly
schedule while iterating); trigger it via the Actions tab. The job
Sigstore-signs the `MANIFEST.json` and publishes everything as a
`fingerprint-YYYY-MM-DD` GitHub Release.

## Release procedure (maintainers)

1. Bump version in `pyproject.toml` and `src/api_key_scanner/__init__.py`
2. Update `CHANGELOG.md`
3. `uv lock` to refresh the lockfile
4. `git commit -am 'chore: release 0.1.x'`
5. `git tag v0.1.x && git push origin main v0.1.x`
6. `release.yml` auto-publishes to PyPI (Trusted Publishers) and GitHub
   Release, both Sigstore-signed.

## Bundled probe set vs reference fingerprints

- **Probes** (questions) live in `src/api_key_scanner/data/probes/`,
  shipped inside the wheel. Versioned as a monolithic set (`v1`,
  `v2`, …).
- **Fingerprints** (vendor responses to probes) live in signed GitHub
  Releases, not in the wheel. Auto-downloaded at runtime.

If you add a probe, you must regenerate every model's fingerprint —
otherwise the reference data and the runtime probes won't match. That
would cascade into D1/D2 returning garbage. Bump the probe-set version
any time you change this data.

## Privacy invariants (don't break these)

- Raw API keys must NEVER appear in any value returned from the MCP
  tool, any log line, or any stderr/stdout output. `OpenAICompatClient`
  has a `_sanitize` helper and a test (`test_gateway::test_sanitize_*`)
  — extend these rather than rolling your own scrubber.
- The server must never POST gateway responses anywhere except to
  process-local detectors. No telemetry, no "send error reports," no
  opt-out.
- All external fetches (fingerprint data, probe set) must be Sigstore-
  verified against our known workflow identity. If you add a new
  fetch path, put the identity check before the cache write.

## Architecture decision records

See `docs/` (not in the public repo; maintainer-only) for the original
Phase 1 design doc, attack taxonomy, and threat-model rationale.
