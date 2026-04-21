# api-key-scanner

> Verify whether an LLM API gateway is actually serving the claimed model.
> Your API key stays on your machine.

**[简体中文](./README.zh-CN.md)**

`api-key-scanner` is a local [MCP](https://modelcontextprotocol.io) server
shipped as a [Claude Code Plugin](https://code.claude.com/docs/en/plugins).
It runs probe prompts against a target gateway, compares the responses
against signed public reference fingerprints of known models, and returns
a trust score — all locally, no backend, no telemetry.

## Why this exists

LLM API middlemen ("shadow APIs" / 中转站) are a growing market. An academic
audit of 17 shadow APIs found [45.83% failed model-identity
verification](https://arxiv.org/abs/2603.01919). Existing third-party
verifiers (e.g. hvoy.ai) require users to hand over their upstream API keys,
which is a massive security risk.

`api-key-scanner` solves this without asking for your key:

- 🔒 **Your API key never leaves your machine.** The MCP server reads it
  from a local env var you specify *by name*.
- 🧾 **Zero backend.** Probes and fingerprints come from signed GitHub
  Releases. No server to trust, no telemetry.
- 📖 **Fully open-source.** Python code you can audit; Sigstore keyless
  signatures you can verify on the fingerprint data.

---

## Quick start

### Prerequisites

- Python ≥ 3.10 and [uv](https://docs.astral.sh/uv/)
- At least one LLM API key (used both to build a reference fingerprint
  and to verify a target endpoint)

### 1. Install

```bash
git clone https://github.com/zhonghp/api-key-scanner.git
cd api-key-scanner
uv sync --all-extras
```

### 2. Configure `.env`

```bash
cp .env.example .env
# Edit .env with your real values:
#   OPENAI_API_KEY=sk-...
#   MODEL_ID=gpt-4o
#   OPENAI_BASE_URL=https://api.openai.com/v1
```

### 3. Collect a reference fingerprint (one-time per model)

```bash
uv run python scripts/bootstrap_fingerprints.py --budget cheap
# writes ./fingerprints/openai/gpt-4o.jsonl

# Collect a second model so D1 has something to compare against
MODEL_ID=gpt-4o-mini uv run python scripts/bootstrap_fingerprints.py --budget cheap
```

### 4. Verify a gateway — three modes

**Mode A · Claude Code plugin (recommended)**

```text
/plugin marketplace add zhonghp/api-key-scanner
/plugin install api-key-scanner@zhonghp-api-key-scanner
```

Then ask in natural language:
> Verify whether https://some-gateway.com/v1 is really gpt-4o. My key is
> in env var OPENAI_API_KEY.

**Mode B · raw stdio MCP** (for debugging; no agent needed):

```bash
export APIGUARD_FINGERPRINT_DIR=$(pwd)/fingerprints
cat <<'EOF' | uv run api-key-scanner-mcp 2>/dev/null
{"jsonrpc":"2.0","id":1,"method":"initialize","params":{"protocolVersion":"2024-11-05","capabilities":{},"clientInfo":{"name":"x","version":"0"}}}
{"jsonrpc":"2.0","method":"notifications/initialized"}
{"jsonrpc":"2.0","id":2,"method":"tools/call","params":{"name":"verify_gateway","arguments":{"endpoint_url":"https://api.openai.com/v1","claimed_model":"gpt-4o","api_key_env_var":"OPENAI_API_KEY","budget":"cheap"}}}
EOF
```

**Mode C · Python** (for scripting / tests):

```python
import asyncio
from dotenv import load_dotenv
load_dotenv()                         # required for SSL_CERT_FILE etc to propagate

from api_key_scanner.server import verify_gateway

async def main():
    verdict = await verify_gateway(
        endpoint_url="https://api.openai.com/v1",
        claimed_model="gpt-4o",
        api_key_env_var="OPENAI_API_KEY",
        budget="cheap",
    )
    print(verdict["verdict"], verdict["trust_score"])

asyncio.run(main())
```

---

## How it works

```
┌─────────────────────────────────────────────────────────────┐
│  Claude Code / opencode / Cursor / any MCP client           │
│         ↓ spawn stdio subprocess                             │
│  api-key-scanner-mcp  (local Python, reads your .env key)   │
│         ↓ run probes                                         │
│  Target gateway  (the one you're verifying)                  │
│         ↓ collect responses                                  │
│  D1 LLMmap  +  D2 MET (MMD²)  +  D4 Metadata                │
│         ↓ Bayesian fusion                                    │
│  Verdict { trust_score, verdict, detectors, evidence }       │
└─────────────────────────────────────────────────────────────┘
```

Three complementary detectors run locally:

- **D1 · LLMmap** — char-n-gram cosine nearest-neighbor classification
  against reference fingerprints. Catches cross-family substitution
  (Opus→Llama, GPT→Claude, etc.). Based on [LLMmap (USENIX
  Sec'25)](https://arxiv.org/abs/2407.15847).
- **D2 · Model Equality Testing** — biased MMD² two-sample test with a
  string kernel + permutation p-values. Catches distribution drift. Based
  on [MET (ICLR'25)](https://arxiv.org/abs/2410.20247).
- **D4 · Metadata** — `system_fingerprint` stability, tokenizer consistency,
  latency envelope. Catches cache-replay and backend swaps.

A Bayesian fusion (`prior=0.85`, weights `d1=0.45, d2=0.40, d4=0.15`)
produces a single `trust_score ∈ [0, 1]` and a verdict label:

- `>= 0.90` → `ok`
- `0.70 – 0.90` → `suspicious`
- `< 0.70` → `likely_substituted`
- when detectors degrade → `inconclusive`

---

## Environment variables

| Name | Purpose | Default | Used by |
|---|---|---|---|
| `OPENAI_API_KEY` (or your name) | Gateway API key — value read via `os.environ` | — | bootstrap, MCP |
| `OPENAI_BASE_URL` | OpenAI-compat endpoint for bootstrap | — | bootstrap only |
| `MODEL_ID` | Model name the vendor accepts | — | bootstrap only |
| `APIGUARD_FINGERPRINT_DIR` | Directory containing `<vendor>/<model>.jsonl` files | — | MCP server |
| `APIGUARD_INSECURE_SSL` | `1` to skip SSL verification (self-signed internal deploys) | off | gateway client |
| `APIGUARD_DOTENV_PATH` | Absolute path; MCP loads this `.env` at startup | off | MCP server |
| `APIGUARD_LOG_LEVEL` | `DEBUG` to log network retries / errors to stderr | `INFO` | MCP server |

For Claude Code, wire everything via `.mcp.json`'s `env` block — the MCP
subprocess does not inherit your shell env when the agent is launched as
a GUI app.

---

## Phase 1 scope

**✅ Covered**

| ID | Attack | Confidence |
|---|---|---|
| A1 | Cross-family substitution (Opus → Llama, etc.) | high |
| A5 | System-prompt tampering / injection | medium |
| A7 | Cached-replay static answers | high |

**⚠️ Partial**

- A2: Same-family downgrade (Opus → Sonnet → Haiku) — coarse-grained
  detection only; hardened in Phase 2.

**❌ Explicitly out of scope in Phase 1**

- A3: Quantization substitution (bf16 → int4) — academic result shows
  black-box detection ≈ random.
- A4: Minor-version substitution (same model, different date)
- A6: Output post-processing (watermark stripping, rewriting)
- A8: Adaptive routing (real model on probes, cheap model on real traffic)

---

## Privacy model

- **Your API key**: read locally from `os.environ[var_name]`. Never
  logged, never sent anywhere except the target gateway you specify.
- **Gateway responses**: analyzed in-process on your machine. Never
  uploaded.
- **What leaves your machine**: outbound HTTPS only to (1) the target
  gateway you named, (2) GitHub Releases (for probe sets and
  fingerprints), and (3) HuggingFace (optional mirror).
- **No backend, by design.** There is nowhere for us to log your traffic
  even if we wanted to.

The `OpenAICompatClient` also scrubs raw API-key substrings from any
response body or error it surfaces as `ProbeResponse.error` — so a
misbehaving backend that echoes the `Authorization` header cannot leak
your key via the verdict JSON.

---

## Development

```bash
uv sync --all-extras
uv run pytest                           # 88 tests
uv run ruff check src tests scripts
uv run api-key-scanner-mcp              # run the MCP server over stdio
```

### Running the batch collection pipeline

```bash
# 1. Edit models.yaml (list of models to collect fingerprints for)
# 2. Collect — keys come from .env or shell exports
uv run python scripts/collect_all.py --out ./fingerprints --fail-on-empty
# 3. Build the MANIFEST.json
uv run python scripts/generate_manifest.py ./fingerprints
# 4. Validate schema + alignment + manifest integrity
uv run python scripts/validate_fingerprints.py ./fingerprints
```

In CI this is automated weekly via
`.github/workflows/weekly-fingerprint-collect.yml`, with Sigstore keyless
signing of the `MANIFEST.json` before publishing to a GitHub Release.

---

## Status and roadmap

🚧 **Alpha (v0.1.x).** The MCP tool interface and Verdict schema are
stable; fingerprint data pipeline and CI landed; PyPI / plugin
marketplace publish pending the first tagged release.

- **Phase 1** (this release): local verification against signed
  fingerprints, OpenAI-compat gateways, 12 models cataloged.
- **Phase 2**: same-family downgrade detection, secret/dynamic canary
  probes, Anthropic/Google native protocol support.
- **Phase 3**: TEE-attested gateway option for "zero-trust"
  per-request verification.

---

## License

- **Code**: [Apache-2.0](LICENSE)
- **Fingerprint data** (published as GitHub Release assets): CC-BY-4.0

## Disclaimer

Verdicts are statistical inferences, not legal determinations. A low
trust score means *"the gateway's responses are inconsistent with the
reference distribution we collected from the vendor directly"* — not
definitive proof of fraud. Treat any `likely_substituted` verdict as a
signal to investigate further, not a final judgment.
