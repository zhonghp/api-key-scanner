# api-key-scanner

Verify whether an LLM API gateway (or 中转站 / third-party proxy) is
actually serving the model it claims — without ever handing your API
key to anyone else.

**[简体中文](./README.zh-CN.md)**

## How it works

You point the tool at an endpoint, tell it what model the gateway
claims to serve, and name the environment variable where your gateway
API key lives. It runs a small probe set against the endpoint, compares
the responses to publicly-signed reference fingerprints of real vendor
models, and returns a trust score.

Everything runs on your machine. Your API key is read from a local env
var (never accepted in chat, never sent anywhere except the gateway you
named). Reference fingerprints are downloaded from our GitHub Releases
and Sigstore-verified before use — if the signature doesn't match the
identity of the GitHub Actions workflow that produced them, the tool
refuses the data and returns `inconclusive`.

The tool ships two pieces: an MCP server (on PyPI) and a skill that
teaches the agent when and how to call the server's `verify_gateway`
tool. Both pieces are platform-neutral; installation just differs per
host.

## Prerequisites

The MCP server runs through [`uvx`](https://docs.astral.sh/uv/), which
fetches and isolates the Python package on every launch. If you don't
already have `uv`, install it once:

```bash
# macOS
brew install uv

# macOS / Linux (no Homebrew)
curl -LsSf https://astral.sh/uv/install.sh | sh

# Windows (PowerShell)
irm https://astral.sh/uv/install.ps1 | iex
```

After install, `uvx --version` should print a version. Restart your
terminal (or your MCP client) if it doesn't show up yet.

## Installation

### Claude Code

In Claude Code:

```
/plugin marketplace add zhonghp/api-key-scanner
/plugin install api-key-scanner@zhonghp-api-key-scanner
```

That's everything — the plugin bundles the MCP server config and the
skill. The server auto-downloads signed reference fingerprints on first
use; no manual bootstrap.

### OpenClaw

Two steps.

**1. Add the MCP server to your OpenClaw config:**

```jsonc
{
  "mcp": {
    "servers": {
      "api-key-scanner": {
        "command": "uvx",
        "args": [
          "--refresh-package", "api-key-scanner-mcp",
          "api-key-scanner-mcp@latest"
        ]
      }
    }
  }
}
```

**2. Install the skill so OpenClaw knows when to invoke it:**

```bash
mkdir -p ~/.openclaw/skills/api-verify
curl -fsSL \
  https://raw.githubusercontent.com/zhonghp/api-key-scanner/main/skills/api-verify/SKILL.md \
  -o ~/.openclaw/skills/api-verify/SKILL.md
```

Restart OpenClaw. That's it.

### Other MCP clients (Cursor, Continue, Zed, Claude Desktop, …)

Any MCP client works — the server is just a standard stdio JSON-RPC
server. Point your client's MCP config at `uvx --refresh-package
api-key-scanner-mcp api-key-scanner-mcp@latest` and you're done. Skills
are Claude Code / OpenClaw-specific; on other clients the user just
mentions the `verify_gateway` tool directly.

## Supplying your gateway key

The server reads your gateway's API key from the local environment.
Put it in `~/.api-key-scanner/.env`:

```bash
mkdir -p ~/.api-key-scanner
cat > ~/.api-key-scanner/.env <<'EOF'
MY_GATEWAY_KEY=sk-your-gateway-key
EOF
```

The server auto-loads this file at startup. A shell `export` works too,
but only if you set it *before* launching the MCP client — most clients
(Claude Code, OpenClaw, etc.) snapshot env at launch.

## Using it

Ask in natural language:

> 帮我验证下 `https://api.example.com/v1` 提供的 gpt-4o 模型是不是
> 真的。我的 key 放在 `MY_GATEWAY_KEY` 环境变量里。

(Phrase the question as "is the model at this URL genuine?", not "is
this URL gpt-4o?" — the former makes the authenticity question clear.)

You get a verdict with:

- `trust_score` — 0.0 to 1.0
- `verdict` — `ok` / `suspicious` / `likely_substituted` / `inconclusive`
- `confidence` — `low` / `medium` / `high`
- Detector breakdown (`d1_llmmap`, `d2_met`, `d4_metadata`)

Cutoffs:

- `>= 0.90` → responses are consistent with the claimed model
- `0.70 – 0.90` → drift worth a deeper probe
- `< 0.70` → the model behind the endpoint likely isn't what's claimed
- `inconclusive` → the verdict explains which step failed

Budget: `cheap` (13 probes), `standard` (58, default), `deep` (92).
Higher = higher confidence, more calls on your gateway.

## Which models can it verify?

Only models for which we've published a signed reference fingerprint.
The current coverage — with canonical IDs, vendor model names, and the
source endpoint each fingerprint was collected from — is tracked in
**[SUPPORTED_MODELS.md](./SUPPORTED_MODELS.md)** (Chinese-only — the
table itself is language-neutral). If the model you care about isn't
listed there, `verify_gateway` will return `inconclusive` — the tool
doesn't guess.

For the live list at runtime, just ask in chat:

> What models does api-key-scanner currently support?

The agent calls `list_supported_models`, which reads the latest
release's `MANIFEST.json` directly — this will always be accurate even
if `SUPPORTED_MODELS.md` hasn't been updated yet.

## What it catches

- **Cross-family substitution** — endpoint claims gpt-4o but serves
  Llama / Qwen / Claude / Gemini.
- **Cached replay** — endpoint returns canned vendor-style answers
  instead of a real model call.
- **System-prompt tampering** — endpoint silently injects a hidden
  system prompt that changes behavior.

## What it doesn't catch (yet)

- **Same-family downgrade** — Opus → Sonnet → Haiku,
  gpt-4o → gpt-4o-mini. We sometimes flag `suspicious` but don't
  commit to a verdict.
- **Quantization** — same model at a lower precision. Academic
  results show black-box detection is ≈ random.
- **Adaptive routing** — the gateway plays real-model to "identify
  yourself" probes and cheap-model to everything else. Needs an
  out-of-band trust anchor to solve.

Treat any `likely_substituted` as a signal to dig deeper, not as proof
of fraud. Trust scores are statistical, not legal.

## Updates

| Something updates | What you need to do |
|---|---|
| New weekly fingerprint snapshot | Nothing — the server checks GitHub on each startup and auto-upgrades. |
| New MCP server version | Restart your MCP client; `uvx` pulls `@latest`. |
| Plugin manifest or skill changes | Claude Code: `/plugin marketplace update zhonghp-api-key-scanner`, then restart. OpenClaw: re-copy `SKILL.md` (see install). |
| Cache problems — old version won't let go | `uv cache clean api-key-scanner-mcp`, then restart. |

## Privacy

- **Your API key** is read locally from your `.env` or environment.
  Never logged, never sent anywhere except the target gateway you
  specified. Key substrings are scrubbed from any error that surfaces
  in verdicts.
- **Gateway responses** are analyzed in-process. Nothing is uploaded.
- **Outbound network from this tool** is limited to (1) the gateway
  URL you provided and (2) `github.com/zhonghp/api-key-scanner`
  releases for the signed reference data.
- **No backend, by design.** There's nowhere for us to log your
  traffic.

## Reference-data integrity

Fingerprint snapshots are signed with [Sigstore](https://www.sigstore.dev/)
keyless OIDC. The signing identity is bound to our weekly GitHub Actions
workflow. The server refuses to load a release whose signature identity
doesn't match — it degrades to `inconclusive` rather than return a
verdict based on unverified reference data.

## Air-gapped use

Download a fingerprint release on another machine, copy it over, then
point the server at the local directory:

```bash
export APIGUARD_FINGERPRINT_DIR=/path/to/fingerprint-YYYY-MM-DD
```

(Set this in `~/.api-key-scanner/.env` so the MCP client's subprocess
picks it up.) The Sigstore check is still enforced; you'll need the
`MANIFEST.json.sigstore.json` in the directory.

## License

- **Code**: [Apache-2.0](LICENSE)
- **Fingerprint data** (GitHub Release assets): CC-BY-4.0
