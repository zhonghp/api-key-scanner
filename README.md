# api-key-scanner

> Verify whether an LLM API gateway is actually serving the claimed
> model. Your API key never leaves your machine.

**[简体中文](./README.zh-CN.md)** · Contributing? See **[CONTRIBUTING.md](./CONTRIBUTING.md)**.

`api-key-scanner` is a [Claude Code Plugin](https://code.claude.com/docs/en/plugins)
that adds a `verify_gateway` tool via a local MCP server. Ask it in
natural language, it runs a probe set against the endpoint you name,
compares the responses to publicly-signed reference fingerprints of
real vendor models, and returns a trust score. All computation happens
on your machine; the only outbound traffic is (1) to the gateway
you're checking and (2) to GitHub Releases for the reference data.

---

## Install

In Claude Code:

```
/plugin marketplace add zhonghp/api-key-scanner
/plugin install api-key-scanner@zhonghp-api-key-scanner
```

That's everything. The server auto-downloads signed reference
fingerprints from our GitHub Releases the first time you use it — no
manual setup.

## Supplying your gateway API key

The MCP server needs to read your gateway's API key to call the
endpoint. It does **not** accept keys in chat. Put your key in
`~/.api-key-scanner/.env`:

```bash
mkdir -p ~/.api-key-scanner
cat > ~/.api-key-scanner/.env <<'EOF'
MY_GATEWAY_KEY=sk-your-gateway-key
EOF
```

The server auto-loads this file on startup. Shell `export` works too,
but only if you set it **before** launching Claude Code (Claude Code
snapshots env at launch and won't see later `export`s).

## Use it

Just ask in natural language:

> 帮我验证下 `https://api.example.com/v1` 是不是真的 gpt-4o，
> 我的 key 在 `MY_GATEWAY_KEY` 环境变量里。

The tool returns a verdict like:

```
verdict:       ok | suspicious | likely_substituted | inconclusive
trust_score:   0.0 – 1.0
confidence:    low | medium | high
detectors:
  d1_llmmap:     score, top_guess
  d2_met:        score, p_value
  d4_metadata:   score, notes
```

Three budget levels available: `cheap` (~13 probes), `standard`
(~58 probes, default), `deep` (~92 probes). Higher budget = higher
confidence, more calls on your gateway. The tool doesn't report a
dollar figure — costs vary too widely across vendors and pricing
tiers; check your provider's billing page.

**Trust score cutoffs:**

- `>= 0.90` → `ok`: responses match the vendor's real fingerprint
- `0.70 – 0.90` → `suspicious`: some drift, worth a deeper probe
- `< 0.70` → `likely_substituted`: the model behind the endpoint
  doesn't match what's claimed
- `inconclusive` → probes failed (network / bad key / rate limit);
  verdict explains which

## What it catches (and what it doesn't)

**Catches reliably:**

- **Cross-family substitution**: endpoint claims `gpt-4o` but is
  actually serving Llama / Qwen / Claude / Gemini.
- **Cached replay**: endpoint returns canned "vendor-style" answers
  instead of a real model call.
- **System-prompt tampering**: endpoint injects a hidden system
  prompt that changes behavior.

**Does NOT reliably catch:**

- **Same-family downgrade**: Opus → Sonnet → Haiku, GPT-4o → GPT-4o-mini.
  We surface `suspicious` sometimes but don't commit to a verdict.
- **Quantization**: bf16 → int4 of the same model. Academic result
  shows black-box detection is ≈ random.
- **Adaptive routing**: a gateway that returns real-model answers to
  "identify yourself" probes but cheap-model answers to everything
  else. Fundamentally unsolved without an out-of-band trust anchor.

Treat any `likely_substituted` verdict as a signal to investigate —
not as proof of fraud. Trust scores are statistical inferences.

## Updates

| Something updates | What you need to do |
|---|---|
| New weekly fingerprint snapshot | Nothing. Server checks GitHub on each startup and auto-upgrades to the newest signed tag. |
| New MCP server version (bug fix / feature) | Restart Claude Code. `uvx` auto-refreshes to `@latest`. |
| Plugin manifest changes (`.mcp.json` / skill wording) | Run `/plugin marketplace update zhonghp-api-key-scanner` in Claude Code, then restart. (Rare.) |
| Cache problems — old version won't let go | `uv cache clean api-key-scanner-mcp`, then restart Claude Code. |

## Privacy

- **Your API key**: read locally from your `.env` or environment.
  Never logged, never sent anywhere except the target gateway you
  specified. Key substrings are scrubbed from any error messages
  that surface in verdicts.
- **Gateway responses**: analyzed entirely in-process. Never uploaded.
- **Outbound network from this tool**: only (1) to the gateway URL
  you provided, and (2) to `github.com/zhonghp/api-key-scanner`
  releases, for the signed reference data.
- **No backend, by design.** There is nowhere for us to log your
  traffic even if we wanted to.

## Reference data integrity

The fingerprint snapshots we publish are signed with
[Sigstore](https://www.sigstore.dev/) keyless OIDC, with cert identity
bound to our weekly GitHub Actions workflow. The server refuses to
load a release whose signature doesn't match our workflow identity —
the tool degrades to `inconclusive` rather than return a verdict based
on unverified reference data.

## Air-gapped / offline use

If your machine cannot reach `github.com`, download a fingerprint
release manually on another machine, copy it over, and point the
server at the local directory:

```bash
export APIGUARD_FINGERPRINT_DIR=/path/to/fingerprint-YYYY-MM-DD
```

(Set this in `~/.api-key-scanner/.env` so Claude Code's MCP subprocess
picks it up too.) The Sigstore check is still enforced; you'll need
the `MANIFEST.json.sigstore.json` in the directory.

---

## License

- **Code**: [Apache-2.0](LICENSE)
- **Fingerprint data** (published as GitHub Release assets): CC-BY-4.0

## Roadmap

- **Phase 1** (current, alpha v0.1.x): cross-family substitution,
  cached-replay, system-prompt tampering; OpenAI-compat gateways.
- **Phase 2**: same-family downgrade detection, secret/dynamic
  canary probes, Anthropic and Google native protocol support.
- **Phase 3**: TEE-attested gateway option for per-request
  "zero-trust" verification.
