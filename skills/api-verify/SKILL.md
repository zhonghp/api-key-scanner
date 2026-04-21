---
name: api-verify
description: |
  Verify whether an LLM API gateway, 中转站, or third-party proxy is actually
  serving the model it claims, rather than silently routing to a cheaper
  substitute. Use this skill whenever the user asks to 验证 / 鉴别 / 检查 /
  审计 an LLM API endpoint, 中转站, gateway, or API reseller; when they
  suspect a model has been swapped, downgraded, or replaced behind an
  endpoint; or when they've bought API credits/keys from a middleman and
  want to confirm what the endpoint is actually running. Calls the
  `verify_gateway` MCP tool from the api-key-scanner plugin. The user's API
  key never leaves their machine. Do NOT trigger for generic REST API
  testing, HTTP health checks, code review, or unit tests — only for
  claims of LLM model identity.
---

# Privacy rule — read first

**Never accept a raw API key in chat.** Ask for the NAME of the env var
holding the key (e.g. `MY_KEY`), not the value. If the user pastes the
key, tell them to edit or clear the message and send only the variable
name. Pass it through as `api_key_env_var=<name>` when calling
`verify_gateway`; the MCP server reads the key locally and sends it
only to the target gateway.

If the server can't find the key after the user `export`ed it in a
terminal, it's because the MCP client snapshotted env at spawn time.
Fix: write the key into `~/.api-key-scanner/.env` (auto-loaded at
startup) and restart the MCP client.

# Workflow

Collect `endpoint_url`, `claimed_model`, and `api_key_env_var` (the
variable name, never the value). Optionally set `budget`: `cheap` (13
probes, spot-check), `standard` (58, default), or `deep` (92, high
confidence).

If you're not sure whether `claimed_model` is one the tool has
fingerprint data for (vendors ship new models faster than the
fingerprint release), call `list_supported_models` first and check.
When the model isn't covered, tell the user which ones are — the
verdict would otherwise come back `inconclusive` without a usable
signal.

Call `verify_gateway`. Then interpret the returned Verdict:

- `trust_score >= 0.90` → consistent with the claimed model
- `0.70 – 0.90` → suspicious; recommend re-running with `deep`
- `< 0.70` → likely substituted; name which detectors fired, and if
  D1 produced a `top_guess`, mention what model the responses actually
  look like
- `verdict == "inconclusive"` → the `disclaimer` field names the step
  that failed (network / signature / model-not-covered / missing key /
  rate limit); if it's "model-not-covered", tell the user what is
  covered

Always surface the `disclaimer` and `num_probes_failed` so the user can
judge how reliable the verdict is.

# Scope — be honest about limits

Phase 1 reliably catches cross-family substitution (Opus → Llama),
cached replay, and system-prompt tampering. It does NOT reliably catch
same-family downgrade (Opus → Sonnet → Haiku), quantization, or adaptive
routing. A high trust score is evidence, not proof — say so.

# Reference data

On first use, the server downloads and Sigstore-verifies the latest
`fingerprint-*` GitHub Release, caching under `~/.cache/api-key-scanner/`.
Nothing to bootstrap manually. Air-gapped machines: set
`APIGUARD_FINGERPRINT_DIR` to a pre-downloaded release directory.

# Example

User: "帮我验证下 https://foo.com/v1 提供的 claude-opus-4 模型是不是真的"

You: [optionally call list_supported_models to confirm claude-opus-4 is
      in the current release]
     "好。还需要你告诉我 key 放在哪个环境变量里（变量名就行，**不要**贴
     key 本身）。比如 `FOO_KEY`。"

User: "FOO_KEY"

You: [call verify_gateway(endpoint_url="https://foo.com/v1",
      claimed_model="claude-opus-4", api_key_env_var="FOO_KEY")]
     [interpret the Verdict; surface trust_score, top detector finding,
      disclaimer, scope caveats]
