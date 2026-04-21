---
description: |
  Verify whether an LLM API gateway / middleman endpoint is actually serving
  the claimed model. Trigger when the user asks to 验证 / 鉴别 / check / verify
  an API endpoint, 中转站, or gateway; or suspects that an endpoint isn't
  really serving the claimed model. Uses the api-key-scanner MCP tool
  `verify_gateway`. The user's API key stays on their machine.
---

# When to trigger

Invoke when the user's request matches any of:
- "帮我验证 / 鉴别 / 检查 / 看看 这个 API / endpoint / 中转站 / gateway"
- "这个接口 / 这个地址 是不是真的 Opus / GPT-4o / ..."
- "verify / check / audit" an LLM API endpoint
- Questions about whether a gateway has been substituting models

# Privacy guardrail — READ FIRST

**NEVER ask the user to paste their API key into chat.** The key must stay
in their local shell environment (e.g. a `.env` file or `export`).

Ask only for the **NAME of the env var** holding the key (e.g. `MY_KEY`,
not the value). If the user volunteers the key value, tell them to unset
it from the conversation and provide only the variable name instead.

When calling `verify_gateway`, pass `api_key_env_var=<variable name>`. The
MCP server reads the key locally and never sends it anywhere except the
user's target gateway.

# Workflow

1. Collect three things from the user (ask if not provided):
   - `endpoint_url`: the gateway endpoint, e.g. `https://some.com/v1`
   - `claimed_model`: e.g. `claude-opus-4`, `gpt-4o`
   - `api_key_env_var`: the NAME of the env var, e.g. `MY_KEY`

2. (Optional) Ask about budget:
   - `cheap` (~$0.05): 8 probes, quick spot-check
   - `standard` (~$0.5, default): 30 probes, reasonable confidence
   - `deep` (~$3): 100 probes, high confidence

3. Call MCP tool `verify_gateway` with these parameters.

4. Interpret the returned Verdict in natural language:
   - `trust_score >= 0.90`: gateway looks consistent with the claimed model
   - `0.70 <= trust_score < 0.90`: suspicious, recommend deeper probe
   - `trust_score < 0.70`: likely substituted — explain which detectors fired
   - `verdict == "inconclusive"`: something went wrong (network, env var,
     rate limit); explain and suggest how to retry

5. Always surface:
   - The `disclaimer` field (Phase 1 limitations)
   - Approximate cost (`cost_usd_estimate`)
   - Which detectors contributed most to the verdict

# Reference data — no pre-setup required

Users do not need to bootstrap fingerprints manually. On first use, the
MCP server fetches the latest signed `fingerprint-*` release from
`https://github.com/zhonghp/api-key-scanner/releases`, verifies its
Sigstore signature against our weekly workflow's identity, and caches
the verified data under `~/.cache/api-key-scanner/`. First call takes
2-5 seconds longer; subsequent calls are cached.

If a user's machine cannot reach GitHub, point `APIGUARD_FINGERPRINT_DIR`
at a pre-downloaded release directory.

# Scope disclosure

Before concluding, remind the user that Phase 1 reliably detects
cross-family substitution (Opus → Llama) but does **NOT** reliably detect
same-family downgrade (Opus → Sonnet), quantization, or adaptive routing.
A high trust score does not rule out these harder attacks.

# Example turn

User: "帮我验证下 https://foo.com/v1 是不是真的 claude-opus-4"

You: "好，我需要三个信息：(1) 端点 URL ✓ 已给 (2) 宣称的模型 ✓ claude-opus-4
     (3) 你的 gateway key 放在哪个环境变量里？比如 `MY_KEY`。**不要**把 key
     本身粘进来——变量名就够了，key 留在你本地。"

User: "key 在 FOO_KEY"

You: [call verify_gateway(endpoint_url="https://foo.com/v1",
      claimed_model="claude-opus-4", api_key_env_var="FOO_KEY")]
     [interpret and present the Verdict]
