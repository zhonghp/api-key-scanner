# 支持的模型

工具当前能对照签名参考指纹验证的模型列表。

- **最近更新**：2026-04-23
- **当前 release**：[`fingerprint-2026-04-23`](https://github.com/zhonghp/api-key-scanner/releases/tag/fingerprint-2026-04-23)
- **Probe 集版本**：`v2`（MANIFEST 里 `probe_set_version` 字段；客户端对不上会拒绝加载）
- **签名**：Sigstore keyless，绑定到本 repo 的 `weekly-fingerprint-collect.yml` workflow
- **自动维护**：本文件由 `weekly-fingerprint-collect.yml` 在每次指纹采集完成后自动重新生成并提交，不要手工编辑

## 覆盖情况

| Canonical ID | 厂商接受的 `model` 字段 | 采集 endpoint（我们从哪里拉的） | 样本数 | Probe 集 |
|---|---|---|---|---|
| `anthropic/claude-4.0-sonnet` | `claude-4.0-sonnet` | `https://aigateway.edgecloudapp.com/v1/f194fd69361cd590f1fa136c9c90eca1/senseai` | 18 | `v2` |
| `anthropic/claude-4.5-haiku` | `claude-4.5-haiku` | `https://aigateway.edgecloudapp.com/v1/f194fd69361cd590f1fa136c9c90eca1/senseai` | 18 | `v2` |
| `anthropic/claude-4.5-sonnet` | `claude-4.5-sonnet` | `https://aigateway.edgecloudapp.com/v1/f194fd69361cd590f1fa136c9c90eca1/senseai` | 18 | `v2` |
| `anthropic/claude-opus-4` | `claude-opus-4` | `https://aigateway.edgecloudapp.com/v1/f194fd69361cd590f1fa136c9c90eca1/senseai` | 18 | `v2` |
| `anthropic/claude-opus-4-5` | `claude-opus-4-5` | `https://aigateway.edgecloudapp.com/v1/f194fd69361cd590f1fa136c9c90eca1/senseai` | 17 | `v2` |
| `google/gemini-2.0-flash` | `gemini-2.0-flash` | `https://aigateway.edgecloudapp.com/v1/f194fd69361cd590f1fa136c9c90eca1/senseai` | 18 | `v2` |
| `google/gemini-2.5-flash` | `gemini-2.5-flash` | `https://aigateway.edgecloudapp.com/v1/f194fd69361cd590f1fa136c9c90eca1/senseai` | 18 | `v2` |
| `google/gemini-2.5-flash-lite` | `gemini-2.5-flash-lite` | `https://aigateway.edgecloudapp.com/v1/f194fd69361cd590f1fa136c9c90eca1/senseai` | 18 | `v2` |
| `google/gemini-3-flash-preview` | `gemini-3-flash-preview` | `https://aigateway.edgecloudapp.com/v1/f194fd69361cd590f1fa136c9c90eca1/senseai` | 18 | `v2` |
| `google/gemini-3.1-pro-preview` | `gemini-3.1-pro-preview` | `https://aigateway.edgecloudapp.com/v1/f194fd69361cd590f1fa136c9c90eca1/senseai` | 18 | `v2` |
| `openai/gpt-4-turbo` | `gpt-4-turbo` | `https://aigateway.edgecloudapp.com/v1/f194fd69361cd590f1fa136c9c90eca1/senseai` | 18 | `v2` |
| `openai/gpt-4.1` | `gpt-4.1` | `https://aigateway.edgecloudapp.com/v1/f194fd69361cd590f1fa136c9c90eca1/senseai` | 18 | `v2` |
| `openai/gpt-4.1-mini` | `gpt-4.1-mini` | `https://aigateway.edgecloudapp.com/v1/f194fd69361cd590f1fa136c9c90eca1/senseai` | 18 | `v2` |
| `openai/gpt-4o` | `gpt-4o` | `https://aigateway.edgecloudapp.com/v1/f194fd69361cd590f1fa136c9c90eca1/senseai` | 18 | `v2` |
| `openai/gpt-4o-mini` | `gpt-4o-mini` | `https://aigateway.edgecloudapp.com/v1/f194fd69361cd590f1fa136c9c90eca1/senseai` | 18 | `v2` |
| `openai/gpt-5.1` | `gpt-5.1` | `https://aigateway.edgecloudapp.com/v1/f194fd69361cd590f1fa136c9c90eca1/senseai` | 18 | `v2` |
| `openai/gpt-5.1-codex-max` | `gpt-5.1-codex-max` | `https://aigateway.edgecloudapp.com/v1/f194fd69361cd590f1fa136c9c90eca1/senseai` | 18 | `v2` |
| `openai/gpt-5.2-codex` | `gpt-5.2-codex` | `https://aigateway.edgecloudapp.com/v1/f194fd69361cd590f1fa136c9c90eca1/senseai` | 17 | `v2` |
| `openai/gpt-5.4` | `gpt-5.4` | `https://aigateway.edgecloudapp.com/v1/f194fd69361cd590f1fa136c9c90eca1/senseai` | 18 | `v2` |

"Canonical ID" 就是你调 `verify_gateway` 时 `claimed_model` 参数要填的
值。像 `gpt-5.4`、`gpt5.4`、`openai/gpt-5.4` 这些别名通过 `aliases.json`
都会归一到同一个 canonical ID。

"采集 endpoint" 是我们跑采集流水线时打的 gateway——这里拿到的响应就是
参考指纹，拿来跟你自己 endpoint 的响应比对。理想情况这里就是厂商直连 API
（参考数据就是 ground truth）；不是的话 notes 里会标注。

"Probe 集" 标识这份指纹是用哪个版本的 probe 集合（`llmmap_vN.jsonl` +
`met_vN.jsonl`）采的。客户端启动时 `APIGUARD_PROBE_SET_VERSION`（默认
`v2`）必须和这个字段一致，否则 `verify_gateway` 会 fail fast 返回
inconclusive——避免把 v1 probe 发出去、拿 v2 指纹对比这种错配。

## 为什么你的模型不在列表里

`verify_gateway` 只对表里的模型返回有意义的 verdict。如果你用其它
`claimed_model` 调它，会得到 `inconclusive` 以及说明"当前覆盖哪些"的
disclaimer。

- 厂商出了新模型——我们有能力采集、验证后才会加进去。需要的话
  [提个 issue](https://github.com/zhonghp/api-key-scanner/issues/new)
  告诉我们想要哪个
- 别名问题——你想验的模型可能用了你想不到的 canonical ID。直接在
  聊天里问：*"api-key-scanner 支持哪些模型？"* agent 会调
  `list_supported_models` 把实时列表打出来

## 运行时权威来源

运行时的权威来源始终是最新 `fingerprint-*` GitHub Release 里的
`MANIFEST.json`——`list_supported_models` 工具读的就是它。本文件只是一个
便于浏览的静态镜像，可能会在 release 刚发出来那几秒钟之内略微落后。
