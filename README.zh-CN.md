# api-key-scanner

> 验证 LLM API gateway 是不是真的在服务它宣称的那个模型。
> 你的 API key 不会离开你的机器。

**[English](./README.md)** · 参与贡献请看 **[CONTRIBUTING.md](./CONTRIBUTING.md)**。

`api-key-scanner` 是一个 [Claude Code Plugin](https://code.claude.com/docs/en/plugins)，
通过本地 MCP server 提供 `verify_gateway` 工具。用自然语言发起请求，
它会对你指定的 endpoint 跑一组 probe，拿回来的响应跟我们公开签名的
厂商真实指纹对比，给出一个 trust score。所有计算都在你机器上完成；
对外的网络请求只有两个方向：(1) 你要验证的 gateway，(2) 我们 GitHub
Releases 上的指纹数据。

---

## 安装

在 Claude Code 里：

```
/plugin marketplace add zhonghp/api-key-scanner
/plugin install api-key-scanner@zhonghp-api-key-scanner
```

这就装完了。第一次使用时 server 会自动从 GitHub Releases 拉取并本地验签
指纹数据——不需要任何手动准备。

## 怎么传入 gateway API key

MCP server 需要读你 gateway 的 API key 去调 endpoint。**绝不要**把 key
贴进聊天。把 key 放进 `~/.api-key-scanner/.env`：

```bash
mkdir -p ~/.api-key-scanner
cat > ~/.api-key-scanner/.env <<'EOF'
MY_GATEWAY_KEY=sk-你的-gateway-key
EOF
```

Server 启动时会自动加载这个文件。用 shell `export` 也行，但必须在
**启动 Claude Code 之前**设好——Claude Code 在启动时快照一次环境变量，
之后 terminal 里的 export 传不到 MCP 子进程。

## 怎么用

直接自然语言问：

> 帮我验证下 `https://api.example.com/v1` 是不是真的 gpt-4o，
> 我的 key 在 `MY_GATEWAY_KEY` 环境变量里。

返回的 verdict 大概长这样：

```
verdict:       ok（可信）| suspicious（可疑）|
               likely_substituted（很可能被换模型）| inconclusive（无法判定）
trust_score:   0.0 – 1.0
confidence:    low | medium | high
detectors:
  d1_llmmap:     分数、最佳猜测模型
  d2_met:        分数、p_value
  d4_metadata:   分数、备注
```

三档预算：`cheap`（约 13 个 probe）、`standard`（约 58 个，默认）、
`deep`（约 92 个）。预算越高置信度越高，但打到 gateway 的请求也越多。
工具不会给 dollar 数字——不同厂商、不同定价档差异太大，实际花了多少
以你 provider 账单为准。

**Trust score 分界：**

- `>= 0.90` → `ok`：响应跟厂商真实指纹吻合
- `0.70 – 0.90` → `suspicious`：有一些漂移，建议跑 `deep` 再看一次
- `< 0.70` → `likely_substituted`：endpoint 背后的模型跟宣称的不一致
- `inconclusive` → probe 跑挂了（网络/key/限流），verdict 里会说明原因

## 能抓什么，抓不到什么

**可靠能抓：**

- **跨家族替换**：endpoint 宣称 `gpt-4o`，实际在跑 Llama / Qwen /
  Claude / Gemini。
- **缓存回放**：endpoint 直接返回事先准备好的"厂商风格"答案，根本
  没调真模型。
- **System prompt 篡改**：endpoint 悄悄注入一段 system prompt 改变模型
  行为。

**抓不可靠：**

- **同家族降档**：Opus → Sonnet → Haiku、GPT-4o → GPT-4o-mini。我们
  有时会给出 `suspicious`，但不会下定论。
- **量化降级**：同模型 bf16 → int4。学术结论是黑盒检测基本接近随机。
- **动态路由**：gateway 对"自我介绍"类 probe 用真模型，对真实业务
  流量用廉价模型。本质上需要额外的信任锚才能解决。

看到 `likely_substituted` 要把它当成**开始调查**的信号，不是判定欺诈
的证据。trust score 是统计推断，不是法律结论。

## 更新相关

| 什么变了 | 你要做啥 |
|---|---|
| 指纹库出了新一期 | **啥也不用**。Server 每次启动都会检查 GitHub 有没有更新的签名 tag，自动升级。 |
| MCP server 新版本（bug fix / 新特性）| **重启 Claude Code**。uvx 会自动拉 `@latest`。 |
| Plugin 本身改了（`.mcp.json` / skill 描述）| `/plugin marketplace update zhonghp-api-key-scanner`，再重启 Claude Code。（不常发生。）|
| 缓存问题——死活不升级 | `uv cache clean api-key-scanner-mcp`，然后重启 Claude Code。 |

## 隐私

- **你的 API key**：从 `.env` 或环境变量本地读。绝不打日志，绝不发到
  除了你指定的 gateway 以外的任何地方。verdict 里如果出现任何报错
  字符串，key 子串都会被擦掉。
- **Gateway 响应**：全部在你机器的进程里分析完，绝不上传。
- **本工具的外连**：只有两条路径——(1) 你自己给的 gateway URL；
  (2) `github.com/zhonghp/api-key-scanner` 的 release 资源。
- **没有后端，故意的**。即使我们想记录你的流量也无处可记。

## 参考数据的可信度

我们发布的指纹快照用 [Sigstore](https://www.sigstore.dev/) keyless OIDC 签名，
证书身份绑定到我们那个 weekly GitHub Actions workflow。Server 拒绝加载
签名身份不匹配的 release——宁可给出 `inconclusive`，也不会基于未验证的
参考数据出 verdict。

## 内网/离线场景

如果你的机器访问不了 `github.com`，另一台能联网的机器下载指纹 release，
拷贝过来，让 server 用本地目录：

```bash
export APIGUARD_FINGERPRINT_DIR=/path/to/fingerprint-YYYY-MM-DD
```

（写进 `~/.api-key-scanner/.env`，Claude Code 的 MCP 子进程才读得到。）
Sigstore 校验仍然强制执行；目录里得有 `MANIFEST.json.sigstore.json`。

---

## 许可证

- **代码**：[Apache-2.0](LICENSE)
- **指纹数据**（GitHub Release 资产）：CC-BY-4.0

## Roadmap

- **Phase 1**（当前 alpha v0.1.x）：跨家族替换、缓存回放、system prompt
  篡改；仅限 OpenAI-compat gateway。
- **Phase 2**：同家族降档检测、动态 canary probe、Anthropic / Google 原生
  协议支持。
- **Phase 3**：TEE 远程证明 gateway 方案，真正做到每请求级别的
  "零信任"验证。
