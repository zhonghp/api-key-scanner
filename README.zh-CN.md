# api-key-scanner

> 鉴别一个 LLM API 中转站到底有没有在提供宣称的模型。你的 API key 不离开本机。

**[English](./README.md)**

`api-key-scanner` 是一个本地 [MCP](https://modelcontextprotocol.io) 服务，
以 [Claude Code Plugin](https://code.claude.com/docs/en/plugins) 形式发布。
它用精心设计的探针打目标网关，把响应和已知模型的签名参考指纹比对，输出
一个信任分——整个过程全在本机、不经任何后端、不带遥测。

## 为什么做这个

LLM 中转站（shadow API）市场在快速增长。[学术审计 17 家中转商发现
45.83% 未通过模型身份验证](https://arxiv.org/abs/2603.01919)。现有第
三方验证服务（如 hvoy.ai）要求用户把上游 API key 交给他们——这是巨大的
安全风险。

`api-key-scanner` 不拿你的 key 也能验：

- 🔒 **你的 API key 永远不离开本机。** MCP 服务通过"环境变量名"读取，
  而不是把 key 本身传来传去。
- 🧾 **零后端。** 探针和指纹从签名过的 GitHub Releases 来，没有要信任
  的服务器，也没有遥测。
- 📖 **完全开源。** Python 源码可审；指纹数据的 Sigstore keyless 签名
  可独立验证。

---

## 快速开始

### 前置条件

- Python ≥ 3.10 和 [uv](https://docs.astral.sh/uv/)
- 至少一个 LLM API key（既用来建参考指纹，也用来验证目标端点）

### 1. 安装

```bash
git clone https://github.com/zhonghp/api-key-scanner.git
cd api-key-scanner
uv sync --all-extras
```

### 2. 配置 `.env`

```bash
cp .env.example .env
# 编辑 .env 填真实值：
#   OPENAI_API_KEY=sk-...
#   MODEL_ID=gpt-4o
#   OPENAI_BASE_URL=https://api.openai.com/v1
```

### 3. 采一份参考指纹（每个模型一次即可）

```bash
uv run python scripts/bootstrap_fingerprints.py --budget cheap
# 产出 ./fingerprints/openai/gpt-4o.jsonl

# 再采一个模型，让 D1 有跨模型对照
MODEL_ID=gpt-4o-mini uv run python scripts/bootstrap_fingerprints.py --budget cheap
```

### 4. 验证网关——三种方式

**方式 A · Claude Code 插件（推荐）**

```text
/plugin marketplace add zhonghp/api-key-scanner
/plugin install api-key-scanner@zhonghp-api-key-scanner
```

装好后用自然语言：
> 帮我验证下 https://some-gateway.com/v1 是不是真的 gpt-4o，
> key 在环境变量 OPENAI_API_KEY 里

**方式 B · 原始 stdio MCP**（调试用，不需要 agent）：

```bash
export APIGUARD_FINGERPRINT_DIR=$(pwd)/fingerprints
cat <<'EOF' | uv run api-key-scanner-mcp 2>/dev/null
{"jsonrpc":"2.0","id":1,"method":"initialize","params":{"protocolVersion":"2024-11-05","capabilities":{},"clientInfo":{"name":"x","version":"0"}}}
{"jsonrpc":"2.0","method":"notifications/initialized"}
{"jsonrpc":"2.0","id":2,"method":"tools/call","params":{"name":"verify_gateway","arguments":{"endpoint_url":"https://api.openai.com/v1","claimed_model":"gpt-4o","api_key_env_var":"OPENAI_API_KEY","budget":"cheap"}}}
EOF
```

**方式 C · Python 脚本**（集成/测试用）：

```python
import asyncio
from dotenv import load_dotenv
load_dotenv()                         # 必要：让 SSL_CERT_FILE 等生效

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

## 工作原理

```
┌─────────────────────────────────────────────────────────────┐
│  Claude Code / opencode / Cursor / 任意 MCP 客户端           │
│         ↓ spawn stdio 子进程                                 │
│  api-key-scanner-mcp  （本地 Python，从你的 env 读 key）     │
│         ↓ 打探针                                             │
│  目标网关  （你要验证的那个 endpoint）                        │
│         ↓ 收集响应                                           │
│  D1 LLMmap  +  D2 MET (MMD²)  +  D4 Metadata                │
│         ↓ 贝叶斯融合                                         │
│  Verdict { trust_score, verdict, detectors, evidence }       │
└─────────────────────────────────────────────────────────────┘
```

三个互补的检测器全部在本机跑：

- **D1 · LLMmap** —— char n-gram 余弦最近邻，把响应分类到参考模型库。
  抓跨家族替换（Opus→Llama、GPT→Claude 等）。方法来自 [LLMmap (USENIX
  Sec'25)](https://arxiv.org/abs/2407.15847)。
- **D2 · 模型等价性检验** —— 带字符串核的 biased MMD² 两样本检验 + 置换
  p 值。抓分布漂移。方法来自 [MET (ICLR'25)](https://arxiv.org/abs/2410.20247)。
- **D4 · 元数据** —— `system_fingerprint` 稳定性、tokenizer 一致性、延迟
  分布。抓缓存回放和后端偷换。

贝叶斯融合（`prior=0.85`，权重 `d1=0.45, d2=0.40, d4=0.15`）产出单一
`trust_score ∈ [0, 1]` 和判定：

- `>= 0.90` → `ok`（可信）
- `0.70 – 0.90` → `suspicious`（可疑）
- `< 0.70` → `likely_substituted`（很可能被换模型）
- 当检测器退化 → `inconclusive`（无法判定）

---

## 指纹数据

第一次调用 `verify_gateway` 时，MCP server 会从
`github.com/zhonghp/api-key-scanner` 拉取最新的 `fingerprint-YYYY-MM-DD`
release，**在本地用 Sigstore 校验签名**（比对我们那个 weekly workflow
的身份），对每个 `.jsonl` 按 `MANIFEST.json` 做 sha256 校验，然后把
验证通过的文件缓存到 `~/.cache/api-key-scanner/fingerprints/<tag>/`
（通过 `platformdirs`）。同一进程内后续调用直接走缓存；新开的 server
进程会检查是否有更新的 tag，自动升级。

签名校验失败直接放弃本次 fetch——server 降级为 `inconclusive`，
绝不会用未验证的数据出 verdict。

离线/内网场景：自己下载一个 release 到本地，把 `APIGUARD_FINGERPRINT_DIR`
指过去，整个网络 fetch 就跳过了。

## 环境变量速查

| 名称 | 作用 | 默认 | 在哪用 |
|---|---|---|---|
| `OPENAI_API_KEY`（或你命名的变量）| 网关 API key 值，通过 `os.environ` 读 | — | bootstrap、MCP |
| `OPENAI_BASE_URL` | bootstrap 用的 OpenAI-compat endpoint | — | 仅 bootstrap |
| `MODEL_ID` | 供应商接受的模型名 | — | 仅 bootstrap |
| `APIGUARD_FINGERPRINT_DIR` | 显式指定本地指纹目录；跳过 GitHub fetch | — | MCP server |
| `APIGUARD_FINGERPRINT_RELEASE` | 钉到某个 `fingerprint-*` tag | 最新 | MCP server |
| `APIGUARD_FINGERPRINT_REPO` | 从哪个 `owner/repo` 拉 release | `zhonghp/api-key-scanner` | MCP server |
| `APIGUARD_FINGERPRINT_AUTO_UPDATE` | 设 `0` 则始终用本地缓存的 tag | `1` | MCP server |
| `APIGUARD_OFFLINE` | 设 `1` 完全不走网络；没缓存就失败 | `0` | MCP server |
| `APIGUARD_INSECURE_SSL` | 设 `1` 跳过 SSL 校验（自签证书内网场景） | 关 | gateway 客户端 |
| `APIGUARD_DOTENV_PATH` | 绝对路径；MCP 启动时加载该 `.env` | 关 | MCP server |
| `APIGUARD_LOG_LEVEL` | 设 `DEBUG` 把网络重试/错误打到 stderr | `INFO` | MCP server |

在 Claude Code 里，所有 env 必须通过 `.mcp.json` 的 `env` 块传进子进程——
子进程不会继承 GUI 启动的 agent 的 shell env。

---

## Phase 1 检测范围

**✅ 覆盖**

| ID | 攻击 | 置信度 |
|---|---|---|
| A1 | 跨家族替换（Opus → Llama 等） | 高 |
| A5 | system prompt 篡改 / 注入 | 中 |
| A7 | 缓存回放静态答案 | 高 |

**⚠️ 部分**

- A2：同家族降档（Opus → Sonnet → Haiku）——粗粒度可抓，Phase 2 加强。

**❌ Phase 1 明确不覆盖**

- A3：量化版替换（bf16 → int4）——学术结论：纯黑盒检测率 ≈ 随机猜
- A4：同模型细版本替换（同一模型不同日期）
- A6：输出后处理（水印剥离、改写）
- A8：自适应路由欺诈（对测试流量用真模型，对真实流量用便宜的）

---

## 隐私模型

- **你的 API key**：只在 `os.environ[变量名]` 这一步被本机读取。不进
  日志，不发往我们这边，只发给你指定的目标网关。
- **网关响应**：在你的进程里分析完就扔，不上传。
- **仅有的出站流量**：HTTPS 到 (1) 你指定的目标网关、(2) GitHub
  Releases（下载签名过的探针和指纹）、(3) HuggingFace（可选镜像）。
- **故意不搭任何后端。** 即使我们想收集也没处存。

`OpenAICompatClient` 还会把原始 API key 子串从任何响应/错误文本里剥掉再
返回——即使某个失控的后端把 `Authorization` header 原样回显到 error body，
你的 key 也不会通过 Verdict JSON 泄露出去。

---

## 开发

```bash
uv sync --all-extras
uv run pytest                           # 88 个测试
uv run ruff check src tests scripts
uv run api-key-scanner-mcp              # 通过 stdio 启动 MCP 服务
```

### 跑批量采集流水线

```bash
# 1. 编辑 models.yaml（要采集指纹的模型清单）
# 2. 采集——key 从 .env 或 shell export 拿
uv run python scripts/collect_all.py --out ./fingerprints --fail-on-empty
# 3. 生成 MANIFEST.json
uv run python scripts/generate_manifest.py ./fingerprints
# 4. 校验 schema + 对齐 + manifest 完整性
uv run python scripts/validate_fingerprints.py ./fingerprints
```

CI 里这套流程通过 `.github/workflows/weekly-fingerprint-collect.yml`
每周一 02:00 UTC 自动跑，对 `MANIFEST.json` 做 Sigstore keyless 签名
后发布到 GitHub Release。

---

## 当前状态与路线图

🚧 **Alpha（v0.1.x）。** MCP 工具接口和 Verdict schema 已稳定；指纹数据
管线和 CI 已就绪；PyPI / plugin marketplace 发布等首个版本 tag。

- **Phase 1**（本版本）：签名指纹本地验证、OpenAI-compat 网关、收录 12
  个模型。
- **Phase 2**：同家族降档检测、秘密/动态 canary 探针、支持 Anthropic /
  Google 原生协议。
- **Phase 3**：TEE attested 网关可选项，实现"零信任" per-request 验证。

---

## License

- **代码**：[Apache-2.0](LICENSE)
- **指纹数据**（以 GitHub Release assets 形式发布）：CC-BY-4.0

## 免责声明

Verdict 是统计推断，不是法律判决。一个低信任分的意思是"网关的响应和我们
从官方直连采到的参考分布不一致"，并非"造假实锤"。拿到
`likely_substituted` 结果应当作进一步调查的起点，而不是终点。
