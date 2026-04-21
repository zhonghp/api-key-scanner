# api-key-scanner

验证 LLM API gateway（中转站 / 第三方 proxy）是不是真的在跑它宣称的那个
模型——而且你的 API key 永远不会离开你自己的机器。

**[English](./README.md)**

## 怎么工作的

你把 endpoint 指给它，告诉它 gateway 宣称在跑什么模型，再告诉它你 key
放在哪个环境变量里。工具对 endpoint 跑一组 probe，把响应和我们公开签名
的厂商真实指纹对比，给出一个 trust score。

全部在你机器上计算。API key 从本地环境变量读取（绝不接受在聊天里贴 key，
也绝不发到除了你指定的那个 gateway 以外的任何地方）。指纹数据从我们的
GitHub Releases 拉下来，用 Sigstore 验签——签名身份如果跟我们那个 GitHub
Actions workflow 对不上，工具拒绝这份数据，返回 `inconclusive`。

工具由两部分组成：一个 MCP server（在 PyPI 上）和一个 skill，skill 负责
教 agent 什么时候、怎么调 `verify_gateway`。两部分都平台中立，只是不同
客户端的安装方式不同。

## 前置依赖

MCP server 通过 [`uvx`](https://docs.astral.sh/uv/) 启动——它会在每次
启动时拉取并隔离 Python 包。如果你机器上还没有 `uv`，先装一次：

```bash
# macOS
brew install uv

# macOS / Linux（没装 Homebrew）
curl -LsSf https://astral.sh/uv/install.sh | sh

# Windows（PowerShell）
irm https://astral.sh/uv/install.ps1 | iex
```

装完跑一下 `uvx --version` 应该能看到版本号。如果没反应，重启 terminal
（或重启 MCP 客户端）再试。

## 安装

### Claude Code

在 Claude Code 里：

```
/plugin marketplace add zhonghp/api-key-scanner
/plugin install api-key-scanner@zhonghp-api-key-scanner
```

到此结束——plugin 里面同时带了 MCP server 配置和 skill。server 第一次
使用时会自动下载签名过的指纹数据，无需任何手动初始化。

### OpenClaw

两步。

**1. 加 MCP server 到 OpenClaw config：**

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

**2. 装 skill，让 OpenClaw 知道什么时候调它：**

```bash
mkdir -p ~/.openclaw/skills/api-verify
curl -fsSL \
  https://raw.githubusercontent.com/zhonghp/api-key-scanner/main/skills/api-verify/SKILL.md \
  -o ~/.openclaw/skills/api-verify/SKILL.md
```

重启 OpenClaw。完事。

### 其他 MCP 客户端（Cursor / Continue / Zed / Claude Desktop 等）

任何 MCP 客户端都能用——server 就是一个标准的 stdio JSON-RPC server。
在你客户端的 MCP 配置里指向 `uvx --refresh-package api-key-scanner-mcp
api-key-scanner-mcp@latest` 就行。skill 是 Claude Code / OpenClaw 专属的；
其他客户端用户自己在对话里直接点名 `verify_gateway` 工具即可。

## 传入 gateway key

Server 从本地环境读 gateway 的 API key。放进 `~/.api-key-scanner/.env`：

```bash
mkdir -p ~/.api-key-scanner
cat > ~/.api-key-scanner/.env <<'EOF'
MY_GATEWAY_KEY=sk-你的-gateway-key
EOF
```

Server 启动时自动加载这个文件。shell `export` 也行，但必须在 **启动 MCP
客户端之前** 设好——大多数客户端（Claude Code、OpenClaw 等）都在启动瞬间
快照一次环境变量。

## 怎么用

直接自然语言：

> 帮我验证下 `https://api.example.com/v1` 提供的 gpt-4o 模型是不是
> 真的。我的 key 放在 `MY_GATEWAY_KEY` 环境变量里。

（问法是"这个 URL 提供的 X 模型是不是真的 X"，而不是"这个 URL 是不是
X"——前者才是在问真实性。）

返回一个 verdict：

- `trust_score`——0.0 到 1.0
- `verdict`——`ok` / `suspicious` / `likely_substituted` / `inconclusive`
- `confidence`——`low` / `medium` / `high`
- Detector 详情（`d1_llmmap` / `d2_met` / `d4_metadata`）

分界：

- `>= 0.90` → 响应跟厂商真实指纹吻合
- `0.70 – 0.90` → 有漂移，建议跑 `deep`
- `< 0.70` → endpoint 背后的模型大概率不是宣称的那个
- `inconclusive` → verdict 里会说明哪一步挂了

Budget：`cheap`（13 个 probe）、`standard`（58 个，默认）、`deep`（92 个）。
越高置信度越高，对 gateway 的调用量也越大。

## 能验证哪些模型

工具只能验证我们发布了签名指纹的模型。想知道当前覆盖哪些，直接在聊天里问：

> api-key-scanner 现在能验证哪些模型？

agent 会调 `list_supported_models` 告诉你。如果你想验的模型不在列表里，
verdict 会返回 `inconclusive`——工具不瞎猜。

我们会持续新增模型，最新名单见
[`fingerprint-*` release](https://github.com/zhonghp/api-key-scanner/releases)。

## 能抓什么

- **跨家族替换**——endpoint 宣称 gpt-4o，实际在跑 Llama / Qwen / Claude /
  Gemini
- **缓存回放**——endpoint 直接返回事先备好的"厂商风格"答案，根本没调
  真模型
- **System prompt 篡改**——endpoint 悄悄注入一段 system prompt 改变行为

## 抓不到什么（目前）

- **同家族降档**——Opus → Sonnet → Haiku，gpt-4o → gpt-4o-mini。有时会
  给 `suspicious`，但不会下定论
- **量化降级**——同模型 bf16 → int4。学术结论是黑盒检测基本接近随机
- **动态路由**——gateway 对"你是谁"这类 probe 给真模型，对真实业务流量
  给廉价模型。本质上需要额外的信任锚才能解决

看到 `likely_substituted` 要把它当成**开始调查**的信号，不是判定欺诈的
证据。trust score 是统计推断，不是法律结论。

## 更新

| 什么变了 | 你要做啥 |
|---|---|
| 指纹库出了新一期 | 啥也不用——server 每次启动都会检查 GitHub，自动升级 |
| MCP server 新版本 | 重启 MCP 客户端；`uvx` 自动拉 `@latest` |
| Plugin 或 skill 改了 | Claude Code：`/plugin marketplace update zhonghp-api-key-scanner` 再重启。OpenClaw：重新拷一次 `SKILL.md`（见安装） |
| 缓存问题——死活不升级 | `uv cache clean api-key-scanner-mcp`，重启客户端 |

## 隐私

- **你的 API key** 从 `.env` 或环境变量本地读。绝不打日志，绝不发到
  除了你指定的 gateway 以外任何地方。verdict 里即使出现报错字符串，key
  子串也会被擦掉
- **Gateway 响应** 在进程里分析完，绝不上传
- **本工具对外的网络** 只有两条路径：(1) 你给的那个 gateway URL；
  (2) `github.com/zhonghp/api-key-scanner` 的 release 资源
- **没有后端，故意的**——即使我们想记录你的流量也无处可记

## 参考数据的可信度

指纹快照用 [Sigstore](https://www.sigstore.dev/) keyless OIDC 签名，签名
身份绑定到我们那个 weekly GitHub Actions workflow。Server 拒绝加载签名
身份对不上的 release——宁可给 `inconclusive`，也不会基于未验证的参考数据
出 verdict。

## 内网/离线用

在另一台能联网的机器下载指纹 release，拷过来，让 server 用本地目录：

```bash
export APIGUARD_FINGERPRINT_DIR=/path/to/fingerprint-YYYY-MM-DD
```

（写进 `~/.api-key-scanner/.env`，MCP 客户端的子进程才读得到。）Sigstore
校验仍然强制执行；目录里得有 `MANIFEST.json.sigstore.json`。

## 许可证

- **代码**：[Apache-2.0](LICENSE)
- **指纹数据**（GitHub Release 资产）：CC-BY-4.0
