#!/usr/bin/env python3
"""Regenerate SUPPORTED_MODELS.md from a fingerprint MANIFEST + models.yaml.

The weekly collection workflow calls this after a successful collection +
manifest generation, then commits the result back to main so users always
see the latest coverage table without us having to touch it by hand.

Usage:
    uv run python scripts/generate_supported_models.py \
        --manifest ./out/fingerprints/MANIFEST.json \
        --models-yaml models.yaml \
        --release-tag fingerprint-2026-04-21 \
        --out SUPPORTED_MODELS.md
"""

from __future__ import annotations

import argparse
import json
import sys
from pathlib import Path
from typing import Any

import yaml

# The surrounding prose is stable copy — only the header and the table
# body are filled in from data. Keeping the static text here (rather than
# a template file) keeps the whole generator in one place.
_HEADER_TEMPLATE = """# 支持的模型

工具当前能对照签名参考指纹验证的模型列表。

- **最近更新**：{date}
- **当前 release**：[`{tag}`](https://github.com/zhonghp/api-key-scanner/releases/tag/{tag})
- **签名**：Sigstore keyless，绑定到本 repo 的 `weekly-fingerprint-collect.yml` workflow
- **自动维护**：本文件由 `weekly-fingerprint-collect.yml` 在每次指纹采集完成后自动重新生成并提交，不要手工编辑

## 覆盖情况

| Canonical ID | 厂商接受的 `model` 字段 | 采集 endpoint（我们从哪里拉的） | 样本数 |
|---|---|---|---|
{rows}

"Canonical ID" 就是你调 `verify_gateway` 时 `claimed_model` 参数要填的
值。像 `gpt-5.4`、`gpt5.4`、`openai/gpt-5.4` 这些别名通过 `aliases.json`
都会归一到同一个 canonical ID。

"采集 endpoint" 是我们跑采集流水线时打的 gateway——这里拿到的响应就是
参考指纹，拿来跟你自己 endpoint 的响应比对。理想情况这里就是厂商直连 API
（参考数据就是 ground truth）；不是的话 notes 里会标注。

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
"""


def _load_endpoint_map(models_yaml: Path) -> dict[str, tuple[str, str]]:
    """Map canonical_id -> (vendor_model_id, endpoint) from models.yaml.

    We read every entry (including `enabled: false`) so models that appear
    in the manifest still get their endpoint looked up even after they've
    been disabled in the collector config.
    """
    cfg = yaml.safe_load(models_yaml.read_text(encoding="utf-8"))
    mapping: dict[str, tuple[str, str]] = {}
    for entry in cfg.get("models", []) or []:
        cid = entry.get("canonical_id")
        if not cid:
            continue
        mapping[cid] = (entry.get("model_id", "?"), entry.get("endpoint", "?"))
    return mapping


def render(
    manifest: dict[str, Any],
    endpoints: dict[str, tuple[str, str]],
    release_tag: str,
) -> str:
    """Produce the full SUPPORTED_MODELS.md content."""
    models = manifest.get("models") or {}
    collected_at = manifest.get("collected_at", "")
    date = collected_at.split("T", 1)[0] if "T" in collected_at else (collected_at or "unknown")

    rows: list[str] = []
    for cid in sorted(models.keys()):
        entry = models[cid] or {}
        model_id, endpoint = endpoints.get(cid, ("?", "?"))
        samples = entry.get("num_samples", 0)
        rows.append(f"| `{cid}` | `{model_id}` | `{endpoint}` | {samples} |")

    if not rows:
        rows.append("| _no models in current release_ | — | — | 0 |")

    return _HEADER_TEMPLATE.format(
        date=date,
        tag=release_tag,
        rows="\n".join(rows),
    )


def main() -> int:
    parser = argparse.ArgumentParser(description=__doc__.splitlines()[0])
    parser.add_argument("--manifest", required=True, help="Path to MANIFEST.json")
    parser.add_argument(
        "--models-yaml",
        default="models.yaml",
        help="Path to models.yaml (for endpoint lookup)",
    )
    parser.add_argument("--release-tag", required=True, help="e.g. fingerprint-2026-04-21")
    parser.add_argument("--out", default="SUPPORTED_MODELS.md", help="Output path")
    args = parser.parse_args()

    manifest_path = Path(args.manifest)
    if not manifest_path.is_file():
        print(f"error: {manifest_path} not found", file=sys.stderr)
        return 2

    models_yaml = Path(args.models_yaml)
    if not models_yaml.is_file():
        print(f"error: {models_yaml} not found", file=sys.stderr)
        return 2

    manifest = json.loads(manifest_path.read_text(encoding="utf-8"))
    endpoints = _load_endpoint_map(models_yaml)
    content = render(manifest, endpoints, release_tag=args.release_tag)

    out_path = Path(args.out)
    out_path.write_text(content, encoding="utf-8")
    print(
        f"[supported-models] wrote {out_path} with {len(manifest.get('models', {}))} models",
        file=sys.stderr,
    )
    return 0


if __name__ == "__main__":
    sys.exit(main())
