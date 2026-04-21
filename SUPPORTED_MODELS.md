# Supported models

Models the tool can currently check against signed reference fingerprints.

- **Last updated**: 2026-04-21
- **Current release**: [`fingerprint-2026-04-21-signed`](https://github.com/zhonghp/api-key-scanner/releases/tag/fingerprint-2026-04-21-signed)
- **Signature**: Sigstore keyless, bound to the `weekly-fingerprint-collect.yml` workflow of this repo

**[简体中文](./SUPPORTED_MODELS.zh-CN.md)**

## Coverage

| Canonical ID | Vendor `model` field | Source endpoint (where we collected) | Samples |
|---|---|---|---|
| `openai/gpt-5.4` | `gpt-5.4` | `https://aigateway.edgecloudapp.com/v1/f194fd69361cd590f1fa136c9c90eca1/senseai` | 58 |
| `openai/gpt-5.4-mini` | `gpt-5.4-mini` | `https://aigateway.edgecloudapp.com/v1/f194fd69361cd590f1fa136c9c90eca1/senseai` | 57 |

"Canonical ID" is what you pass as `claimed_model` when calling
`verify_gateway`. Aliases like `gpt-5.4`, `gpt5.4`, or full
`openai/gpt-5.4` all resolve to the same canonical ID via
`aliases.json`.

"Source endpoint" is the gateway we ran the collection pipeline against
to build the reference fingerprint. That fingerprint is what your own
endpoint's responses get compared to. Ideally this is the vendor's own
direct API (so the reference is the ground truth); where it isn't,
we flag it in the "Notes" column when applicable.

## Why your model might not be here

`verify_gateway` only returns a meaningful verdict for models in the
table above. If you call it with a different `claimed_model`, you'll
get `inconclusive` with a disclaimer explaining what is covered.

- New vendor models — we add them when we have capacity to collect
  and validate a fingerprint. [File an issue](https://github.com/zhonghp/api-key-scanner/issues/new)
  naming the model if you need it.
- Aliases — the canonical ID might exist under a name you didn't
  expect. Ask in chat: *"Which models does api-key-scanner support?"*
  The agent calls `list_supported_models` and prints the live list.

## How this file is maintained

For now, manually — whenever the weekly fingerprint release changes
set of models, we update this file in the same commit. Future: have
`weekly-fingerprint-collect.yml` regenerate and commit this file
after each successful collection run.

The authoritative runtime source is always the `MANIFEST.json` inside
the latest `fingerprint-*` GitHub Release — `list_supported_models`
reads that at runtime, so it never goes stale.
