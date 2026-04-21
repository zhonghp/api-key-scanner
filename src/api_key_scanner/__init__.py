"""api-key-scanner: Verify LLM API gateway authenticity.

A local MCP server + Claude Code plugin that verifies whether an API
endpoint is actually serving the claimed model, using public signed
fingerprint data. Your API key never leaves your machine.

See docs/2026-04-20-phase1-技术实现方案.md for the full Phase 1 design.
"""

__version__ = "0.1.4"
