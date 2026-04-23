"""OpenAI-compatible gateway client.

Phase 1 supports the OpenAI `POST /v1/chat/completions` shape, which covers
90%+ of LLM middlemen. Anthropic-native / Google-native paths are out of scope
until Phase 2.

Design notes:
  - httpx.AsyncClient for per-probe concurrency (default 3 in flight)
  - Exponential backoff on 429 / 5xx / connection errors (3 retries)
  - Captures response_ms, system_fingerprint, finish_reason, token counts
  - TTFT requires streaming; Phase 1 keeps stream=false (ttft_ms stays None)
  - The user's API key passes through here from os.environ[...] exactly once;
    it is never logged, never included in exceptions
"""

from __future__ import annotations

import asyncio
import logging
import os
import time
from dataclasses import dataclass, field

import httpx

from api_key_scanner import __version__ as _PKG_VERSION  # noqa: N812
from api_key_scanner.schemas import Probe, ProbeResponse

logger = logging.getLogger(__name__)

_DEFAULT_CONCURRENCY = 3
_DEFAULT_MAX_RETRIES = 3

_ENV_INSECURE_SSL = "APIGUARD_INSECURE_SSL"


def _default_timeout() -> httpx.Timeout:
    return httpx.Timeout(connect=10.0, read=60.0, write=10.0, pool=10.0)


def _should_verify_ssl() -> bool:
    """Return False if APIGUARD_INSECURE_SSL is set to a truthy value.

    Internal LLM deployments (vLLM / SGLang / Triton on a private IP) very
    often use self-signed certs or don't match the IP-as-hostname, which
    httpx rejects by default. This env var is the escape hatch — use it
    only when you trust your network path to the server.
    """
    val = os.environ.get(_ENV_INSECURE_SSL, "").strip().lower()
    return val not in ("1", "true", "yes", "on")


@dataclass
class ClientConfig:
    endpoint_url: str
    api_key: str  # raw key; NEVER log this field
    model: str
    concurrency: int = _DEFAULT_CONCURRENCY
    max_retries: int = _DEFAULT_MAX_RETRIES
    timeout: httpx.Timeout = field(default_factory=_default_timeout)
    extra_headers: dict[str, str] | None = None


class OpenAICompatClient:
    """Minimal async client for OpenAI `/chat/completions` compatible gateways."""

    def __init__(self, config: ClientConfig):
        self._config = config
        self._semaphore = asyncio.Semaphore(config.concurrency)
        # Normalize endpoint to have no trailing slash; we'll append /chat/completions
        self._base = config.endpoint_url.rstrip("/")
        self._completions_path = self._resolve_completions_path(self._base)

    @staticmethod
    def _resolve_completions_path(base: str) -> str:
        # Common shapes:
        #   https://api.openai.com/v1          -> /v1/chat/completions
        #   https://api.openai.com/v1/         -> /v1/chat/completions
        #   https://gw.example.com              -> /chat/completions (caller responsible)
        #   https://gw.example.com/v1/chat/completions (already full) -> use as-is
        if base.endswith("/chat/completions"):
            return base
        return f"{base}/chat/completions"

    def _headers(self) -> dict[str, str]:
        headers = {
            "Authorization": f"Bearer {self._config.api_key}",
            "Content-Type": "application/json",
            "Accept": "application/json",
            "User-Agent": f"api-key-scanner-mcp/{_PKG_VERSION}",
        }
        if self._config.extra_headers:
            headers.update(self._config.extra_headers)
        return headers

    def _sanitize(self, text: str) -> str:
        """Defense in depth: remove the raw API key from any outbound string.

        Some backends echo the Authorization header (or parts of it) back
        in their error bodies. If we were to surface that as a
        ProbeResponse.error, the key would leak into the MCP transcript
        and thence into agent logs. Always scrub on the way out.
        """
        key = self._config.api_key
        if key and len(key) >= 8:
            text = text.replace(key, "<REDACTED>")
        return text

    def _build_payload(self, probe: Probe) -> dict:
        payload: dict = {
            "model": self._config.model,
            "messages": [m.model_dump() for m in probe.messages],
            "temperature": probe.params.temperature,
            "top_p": probe.params.top_p,
            "max_tokens": probe.params.max_tokens,
            "stream": False,
        }
        if probe.params.seed is not None:
            payload["seed"] = probe.params.seed
        return payload

    async def run_probes(
        self, probes: list[Probe], *, client: httpx.AsyncClient | None = None
    ) -> list[ProbeResponse]:
        """Run all probes, each num_samples times, with concurrency + retries.

        Returns one ProbeResponse per (probe, sample_index) pair. Failed
        samples carry the error in .error and have empty output.
        """
        owns_client = client is None
        if client is None:
            verify = _should_verify_ssl()
            if not verify:
                logger.warning(
                    "SSL verification DISABLED via %s — only use on trusted networks",
                    _ENV_INSECURE_SSL,
                )
            client = httpx.AsyncClient(timeout=self._config.timeout, verify=verify)

        try:
            tasks: list[asyncio.Task[ProbeResponse]] = []
            for probe in probes:
                for i in range(probe.num_samples):
                    tasks.append(asyncio.create_task(self._run_one(client, probe, sample_index=i)))
            results = await asyncio.gather(*tasks)
            return list(results)
        finally:
            if owns_client:
                await client.aclose()

    async def _run_one(
        self, client: httpx.AsyncClient, probe: Probe, sample_index: int
    ) -> ProbeResponse:
        async with self._semaphore:
            return await self._call_with_retry(client, probe, sample_index)

    async def _call_with_retry(
        self, client: httpx.AsyncClient, probe: Probe, sample_index: int
    ) -> ProbeResponse:
        payload = self._build_payload(probe)
        last_err: str | None = None

        for attempt in range(self._config.max_retries + 1):
            try:
                t0 = time.perf_counter()
                resp = await client.post(
                    self._completions_path, headers=self._headers(), json=payload
                )
                elapsed_ms = int((time.perf_counter() - t0) * 1000)

                if resp.status_code == 200:
                    parsed = self._parse_ok_response(
                        resp.json(), probe=probe, sample_index=sample_index, elapsed_ms=elapsed_ms
                    )
                    # Defense-in-depth: sanitize content + error too. A misbehaving
                    # gateway that echoes the Authorization header into the response
                    # body should NOT propagate it via a ProbeResponse.
                    if parsed.output:
                        parsed.output = self._sanitize(parsed.output)
                    if parsed.error:
                        parsed.error = self._sanitize(parsed.error)
                    return parsed

                # Retryable status codes
                if resp.status_code in (408, 429, 500, 502, 503, 504):
                    last_err = f"http {resp.status_code}"
                    backoff = 2**attempt + 0.1 * attempt
                    logger.debug(
                        "retry probe=%s sample=%d status=%d attempt=%d backoff=%.1fs",
                        probe.probe_id,
                        sample_index,
                        resp.status_code,
                        attempt,
                        backoff,
                    )
                    await asyncio.sleep(backoff)
                    continue

                # Non-retryable HTTP error
                return ProbeResponse(
                    probe_id=probe.probe_id,
                    sample_index=sample_index,
                    output="",
                    error=self._sanitize(f"http {resp.status_code}: {_truncate_body(resp.text)}"),
                )

            except (httpx.TimeoutException, httpx.NetworkError) as exc:
                last_err = f"{type(exc).__name__}: {exc}"
                logger.debug(
                    "network error probe=%s sample=%d attempt=%d: %s",
                    probe.probe_id,
                    sample_index,
                    attempt,
                    last_err,
                )
                if attempt < self._config.max_retries:
                    await asyncio.sleep(2**attempt)
                    continue

            except Exception as exc:
                # Unexpected error — do not retry; do not include the key or body
                return ProbeResponse(
                    probe_id=probe.probe_id,
                    sample_index=sample_index,
                    output="",
                    error=f"unexpected {type(exc).__name__}",
                )

        return ProbeResponse(
            probe_id=probe.probe_id,
            sample_index=sample_index,
            output="",
            error=self._sanitize(last_err or "max retries exceeded"),
        )

    @staticmethod
    def _parse_ok_response(
        body: dict, *, probe: Probe, sample_index: int, elapsed_ms: int
    ) -> ProbeResponse:
        """Extract fields from a 200 response body.

        Shape (OpenAI-compat):
          {
            "choices": [{"message": {"content": "..."}, "finish_reason": "stop"}],
            "usage": {"completion_tokens": 12, "prompt_tokens": 20, "total_tokens": 32},
            "system_fingerprint": "fp_abc"  # optional
          }
        """
        choices = body.get("choices") or []
        if not choices:
            return ProbeResponse(
                probe_id=probe.probe_id,
                sample_index=sample_index,
                output="",
                response_ms=elapsed_ms,
                error="empty choices[]",
            )

        message = choices[0].get("message", {}) or {}
        content = message.get("content") or ""
        finish_reason = choices[0].get("finish_reason")
        usage = body.get("usage") or {}

        return ProbeResponse(
            probe_id=probe.probe_id,
            sample_index=sample_index,
            output=content,
            output_tokens=usage.get("completion_tokens"),
            response_ms=elapsed_ms,
            ttft_ms=None,  # Phase 1: no streaming
            system_fingerprint=body.get("system_fingerprint"),
            finish_reason=finish_reason,
        )


def _truncate_body(text: str, limit: int = 200) -> str:
    if len(text) <= limit:
        return text
    return text[:limit] + "..."
