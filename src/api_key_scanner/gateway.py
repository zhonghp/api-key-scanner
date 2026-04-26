"""LLM gateway client.

The default path supports the OpenAI `POST /v1/chat/completions` shape, which
covers many LLM middlemen. `api_format="anthropic"` and `api_format="gemini"`
enable native Anthropic Messages and Gemini GenerateContent request shapes.

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
import json
import logging
import os
import time
from dataclasses import dataclass, field
from typing import Any
from urllib.parse import quote, urlsplit

import httpx

from api_key_scanner import __version__ as _PKG_VERSION  # noqa: N812
from api_key_scanner.schemas import (
    ApiFormat,
    AuthScheme,
    ChatMessage,
    Probe,
    ProbeResponse,
    SampleParams,
    validate_request_omit_fields,
    validate_request_overrides_dict,
)

logger = logging.getLogger(__name__)

_DEFAULT_CONCURRENCY = 3
_DEFAULT_MAX_RETRIES = 3

_ENV_INSECURE_SSL = "APIGUARD_INSECURE_SSL"


@dataclass(frozen=True)
class _AutoDetectCandidate:
    label: str
    api_format: ApiFormat
    auth_scheme: AuthScheme
    request_overrides: dict[str, Any]
    request_omit_fields: list[str]


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


def _has_url_path(base: str) -> bool:
    return bool(urlsplit(base).path.strip("/"))


@dataclass
class ClientConfig:
    endpoint_url: str
    api_key: str  # raw key; NEVER log this field
    model: str
    concurrency: int = _DEFAULT_CONCURRENCY
    max_retries: int = _DEFAULT_MAX_RETRIES
    timeout: httpx.Timeout = field(default_factory=_default_timeout)
    extra_headers: dict[str, str] | None = None
    request_overrides: dict[str, Any] | None = None
    request_omit_fields: list[str] | None = None
    api_format: ApiFormat = "openai"
    auth_scheme: AuthScheme = "default"


class OpenAICompatClient:
    """Minimal async client for OpenAI-compatible, Anthropic, and Gemini gateways."""

    def __init__(self, config: ClientConfig):
        self._config = config
        self._resolved_config: ClientConfig | None = None
        if config.api_format not in ("openai", "anthropic", "gemini", "auto"):
            raise ValueError("api_format must be one of: openai, anthropic, gemini, auto")
        if config.auth_scheme not in ("default", "bearer", "x-api-key", "x-goog-api-key"):
            raise ValueError(
                "auth_scheme must be one of: default, bearer, x-api-key, x-goog-api-key"
            )
        if config.request_overrides:
            validate_request_overrides_dict(config.request_overrides)
        if config.request_omit_fields:
            validate_request_omit_fields(config.request_omit_fields)
        self._semaphore = asyncio.Semaphore(config.concurrency)
        # Normalize endpoint to have no trailing slash; we'll append provider paths.
        self._base = config.endpoint_url.rstrip("/")
        self._request_path = self._resolve_request_path(self._base)
        # Backward-compatible test/debug alias for the default OpenAI-compatible path.
        self._completions_path = self._request_path

    @property
    def resolved_config(self) -> ClientConfig | None:
        return self._resolved_config

    def _resolve_request_path(self, base: str) -> str:
        if self._config.api_format == "anthropic":
            return self._resolve_anthropic_path(base)
        if self._config.api_format == "gemini":
            return self._resolve_gemini_path(base, self._config.model)
        return self._resolve_openai_path(base)

    @staticmethod
    def _resolve_openai_path(base: str) -> str:
        # Common shapes:
        #   https://api.openai.com/v1          -> /v1/chat/completions
        #   https://api.openai.com/v1/         -> /v1/chat/completions
        #   https://api.openai.com             -> /v1/chat/completions
        #   https://gw.example.com/v1/chat/completions (already full) -> use as-is
        if base.endswith("/chat/completions"):
            return base
        if not _has_url_path(base):
            return f"{base}/v1/chat/completions"
        return f"{base}/chat/completions"

    @staticmethod
    def _resolve_anthropic_path(base: str) -> str:
        if base.endswith("/messages"):
            return base
        if base.endswith("/v1"):
            return f"{base}/messages"
        return f"{base}/v1/messages"

    @staticmethod
    def _resolve_gemini_path(base: str, model: str) -> str:
        encoded_model = quote(model, safe="")
        if base.endswith(":generateContent"):
            return base
        if "{model}" in base:
            return base.format(model=encoded_model)
        if not _has_url_path(base):
            return f"{base}/v1/models/{encoded_model}:generateContent"
        return f"{base}/models/{encoded_model}:generateContent"

    def _headers(self) -> dict[str, str]:
        if self._config.api_format == "anthropic":
            headers = {
                "anthropic-version": "2023-06-01",
                "Content-Type": "application/json",
                "Accept": "application/json",
                "User-Agent": f"api-key-scanner-mcp/{_PKG_VERSION}",
            }
        elif self._config.api_format == "gemini":
            headers = {
                "Content-Type": "application/json",
                "Accept": "application/json",
                "User-Agent": f"api-key-scanner-mcp/{_PKG_VERSION}",
            }
        else:
            headers = {
                "Content-Type": "application/json",
                "Accept": "application/json",
                "User-Agent": f"api-key-scanner-mcp/{_PKG_VERSION}",
            }
        headers.update(self._auth_headers())
        if self._config.extra_headers:
            headers.update(self._config.extra_headers)
        return headers

    def _auth_headers(self) -> dict[str, str]:
        scheme = self._config.auth_scheme
        if scheme == "default":
            if self._config.api_format == "anthropic":
                scheme = "x-api-key"
            elif self._config.api_format == "gemini":
                scheme = "x-goog-api-key"
            else:
                scheme = "bearer"
        if scheme == "bearer":
            return {"Authorization": f"Bearer {self._config.api_key}"}
        if scheme == "x-api-key":
            return {"x-api-key": self._config.api_key}
        if scheme == "x-goog-api-key":
            return {"x-goog-api-key": self._config.api_key}
        return {}

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

    def _build_payload(self, probe: Probe) -> dict[str, Any]:
        if self._config.api_format == "anthropic":
            return self._build_anthropic_payload(probe)
        if self._config.api_format == "gemini":
            return self._build_gemini_payload(probe)
        return self._build_openai_payload(probe)

    def _build_openai_payload(self, probe: Probe) -> dict[str, Any]:
        payload: dict[str, Any] = {
            "model": self._config.model,
            "messages": [m.model_dump() for m in probe.messages],
            "stream": False,
        }
        omit_fields = set(self._config.request_omit_fields or [])
        if "temperature" not in omit_fields:
            payload["temperature"] = probe.params.temperature
        if "top_p" not in omit_fields:
            payload["top_p"] = probe.params.top_p
        # Some reasoning models reject `max_tokens` and require
        # `max_completion_tokens` instead. When the caller explicitly opts
        # into that parameter via request_overrides, omit the legacy field.
        if (
            self._config.request_overrides
            and "max_completion_tokens" in self._config.request_overrides
        ):
            omit_fields.add("max_tokens")
        if "max_tokens" not in omit_fields:
            payload["max_tokens"] = probe.params.max_tokens
        if probe.params.seed is not None and "seed" not in omit_fields:
            payload["seed"] = probe.params.seed
        if self._config.request_overrides:
            payload = _merge_openai_request_overrides(payload, self._config.request_overrides)
        return payload

    def _build_anthropic_payload(self, probe: Probe) -> dict[str, Any]:
        payload: dict[str, Any] = {
            "model": self._config.model,
            "messages": [],
        }
        omit_fields = set(self._config.request_omit_fields or [])
        if "max_tokens" not in omit_fields:
            payload["max_tokens"] = probe.params.max_tokens
        if "temperature" not in omit_fields:
            payload["temperature"] = probe.params.temperature
        if "top_p" not in omit_fields:
            payload["top_p"] = probe.params.top_p

        system_parts: list[str] = []
        messages: list[dict[str, str]] = []
        for message in probe.messages:
            if message.role == "system":
                system_parts.append(message.content)
            else:
                messages.append({"role": message.role, "content": message.content})
        if system_parts:
            payload["system"] = "\n\n".join(system_parts)
        payload["messages"] = messages

        overrides = dict(self._config.request_overrides or {})
        max_completion_tokens = overrides.pop("max_completion_tokens", None)
        if max_completion_tokens is not None:
            payload["max_tokens"] = max_completion_tokens
        extra_body = overrides.pop("extra_body", None)
        if isinstance(extra_body, dict):
            payload = _merge_request_overrides(payload, extra_body)
        if overrides:
            payload = _merge_request_overrides(payload, overrides)
        return payload

    def _build_gemini_payload(self, probe: Probe) -> dict[str, Any]:
        generation_config: dict[str, Any] = {}
        omit_fields = set(self._config.request_omit_fields or [])
        if "temperature" not in omit_fields:
            generation_config["temperature"] = probe.params.temperature
        if "top_p" not in omit_fields:
            generation_config["topP"] = probe.params.top_p
        if "max_tokens" not in omit_fields:
            generation_config["maxOutputTokens"] = probe.params.max_tokens
        if probe.params.seed is not None and "seed" not in omit_fields:
            generation_config["seed"] = probe.params.seed

        system_parts: list[str] = []
        contents: list[dict[str, Any]] = []
        for message in probe.messages:
            if message.role == "system":
                system_parts.append(message.content)
                continue
            role = "model" if message.role == "assistant" else "user"
            contents.append({"role": role, "parts": [{"text": message.content}]})

        payload: dict[str, Any] = {"contents": contents}
        if generation_config:
            payload["generationConfig"] = generation_config
        if system_parts:
            payload["systemInstruction"] = {
                "parts": [{"text": "\n\n".join(system_parts)}],
            }

        overrides = _normalize_gemini_native_overrides(
            self._config.request_overrides or {},
            model=self._config.model,
        )
        if overrides:
            payload = _merge_request_overrides(payload, overrides)
        return payload

    async def run_probes(
        self, probes: list[Probe], *, client: httpx.AsyncClient | None = None
    ) -> list[ProbeResponse]:
        """Run all probes, each num_samples times, with concurrency + retries.

        Returns one ProbeResponse per (probe, sample_index) pair. Failed
        samples carry the error in .error and have empty output.
        """
        probe_samples = [
            (probe, sample_index) for probe in probes for sample_index in range(probe.num_samples)
        ]
        return await self.run_probe_samples(probe_samples, client=client)

    async def run_probe_samples(
        self,
        probe_samples: list[tuple[Probe, int]],
        *,
        client: httpx.AsyncClient | None = None,
    ) -> list[ProbeResponse]:
        """Run explicit (probe, sample_index) pairs.

        Batch collection uses this for resume: an existing fingerprint may
        already contain sample indexes 0, 1, and 3, so the collector must be
        able to request only sample index 2 without renumbering it.
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
            if self._config.api_format == "auto":
                resolved_config = self._resolved_config
                if resolved_config is None:
                    try:
                        resolved_config = await self._resolve_auto_config(client)
                    except ValueError as exc:
                        message = self._sanitize(str(exc))
                        return [
                            ProbeResponse(
                                probe_id=probe.probe_id,
                                sample_index=sample_index,
                                output="",
                                error=message,
                            )
                            for probe, sample_index in probe_samples
                        ]
                    self._resolved_config = resolved_config
                self._resolved_config = resolved_config
                resolved_client = OpenAICompatClient(resolved_config)
                results = await resolved_client.run_probe_samples(probe_samples, client=client)
                self._resolved_config = resolved_client.resolved_config or resolved_config
                return results

            tasks: list[asyncio.Task[ProbeResponse]] = []
            for probe, sample_index in probe_samples:
                tasks.append(
                    asyncio.create_task(self._run_one(client, probe, sample_index=sample_index))
                )
            results = await asyncio.gather(*tasks)
            return list(results)
        finally:
            if owns_client:
                await client.aclose()

    async def _resolve_auto_config(self, client: httpx.AsyncClient) -> ClientConfig:
        candidates = _auto_detect_candidates(self._config)
        failures: list[str] = []
        openai_successes: list[tuple[int, _AutoDetectCandidate]] = []

        for index, candidate in enumerate(candidates):
            candidate_config = _config_from_candidate(self._config, candidate)
            candidate_client = OpenAICompatClient(candidate_config)
            response = (
                await candidate_client.run_probe_samples([(_auto_detect_probe(), 0)], client=client)
            )[0]
            if not _auto_probe_usable(response):
                failures.append(_format_auto_failure(candidate.label, response))
                continue
            if candidate.api_format != "openai":
                return candidate_config
            score = _auto_probe_score(response)
            openai_successes.append((score * 1000 + index, candidate))

        if openai_successes:
            _, best_candidate = min(openai_successes, key=lambda item: item[0])
            return _config_from_candidate(self._config, best_candidate)

        detail = "; ".join(failures[:6]) if failures else "no candidates"
        raise ValueError(f"auto API detection failed for model {self._config.model!r}: {detail}")

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
                resp = await client.post(self._request_path, headers=self._headers(), json=payload)
                elapsed_ms = int((time.perf_counter() - t0) * 1000)

                if resp.status_code == 200:
                    try:
                        body = resp.json()
                    except ValueError:
                        return ProbeResponse(
                            probe_id=probe.probe_id,
                            sample_index=sample_index,
                            output="",
                            response_ms=elapsed_ms,
                            error=self._sanitize(
                                f"invalid json response: {_truncate_body(resp.text)}"
                            ),
                        )
                    parsed = self._parse_ok_response(
                        body, probe=probe, sample_index=sample_index, elapsed_ms=elapsed_ms
                    )
                    # Defense-in-depth: sanitize content + error too. A misbehaving
                    # gateway that echoes the Authorization header into the response
                    # body should NOT propagate it via a ProbeResponse.
                    if parsed.output:
                        parsed.output = self._sanitize(parsed.output)
                    if parsed.reasoning_content:
                        parsed.reasoning_content = self._sanitize(parsed.reasoning_content)
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

    def _parse_ok_response(
        self, body: dict, *, probe: Probe, sample_index: int, elapsed_ms: int
    ) -> ProbeResponse:
        if self._config.api_format == "anthropic":
            return _parse_anthropic_response(
                body, probe=probe, sample_index=sample_index, elapsed_ms=elapsed_ms
            )
        if self._config.api_format == "gemini":
            return _parse_gemini_response(
                body, probe=probe, sample_index=sample_index, elapsed_ms=elapsed_ms
            )
        return _parse_openai_response(
            body, probe=probe, sample_index=sample_index, elapsed_ms=elapsed_ms
        )


def _parse_openai_response(
    body: dict, *, probe: Probe, sample_index: int, elapsed_ms: int
) -> ProbeResponse:
    """Extract fields from a 200 OpenAI-compatible response body."""
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
    completion_details = usage.get("completion_tokens_details") or {}
    reasoning_content = _extract_reasoning_content(message, choices[0])

    return ProbeResponse(
        probe_id=probe.probe_id,
        sample_index=sample_index,
        output=content,
        output_tokens=usage.get("completion_tokens"),
        response_ms=elapsed_ms,
        ttft_ms=None,
        system_fingerprint=body.get("system_fingerprint"),
        finish_reason=finish_reason,
        reasoning_tokens=completion_details.get("reasoning_tokens"),
        reasoning_content=reasoning_content,
    )


def _parse_anthropic_response(
    body: dict, *, probe: Probe, sample_index: int, elapsed_ms: int
) -> ProbeResponse:
    if body.get("choices"):
        return _parse_openai_response(
            body, probe=probe, sample_index=sample_index, elapsed_ms=elapsed_ms
        )
    content_blocks = body.get("content") or []
    text_parts: list[str] = []
    reasoning_parts: list[str] = []
    for block in content_blocks:
        if not isinstance(block, dict):
            continue
        block_type = block.get("type")
        text = block.get("text")
        if block_type == "text" and isinstance(text, str):
            text_parts.append(text)
        elif isinstance(text, str):
            reasoning_parts.append(text)

    usage = body.get("usage") or {}
    return ProbeResponse(
        probe_id=probe.probe_id,
        sample_index=sample_index,
        output="".join(text_parts),
        output_tokens=usage.get("output_tokens"),
        response_ms=elapsed_ms,
        ttft_ms=None,
        system_fingerprint=None,
        finish_reason=_normalize_anthropic_finish_reason(body.get("stop_reason")),
        reasoning_tokens=None,
        reasoning_content="\n".join(reasoning_parts) or None,
    )


def _parse_gemini_response(
    body: dict, *, probe: Probe, sample_index: int, elapsed_ms: int
) -> ProbeResponse:
    if body.get("choices"):
        return _parse_openai_response(
            body, probe=probe, sample_index=sample_index, elapsed_ms=elapsed_ms
        )
    candidates = body.get("candidates") or []
    if not candidates:
        return ProbeResponse(
            probe_id=probe.probe_id,
            sample_index=sample_index,
            output="",
            response_ms=elapsed_ms,
            error="empty candidates[]",
        )

    candidate = candidates[0] or {}
    content = candidate.get("content") or {}
    parts = content.get("parts") or []
    text_parts: list[str] = []
    reasoning_parts: list[str] = []
    for part in parts:
        if not isinstance(part, dict):
            continue
        text = part.get("text")
        if not isinstance(text, str):
            continue
        if part.get("thought") is True:
            reasoning_parts.append(text)
        else:
            text_parts.append(text)

    usage = body.get("usageMetadata") or {}
    return ProbeResponse(
        probe_id=probe.probe_id,
        sample_index=sample_index,
        output="".join(text_parts),
        output_tokens=usage.get("candidatesTokenCount") or usage.get("outputTokenCount"),
        response_ms=elapsed_ms,
        ttft_ms=None,
        system_fingerprint=None,
        finish_reason=_normalize_gemini_finish_reason(candidate.get("finishReason")),
        reasoning_tokens=usage.get("thoughtsTokenCount"),
        reasoning_content="\n".join(reasoning_parts) or None,
    )


def _normalize_anthropic_finish_reason(reason: Any) -> str | None:
    if reason is None:
        return None
    mapping = {
        "end_turn": "stop",
        "stop_sequence": "stop",
        "max_tokens": "length",
        "tool_use": "tool_calls",
    }
    return mapping.get(str(reason), str(reason))


def _normalize_gemini_finish_reason(reason: Any) -> str | None:
    if reason is None:
        return None
    mapping = {
        "STOP": "stop",
        "MAX_TOKENS": "length",
    }
    return mapping.get(str(reason), str(reason).lower())


def _truncate_body(text: str, limit: int = 200) -> str:
    if len(text) <= limit:
        return text
    return text[:limit] + "..."


def _stringify_reasoning_content(value: Any) -> str | None:
    if value is None or value == "":
        return None
    if isinstance(value, str):
        return value
    return str(value)


def _extract_reasoning_content(*containers: dict[str, Any]) -> str | None:
    # OpenAI-compatible gateways use different non-standard names for exposed
    # reasoning text. Most only expose token counts; this keeps any visible
    # content for debug/rejected-sample logs when a gateway does provide it.
    field_names = (
        "reasoning_content",
        "reasoning",
        "thinking_content",
        "thinking",
        "thought",
        "thoughts",
    )
    for container in containers:
        for field_name in field_names:
            content = _stringify_reasoning_content(container.get(field_name))
            if content:
                return content
    return None


def _auto_detect_probe() -> Probe:
    return Probe(
        probe_id="api-format-autodetect",
        category="identification",
        messages=[ChatMessage(role="user", content="Reply with exactly: ok")],
        params=SampleParams(temperature=0.0, top_p=1.0, max_tokens=32),
        num_samples=1,
    )


def _auto_detect_candidates(config: ClientConfig) -> list[_AutoDetectCandidate]:
    family = _infer_model_family(config.model)
    candidates: list[_AutoDetectCandidate] = []
    if family == "anthropic":
        candidates.extend(_anthropic_native_candidates(config))
    elif family == "gemini":
        candidates.extend(_gemini_native_candidates(config))

    candidates.extend(_openai_compatible_candidates(config, family=family))
    return _dedupe_auto_candidates(candidates)


def _infer_model_family(model: str) -> str:
    lowered = model.lower()
    if "claude" in lowered or "anthropic/" in lowered:
        return "anthropic"
    if "gemini" in lowered or "google/" in lowered:
        return "gemini"
    return "openai"


def _anthropic_native_candidates(config: ClientConfig) -> list[_AutoDetectCandidate]:
    auth_schemes: list[AuthScheme]
    if config.auth_scheme == "default":
        auth_schemes = ["x-api-key", "bearer"]
    else:
        auth_schemes = [config.auth_scheme]
    candidates: list[_AutoDetectCandidate] = []
    for auth_scheme in auth_schemes:
        candidates.append(
            _AutoDetectCandidate(
                label=f"anthropic/{auth_scheme}",
                api_format="anthropic",
                auth_scheme=auth_scheme,
                request_overrides=dict(config.request_overrides or {}),
                request_omit_fields=list(config.request_omit_fields or []),
            )
        )
        candidates.append(
            _AutoDetectCandidate(
                label=f"anthropic/{auth_scheme}/omit-top-p",
                api_format="anthropic",
                auth_scheme=auth_scheme,
                request_overrides=dict(config.request_overrides or {}),
                request_omit_fields=_merge_omit_fields(config.request_omit_fields or [], ["top_p"]),
            )
        )
    return candidates


def _gemini_native_candidates(config: ClientConfig) -> list[_AutoDetectCandidate]:
    auth_schemes: list[AuthScheme]
    if config.auth_scheme == "default":
        auth_schemes = ["x-goog-api-key", "bearer"]
    else:
        auth_schemes = [config.auth_scheme]
    candidates: list[_AutoDetectCandidate] = []
    base_overrides = dict(config.request_overrides or {})
    for auth_scheme in auth_schemes:
        candidates.append(
            _AutoDetectCandidate(
                label=f"gemini/{auth_scheme}",
                api_format="gemini",
                auth_scheme=auth_scheme,
                request_overrides=base_overrides,
                request_omit_fields=list(config.request_omit_fields or []),
            )
        )
        if _should_try_native_gemini_thinking_zero(base_overrides):
            candidates.append(
                _AutoDetectCandidate(
                    label=f"gemini/{auth_scheme}/thinking-budget-0",
                    api_format="gemini",
                    auth_scheme=auth_scheme,
                    request_overrides=_merge_request_overrides(
                        base_overrides,
                        {"extra_body": {"google": {"thinking_config": {"thinking_budget": 0}}}},
                    ),
                    request_omit_fields=list(config.request_omit_fields or []),
                )
            )
    return candidates


def _should_try_native_gemini_thinking_zero(overrides: dict[str, Any]) -> bool:
    if "max_completion_tokens" in overrides:
        return False
    if overrides.get("reasoning_effort") == "none":
        return False
    extra_body = overrides.get("extra_body")
    if isinstance(extra_body, dict):
        google_body = extra_body.get("google")
        if isinstance(google_body, dict) and (
            "thinking_config" in google_body or "thinkingConfig" in google_body
        ):
            return False
    return "thinking_config" not in overrides and "thinkingConfig" not in overrides


def _openai_compatible_candidates(
    config: ClientConfig, *, family: str
) -> list[_AutoDetectCandidate]:
    auth_scheme: AuthScheme = config.auth_scheme if config.auth_scheme != "default" else "bearer"
    base_overrides = dict(config.request_overrides or {})
    base_omit_fields = list(config.request_omit_fields or [])
    candidates = [
        _AutoDetectCandidate(
            label="openai/base",
            api_format="openai",
            auth_scheme=auth_scheme,
            request_overrides=base_overrides,
            request_omit_fields=base_omit_fields,
        )
    ]
    if family == "gemini":
        thinking_level_override = _gemini_openai_thinking_none_override(config.model)
        candidates.append(
            _AutoDetectCandidate(
                label="openai/gemini/reasoning-none",
                api_format="openai",
                auth_scheme=auth_scheme,
                request_overrides=_merge_request_overrides(
                    base_overrides,
                    {"reasoning_effort": "none"},
                ),
                request_omit_fields=base_omit_fields,
            )
        )
        if thinking_level_override:
            candidates.append(
                _AutoDetectCandidate(
                    label="openai/gemini/google-thinking-level",
                    api_format="openai",
                    auth_scheme=auth_scheme,
                    request_overrides=_merge_request_overrides(
                        _merge_request_overrides(
                            base_overrides,
                            {"reasoning_effort": "none"},
                        ),
                        thinking_level_override,
                    ),
                    request_omit_fields=base_omit_fields,
                )
            )
        candidates.append(
            _AutoDetectCandidate(
                label="openai/gemini/google-thinking-budget-0",
                api_format="openai",
                auth_scheme=auth_scheme,
                request_overrides=_merge_request_overrides(
                    base_overrides,
                    {"extra_body": {"google": {"thinking_config": {"thinking_budget": 0}}}},
                ),
                request_omit_fields=base_omit_fields,
            )
        )
    elif family == "anthropic":
        candidates.append(
            _AutoDetectCandidate(
                label="openai/anthropic/omit-top-p",
                api_format="openai",
                auth_scheme=auth_scheme,
                request_overrides=base_overrides,
                request_omit_fields=_merge_omit_fields(base_omit_fields, ["top_p"]),
            )
        )
    return candidates


def _dedupe_auto_candidates(candidates: list[_AutoDetectCandidate]) -> list[_AutoDetectCandidate]:
    deduped: list[_AutoDetectCandidate] = []
    seen: set[str] = set()
    for candidate in candidates:
        marker = json_dumps_compact(
            {
                "api_format": candidate.api_format,
                "auth_scheme": candidate.auth_scheme,
                "request_overrides": candidate.request_overrides,
                "request_omit_fields": candidate.request_omit_fields,
            }
        )
        if marker in seen:
            continue
        deduped.append(candidate)
        seen.add(marker)
    return deduped


def _config_from_candidate(config: ClientConfig, candidate: _AutoDetectCandidate) -> ClientConfig:
    return ClientConfig(
        endpoint_url=config.endpoint_url,
        api_key=config.api_key,
        model=config.model,
        concurrency=config.concurrency,
        max_retries=config.max_retries,
        timeout=config.timeout,
        extra_headers=config.extra_headers,
        request_overrides=candidate.request_overrides,
        request_omit_fields=candidate.request_omit_fields,
        api_format=candidate.api_format,
        auth_scheme=candidate.auth_scheme,
    )


def _auto_probe_usable(response: ProbeResponse) -> bool:
    return response.error is None and bool(response.output.strip())


def _auto_probe_score(response: ProbeResponse) -> int:
    score = 0
    if (response.finish_reason or "").lower() == "length":
        score += 10_000
    reasoning = response.reasoning_tokens or 0
    if reasoning > 0:
        score += min(reasoning, 5_000)
    return score


def _format_auto_failure(label: str, response: ProbeResponse) -> str:
    if response.error:
        return f"{label}: {response.error}"
    if not response.output.strip():
        return f"{label}: empty output"
    return f"{label}: unusable response"


def _merge_omit_fields(base: list[str], additions: list[str]) -> list[str]:
    merged = list(base)
    for field_name in additions:
        if field_name not in merged:
            merged.append(field_name)
    return merged


def json_dumps_compact(value: Any) -> str:
    return json.dumps(value, ensure_ascii=True, sort_keys=True, separators=(",", ":"))


def _normalize_gemini_native_overrides(
    overrides: dict[str, Any],
    *,
    model: str,
) -> dict[str, Any]:
    """Translate common OpenAI-compatible Gemini knobs to native Gemini fields."""
    normalized = dict(overrides)
    output: dict[str, Any] = {}

    max_completion_tokens = normalized.pop("max_completion_tokens", None)
    if max_completion_tokens is not None:
        _merge_generation_config(output, {"maxOutputTokens": max_completion_tokens})

    reasoning_effort = normalized.pop("reasoning_effort", None)
    if reasoning_effort == "none":
        _merge_generation_config(
            output,
            {"thinkingConfig": _gemini_native_thinking_none_config(model)},
        )

    extra_body = normalized.pop("extra_body", None)
    if isinstance(extra_body, dict):
        google_body = extra_body.get("google")
        if isinstance(google_body, dict):
            thinking = google_body.get("thinking_config") or google_body.get("thinkingConfig")
            if isinstance(thinking, dict):
                _merge_generation_config(
                    output,
                    {"thinkingConfig": _camelize_gemini_thinking_config(thinking)},
                )
        else:
            output = _merge_request_overrides(output, extra_body)

    thinking_config = normalized.pop("thinking_config", None)
    if isinstance(thinking_config, dict):
        _merge_generation_config(
            output,
            {"thinkingConfig": _camelize_gemini_thinking_config(thinking_config)},
        )

    thinking_config_camel = normalized.pop("thinkingConfig", None)
    if isinstance(thinking_config_camel, dict):
        _merge_generation_config(output, {"thinkingConfig": thinking_config_camel})

    if normalized:
        output = _merge_request_overrides(output, normalized)
    return output


def _gemini_native_thinking_none_config(model: str) -> dict[str, Any]:
    """Best-effort native Gemini mapping for OpenAI-style reasoning_effort=none.

    Gemini 2.5 Flash/Lite support turning thinking off with thinkingBudget=0.
    Gemini 3 models use thinkingLevel; Pro does not expose a true "off" level,
    so "low" is the closest compatible native setting. Flash supports the more
    aggressive "minimal" level.
    """
    lowered = model.lower()
    if "gemini-3" in lowered:
        level = "minimal" if "flash" in lowered else "low"
        return {"thinkingLevel": level}
    return {"thinkingBudget": 0}


def _gemini_openai_thinking_none_override(model: str) -> dict[str, Any]:
    thinking_config = _gemini_openai_thinking_none_config(model)
    if not thinking_config:
        return {}
    return {"extra_body": {"google": {"thinking_config": thinking_config}}}


def _gemini_openai_thinking_none_config(model: str) -> dict[str, Any]:
    lowered = model.lower()
    if "gemini-3" not in lowered:
        return {}
    level = "minimal" if "flash" in lowered else "low"
    return {"thinking_level": level}


def _merge_generation_config(output: dict[str, Any], config: dict[str, Any]) -> None:
    generation_config = output.setdefault("generationConfig", {})
    output["generationConfig"] = _merge_nested_dict(generation_config, config)


def _camelize_gemini_thinking_config(config: dict[str, Any]) -> dict[str, Any]:
    converted: dict[str, Any] = {}
    for key, value in config.items():
        if key == "thinking_budget":
            converted["thinkingBudget"] = value
        elif key == "thinking_level":
            converted["thinkingLevel"] = value
        else:
            converted[key] = value
    return converted


def _merge_request_overrides(base: dict[str, Any], overrides: dict[str, Any]) -> dict[str, Any]:
    merged = dict(base)
    for key, value in overrides.items():
        if isinstance(value, dict) and isinstance(merged.get(key), dict):
            merged[key] = _merge_nested_dict(merged[key], value)
        else:
            merged[key] = value
    return merged


def _merge_openai_request_overrides(
    base: dict[str, Any], overrides: dict[str, Any]
) -> dict[str, Any]:
    normalized = dict(overrides)
    extra_body = normalized.pop("extra_body", None)
    merged = _merge_request_overrides(base, normalized) if normalized else dict(base)
    if isinstance(extra_body, dict):
        merged = _merge_request_overrides(merged, extra_body)
    return merged


def _merge_nested_dict(base: dict[str, Any], overrides: dict[str, Any]) -> dict[str, Any]:
    merged = dict(base)
    for key, value in overrides.items():
        if isinstance(value, dict) and isinstance(merged.get(key), dict):
            merged[key] = _merge_nested_dict(merged[key], value)
        else:
            merged[key] = value
    return merged
