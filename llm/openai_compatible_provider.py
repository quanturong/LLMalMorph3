"""
Async wrapper for OpenAI-compatible chat-completions endpoints.

Use this provider for hosted inference services such as RunPod OpenAI API
endpoints while keeping the same request/response contract used by the
framework's other LLM providers.
"""

from __future__ import annotations

import asyncio
import logging
import time
from typing import Optional

import requests

from .provider import (
    LLMError,
    LLMRateLimitError,
    LLMProviderInterface,
    LLMRequest,
    LLMResponse,
    LLMTimeoutError,
)

logger = logging.getLogger(__name__)


class OpenAICompatibleProvider(LLMProviderInterface):
    """Generic provider for OpenAI-compatible `/chat/completions` APIs."""

    def __init__(
        self,
        api_key: str,
        base_url: str,
        default_model: str,
        provider_name: str = "openai_compatible",
    ) -> None:
        self._api_key = api_key
        self._base_url = base_url.rstrip("/")
        self._default_model = default_model
        self._provider_name = provider_name

        if not self._api_key:
            logger.warning("API key not set for %s provider; calls will fail.", provider_name)
        if not self._base_url:
            logger.warning("Base URL not set for %s provider; calls will fail.", provider_name)

    @staticmethod
    def _is_ollama_url(base_url: str) -> bool:
        """Detect Ollama endpoints (RunPod proxied or direct)."""
        # Ollama typically serves on port 11434; RunPod proxies contain it too
        return "11434" in base_url

    @staticmethod
    def _strip_think_tags(text: str) -> str:
        """Remove <think>...</think> blocks from Ollama thinking-model output."""
        import re
        # Remove everything from start up to and including </think>
        cleaned = re.sub(r"^<think>.*?</think>\s*", "", text, count=1, flags=re.DOTALL)
        if cleaned != text:
            return cleaned
        # Also handle case where content starts with thinking but no <think> open tag
        if "</think>" in text:
            return text.split("</think>", 1)[1].strip()
        return text

    def _sync_call(self, request: LLMRequest, model: str) -> LLMResponse:
        use_native_ollama = self._is_ollama_url(self._base_url)

        if use_native_ollama:
            # Use native Ollama /api/chat — avoids the /v1 bug where qwen3
            # puts all output into "reasoning" field leaving "content" empty.
            base = self._base_url.rstrip("/")
            # Strip /v1 suffix if present to get the Ollama root URL
            if base.endswith("/v1"):
                base = base[:-3]
            endpoint = f"{base}/api/chat"
            headers = {"Content-Type": "application/json"}
        else:
            endpoint = self._base_url
            if not endpoint.endswith("/chat/completions"):
                endpoint = f"{endpoint}/chat/completions"
            if self._provider_name.startswith("salad"):
                headers = {
                    "Salad-Api-Key": self._api_key,
                    "Content-Type": "application/json",
                }
            else:
                headers = {
                    "Authorization": f"Bearer {self._api_key}",
                    "Content-Type": "application/json",
                }

        # Ollama qwen3 (non-coder): append /no_think to suppress chain-of-thought
        # qwen3-coder does not recognize /no_think — skip it for coder models
        user_prompt = request.user_prompt
        _is_qwen3_thinker = "qwen3" in model.lower() and "coder" not in model.lower()
        if use_native_ollama and _is_qwen3_thinker and "/no_think" not in user_prompt and "/think" not in user_prompt:
            user_prompt = user_prompt + "\n/no_think"

        body: dict = {
            "model": model,
            "messages": [
                {"role": "system", "content": request.system_prompt},
                {"role": "user", "content": user_prompt},
            ],
            "temperature": request.temperature,
        }

        if use_native_ollama:
            body["stream"] = True
            # Only enable think mode for qwen3 general models; qwen3-coder does NOT support it
            _supports_think = _is_qwen3_thinker
            if _supports_think:
                # think:true → model reasons in <think> block then outputs final code.
                # qwen3 thinking uses 8000-15000 tokens, so multiply budget by 4 to
                # ensure it covers thinking AND actual code output.
                _token_budget = min(request.max_tokens * 4, 32768)
            else:
                # Non-thinking model: use the requested token budget directly
                _token_budget = request.max_tokens
            body["options"] = {"num_predict": _token_budget}
            if _supports_think:
                body["think"] = True  # only send for models that support it
            if request.response_format == "json_object":
                body["format"] = "json"
        else:
            body["stream"] = True
            body["max_tokens"] = request.max_tokens
            if request.response_format == "json_object":
                body["response_format"] = {"type": "json_object"}

        start = time.monotonic()
        deadline = start + max(1.0, float(request.timeout_s))
        resp: Optional[requests.Response] = None
        try:
            resp = requests.post(
                endpoint, headers=headers, json=body,
                timeout=(30, request.timeout_s),  # (connect, read-between-chunks)
                stream=True,
            )
            resp.raise_for_status()
        except requests.exceptions.Timeout:
            if resp is not None:
                resp.close()
            raise LLMTimeoutError(f"{self._provider_name} timed out after {request.timeout_s}s")
        except requests.exceptions.HTTPError as exc:
            code = getattr(exc.response, "status_code", None)
            if code == 429:
                if resp is not None:
                    resp.close()
                raise LLMRateLimitError(f"{self._provider_name} rate limit exceeded")
            text = getattr(exc.response, "text", "")
            if resp is not None:
                resp.close()
            raise LLMError(f"{self._provider_name} HTTP {code}: {text[:200]}")
        except requests.RequestException as exc:
            if resp is not None:
                resp.close()
            raise LLMError(f"{self._provider_name} request failed: {exc}")

        import json as _json

        if use_native_ollama:
            # Ollama streaming: each line is a JSON object
            # {"message": {"content": "tok"}, "done": false}
            # Final: {"message": {"content": ""}, "done": true, "eval_count": N, ...}
            content_chunks = []
            usage_prompt = 0
            usage_completion = 0
            try:
                for raw_line in resp.iter_lines(decode_unicode=True):
                    if time.monotonic() >= deadline:
                        raise LLMTimeoutError(
                            f"{self._provider_name} total timeout after {request.timeout_s}s"
                        )
                    if not raw_line:
                        continue
                    try:
                        chunk = _json.loads(raw_line)
                    except (ValueError, _json.JSONDecodeError):
                        continue
                    msg = chunk.get("message", {})
                    tok = msg.get("content")
                    if tok:
                        content_chunks.append(tok)
                    if chunk.get("done"):
                        usage_prompt = chunk.get("prompt_eval_count", 0)
                        usage_completion = chunk.get("eval_count", 0)
                        break
            finally:
                resp.close()
            raw_content = "".join(content_chunks)
            content = self._strip_think_tags(raw_content)
            if not content.strip() and raw_content.strip():
                logger.warning("think_only_response: raw_len=%d, stripping think tags yielded empty. "
                               "Falling back to raw thinking content.",
                               len(raw_content))
                content = raw_content
        else:
            # OpenAI-compat streaming: SSE format
            # data: {"choices": [{"delta": {"content": "tok"}}]}
            # data: [DONE]
            content_chunks = []
            usage_prompt = 0
            usage_completion = 0
            try:
                for raw_line in resp.iter_lines(decode_unicode=True):
                    if time.monotonic() >= deadline:
                        raise LLMTimeoutError(
                            f"{self._provider_name} total timeout after {request.timeout_s}s"
                        )
                    if not raw_line or not raw_line.startswith("data:"):
                        continue
                    payload = raw_line[len("data:"):].strip()
                    if payload == "[DONE]":
                        break
                    try:
                        chunk = _json.loads(payload)
                    except (ValueError, _json.JSONDecodeError):
                        continue
                    delta = chunk.get("choices", [{}])[0].get("delta", {})
                    if delta.get("content"):
                        content_chunks.append(delta["content"])
                    # Some providers include usage in the final chunk
                    if chunk.get("usage"):
                        usage_prompt = chunk["usage"].get("prompt_tokens", 0)
                        usage_completion = chunk["usage"].get("completion_tokens", 0)
            finally:
                resp.close()
            content = "".join(content_chunks)
            if not content.strip():
                # Fallback: check if reasoning field was used
                logger.warning("streaming_empty_content: chunks=%d", len(content_chunks))

        elapsed = time.monotonic() - start
        logger.info("llm_call_ok (streamed): provider=%s model=%s time=%.1fs",
                     self._provider_name, model, elapsed)

        return LLMResponse(
            content=content,
            model_used=model,
            provider=self._provider_name,
            latency_s=time.monotonic() - start,
            input_tokens=usage_prompt,
            output_tokens=usage_completion,
        )

    async def generate(self, request: LLMRequest) -> LLMResponse:
        model = request.model or self._default_model
        loop = asyncio.get_running_loop()
        return await asyncio.wait_for(
            loop.run_in_executor(None, self._sync_call, request, model),
            timeout=request.timeout_s + 5,
        )
