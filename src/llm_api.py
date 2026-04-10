"""
Unified LLM API interface supporting both Ollama (local) and Mistral API (cloud).
Provides error handling, retry mechanism, and logging.
"""

import os
import re
import time
import logging
import requests
from typing import Optional, Dict, Any, Tuple
from functools import wraps

logger = logging.getLogger(__name__)

# Optional imports for Ollama (not needed on some environments)
try:
    import ollama
    OLLAMA_AVAILABLE = True
except ImportError:
    ollama = None
    OLLAMA_AVAILABLE = False


# =========================
# Exceptions
# =========================
class LLMAPIError(Exception):
    """Base LLM API error."""
    pass


class LLMAPIKeyError(LLMAPIError):
    """Missing/invalid API key."""
    pass


class LLMAPIRequestError(LLMAPIError):
    """Network / rate limit / provider request failure."""
    pass


# =========================
# Retry helper
# =========================
def retry_on_failure(max_retries: int = 3, delay: float = 1.0, backoff: float = 2.0):
    def deco(fn):
        @wraps(fn)
        def wrapper(*args, **kwargs):
            d = delay
            last_exc = None
            for _ in range(max_retries):
                try:
                    return fn(*args, **kwargs)
                except Exception as e:
                    last_exc = e
                    time.sleep(d)
                    d *= backoff
            raise last_exc
        return wrapper
    return deco


# =========================
# Provider base
# =========================
class LLMProvider:
    def generate(self, system_prompt: str, user_prompt: str, **kwargs) -> str:
        raise NotImplementedError

    def generate_chat(self, messages: list, **kwargs) -> str:
        # Optional override
        raise NotImplementedError


# =========================
# Mistral (cloud)
# =========================
class MistralAPIProvider(LLMProvider):
    """Mistral API provider (Codestral)."""
    BASE_URL = "https://api.mistral.ai/v1/chat/completions"

    def __init__(self, api_key: Optional[str] = None):
        self.api_key = api_key or os.getenv("MISTRAL_API_KEY")
        if not self.api_key:
            raise LLMAPIKeyError(
                "Mistral API key not found. Please set MISTRAL_API_KEY env var or pass api_key."
            )
        logger.info("Mistral API provider initialized")

    @retry_on_failure(max_retries=3, delay=1.0, backoff=2.0)
    def generate(
        self,
        system_prompt: str,
        user_prompt: str,
        model: str = "codestral-latest",
        temperature: float = 0.4,
        top_p: float = 0.9,
        seed: Optional[int] = None,
        timeout: int = 60,
        **kwargs
    ) -> str:
        headers = {
            "Authorization": f"Bearer {self.api_key}",
            "Content-Type": "application/json",
        }
        messages = [
            {"role": "system", "content": system_prompt},
            {"role": "user", "content": user_prompt},
        ]
        data: Dict[str, Any] = {
            "model": model,
            "messages": messages,
            "temperature": temperature,
            "top_p": top_p,
        }
        if seed is not None:
            data["random_seed"] = seed

        start_time = time.time()
        try:
            resp = requests.post(self.BASE_URL, headers=headers, json=data, timeout=timeout)
            resp.raise_for_status()
            result = resp.json()
            if "choices" not in result or not result["choices"]:
                raise LLMAPIRequestError("Invalid response format from Mistral API")
            content = result["choices"][0]["message"]["content"]
            # Strip reasoning model <think>...</think> blocks
            content = re.sub(r'<think>.*?</think>', '', content, flags=re.DOTALL).strip()
            if '<think>' in content:
                content = re.sub(r'<think>.*', '', content, flags=re.DOTALL).strip()
            elapsed = time.time() - start_time
            logger.info(
                f"Mistral API call successful. Model: {model}, Time: {elapsed:.2f}s, "
                f"Tokens: {result.get('usage', {}).get('total_tokens', 'N/A')}"
            )
            return content

        except requests.exceptions.Timeout:
            raise LLMAPIRequestError(f"Request timeout after {timeout} seconds")
        except requests.exceptions.HTTPError as e:
            code = getattr(e.response, "status_code", None)
            if code == 401:
                raise LLMAPIKeyError("Invalid Mistral API key")
            if code == 429:
                raise LLMAPIRequestError("Rate limit exceeded. Please try again later.")
            text = getattr(e.response, "text", "")
            raise LLMAPIRequestError(f"HTTP {code}: {text}")
        except requests.exceptions.RequestException as e:
            raise LLMAPIRequestError(f"Request failed: {str(e)}")

    def generate_chat(self, messages: list, model: str = "codestral-latest", **kwargs) -> str:
        # Minimal wrapper: convert chat -> single call
        # (your code mostly uses generate(); keep this for compatibility)
        system = ""
        user_parts = []
        for m in messages:
            if m.get("role") == "system":
                system += (m.get("content") or "") + "\n"
            elif m.get("role") == "user":
                user_parts.append(m.get("content") or "")
            else:
                # assistant turns: include as context
                user_parts.append(f"[{m.get('role','assistant')}] {m.get('content','')}")
        return self.generate(system_prompt=system.strip(), user_prompt="\n".join(user_parts), model=model, **kwargs)


# =========================
# DeepSeek (cloud)
# =========================
class DeepSeekProvider(LLMProvider):
    """DeepSeek API provider (OpenAI-compatible)."""
    BASE_URL = "https://api.deepseek.com/v1/chat/completions"

    def __init__(self, api_key: Optional[str] = None):
        self.api_key = api_key or os.getenv("DEEPSEEK_API_KEY")
        if not self.api_key:
            raise LLMAPIKeyError(
                "DeepSeek API key not found. Please set DEEPSEEK_API_KEY env var or pass api_key."
            )
        logger.info("DeepSeek API provider initialized")

    @retry_on_failure(max_retries=3, delay=1.0, backoff=2.0)
    def generate(
        self,
        system_prompt: str,
        user_prompt: str,
        model: str = "deepseek-chat",
        temperature: float = 0.3,
        top_p: float = 0.9,
        seed: Optional[int] = None,
        timeout: int = 120,
        **kwargs
    ) -> str:
        headers = {
            "Authorization": f"Bearer {self.api_key}",
            "Content-Type": "application/json",
        }
        messages = [
            {"role": "system", "content": system_prompt},
            {"role": "user", "content": user_prompt},
        ]
        data: Dict[str, Any] = {
            "model": model,
            "messages": messages,
            "temperature": temperature,
            "top_p": top_p,
        }
        if seed is not None:
            data["seed"] = seed

        start_time = time.time()
        try:
            resp = requests.post(self.BASE_URL, headers=headers, json=data, timeout=timeout)
            resp.raise_for_status()
            result = resp.json()
            if "choices" not in result or not result["choices"]:
                raise LLMAPIRequestError("Invalid response format from DeepSeek API")
            content = result["choices"][0]["message"]["content"]
            # Strip reasoning model <think>...</think> blocks
            content = re.sub(r'<think>.*?</think>', '', content, flags=re.DOTALL).strip()
            if '<think>' in content:
                content = re.sub(r'<think>.*', '', content, flags=re.DOTALL).strip()
            elapsed = time.time() - start_time
            logger.info(
                f"DeepSeek API call successful. Model: {model}, Time: {elapsed:.2f}s, "
                f"Tokens: {result.get('usage', {}).get('total_tokens', 'N/A')}"
            )
            return content

        except requests.exceptions.Timeout:
            raise LLMAPIRequestError(f"Request timeout after {timeout} seconds")
        except requests.exceptions.HTTPError as e:
            code = getattr(e.response, "status_code", None)
            if code == 401:
                raise LLMAPIKeyError("Invalid DeepSeek API key")
            if code == 429:
                raise LLMAPIRequestError("Rate limit exceeded. Please try again later.")
            text = getattr(e.response, "text", "")
            raise LLMAPIRequestError(f"HTTP {code}: {text}")
        except requests.exceptions.RequestException as e:
            raise LLMAPIRequestError(f"Request failed: {str(e)}")

    def generate_chat(self, messages: list, model: str = "deepseek-chat", **kwargs) -> str:
        system = ""
        user_parts = []
        for m in messages:
            if m.get("role") == "system":
                system += (m.get("content") or "") + "\n"
            elif m.get("role") == "user":
                user_parts.append(m.get("content") or "")
            else:
                user_parts.append(f"[{m.get('role','assistant')}] {m.get('content','')}")
        return self.generate(system_prompt=system.strip(), user_prompt="\n".join(user_parts), model=model, **kwargs)


# =========================
# Ollama (local)
# =========================
class OllamaProvider(LLMProvider):
    def __init__(
        self,
        model: str = "qwen2.5-coder:7b-instruct-q4_K_M",
        base_url: str = "http://localhost:11434",
        timeout: int = 300,
    ):
        if not OLLAMA_AVAILABLE:
            raise LLMAPIError("Ollama is not available. Install with: pip install ollama")
        self.model = model
        self.base_url = base_url
        self.timeout = timeout
        self.client = ollama.Client(host=base_url, timeout=timeout)
        logger.info(f"Ollama provider initialized with model: {model}, timeout: {timeout}s")

    @retry_on_failure(max_retries=3, delay=1.0, backoff=2.0)
    def generate(
        self,
        system_prompt: str,
        user_prompt: str,
        model: Optional[str] = None,
        temperature: float = 0.3,
        top_k: int = 20,
        top_p: float = 0.85,
        seed: Optional[int] = 42,
        **kwargs
    ) -> str:
        model = model or self.model
        start = time.time()
        try:
            resp = self.client.chat(
                model=model,
                messages=[
                    {"role": "system", "content": system_prompt},
                    {"role": "user", "content": user_prompt},
                ],
                options={
                    "temperature": temperature,
                    "top_k": top_k,
                    "top_p": top_p,
                    "seed": seed,
                },
            )
            elapsed = time.time() - start
            content = re.sub(r'<think>.*?</think>', '', resp["message"]["content"], flags=re.DOTALL).strip()
            if '<think>' in content:
                content = re.sub(r'<think>.*', '', content, flags=re.DOTALL).strip()
            logger.info(f"Ollama call successful. Model: {model}, Time: {elapsed:.2f}s")
            return content
        except Exception as e:
            raise LLMAPIRequestError(f"Ollama API call failed: {str(e)}")

    def generate_chat(self, messages: list, model: Optional[str] = None, seed: Optional[int] = 42, **kwargs) -> str:
        model = model or self.model
        start = time.time()
        try:
            resp = self.client.chat(
                model=model,
                messages=messages,
                options={"seed": seed},
            )
            elapsed = time.time() - start
            content = re.sub(r'<think>.*?</think>', '', resp["message"]["content"], flags=re.DOTALL).strip()
            logger.info(f"Ollama multi-turn call successful. Model: {model}, Time: {elapsed:.2f}s")
            return content
        except Exception as e:
            raise LLMAPIRequestError(f"Ollama chat failed: {str(e)}")


# =========================
# OpenAI-Compatible Provider (RunPod / any OpenAI-format endpoint)
# =========================
class OpenAICompatibleProvider(LLMProvider):
    """Generic OpenAI-compatible provider for RunPod, local Ollama via /v1, etc."""

    def __init__(
        self,
        base_url: str,
        api_key: str = "ollama",
        model: str = "qwen2.5:32b",
        timeout: int = 300,
    ):
        self.base_url = base_url.rstrip("/")
        self.api_key = api_key
        self.model = model
        self.timeout = timeout
        logger.info(f"OpenAI-compatible provider: {base_url}, model={model}")

    @retry_on_failure(max_retries=3, delay=2.0, backoff=2.0)
    def generate(
        self,
        system_prompt: str,
        user_prompt: str,
        model: Optional[str] = None,
        temperature: float = 0.3,
        top_p: float = 0.9,
        seed: Optional[int] = None,
        timeout: Optional[int] = None,
        **kwargs,
    ) -> str:
        model = model or self.model
        timeout = timeout or self.timeout
        # SaladCloud uses Salad-Api-Key header instead of Bearer token
        if "salad.cloud" in self.base_url:
            headers = {
                "Salad-Api-Key": self.api_key,
                "Content-Type": "application/json",
            }
        else:
            headers = {
                "Authorization": f"Bearer {self.api_key}",
                "Content-Type": "application/json",
            }
        data: Dict[str, Any] = {
            "model": model,
            "messages": [
                {"role": "system", "content": system_prompt},
                {"role": "user", "content": user_prompt},
            ],
            "temperature": temperature,
            "top_p": top_p,
        }
        if seed is not None:
            data["seed"] = seed
        start = time.time()
        try:
            resp = requests.post(
                f"{self.base_url}/chat/completions",
                headers=headers,
                json=data,
                timeout=timeout,
            )
            resp.raise_for_status()
            result = resp.json()
            if "choices" not in result or not result["choices"]:
                raise LLMAPIRequestError("Invalid response from OpenAI-compatible API")
            msg = result["choices"][0]["message"]
            content = re.sub(r'<think>.*?</think>', '', msg.get("content") or "", flags=re.DOTALL).strip()
            if '<think>' in content:
                content = re.sub(r'<think>.*', '', content, flags=re.DOTALL).strip()
            # Ollama reasoning models return chain-of-thought in "reasoning" field
            if not content and msg.get("reasoning"):
                content = msg["reasoning"].strip()
            elapsed = time.time() - start
            logger.info(f"OpenAI-compat call OK. model={model}, time={elapsed:.1f}s")
            return content
        except requests.exceptions.Timeout:
            raise LLMAPIRequestError(f"Request timeout after {timeout}s")
        except requests.exceptions.HTTPError as e:
            code = getattr(e.response, "status_code", None)
            text = getattr(e.response, "text", "")
            raise LLMAPIRequestError(f"HTTP {code}: {text}")
        except requests.exceptions.RequestException as e:
            raise LLMAPIRequestError(f"Request failed: {str(e)}")

    def generate_chat(self, messages: list, model: Optional[str] = None, **kwargs) -> str:
        system = ""
        user_parts = []
        for m in messages:
            role = m.get("role", "user")
            content = m.get("content") or ""
            if role == "system":
                system += content + "\n"
            elif role == "user":
                user_parts.append(content)
            else:
                user_parts.append(f"[{role}] {content}")
        return self.generate(
            system_prompt=system.strip(),
            user_prompt="\n".join(user_parts),
            model=model,
            **kwargs,
        )


# =========================
# Parallel Race Provider
# =========================
class RaceLLMProvider(LLMProvider):
    """Fire identical requests to multiple providers in parallel; return the first success."""

    def __init__(self, providers: list, label: str = "race"):
        if not providers:
            raise ValueError("RaceLLMProvider needs at least one provider")
        self.providers = providers
        self.label = label
        self._win_counts: dict = {}  # track which provider wins most often
        logger.info(f"RaceLLMProvider({label}): {len(providers)} contestants")

    def generate(self, system_prompt: str, user_prompt: str, **kwargs) -> str:
        return self._race("generate", system_prompt=system_prompt, user_prompt=user_prompt, **kwargs)

    def generate_chat(self, messages: list, **kwargs) -> str:
        return self._race("generate_chat", messages=messages, **kwargs)

    def _race(self, method: str, **kwargs) -> str:
        from concurrent.futures import ThreadPoolExecutor, as_completed
        import threading
        cancel = threading.Event()

        def _call(idx, provider):
            if cancel.is_set():
                return None
            try:
                fn = getattr(provider, method)
                result = fn(**kwargs)
                return (idx, result)
            except NotImplementedError:
                # generate_chat not supported → fall back to generate
                if method == "generate_chat" and hasattr(provider, "generate"):
                    msgs = kwargs.get("messages", [])
                    sys_parts, usr_parts = [], []
                    for m in msgs:
                        (sys_parts if m.get("role") == "system" else usr_parts).append(m.get("content", ""))
                    return (idx, provider.generate(
                        system_prompt="\n".join(sys_parts),
                        user_prompt="\n".join(usr_parts),
                        **{k: v for k, v in kwargs.items() if k != "messages"},
                    ))
                return None
            except Exception as e:
                logger.warning(f"Race contestant {idx} failed: {e}")
                return None

        errors = []
        with ThreadPoolExecutor(max_workers=len(self.providers)) as pool:
            futures = {pool.submit(_call, i, p): i for i, p in enumerate(self.providers)}
            for fut in as_completed(futures):
                try:
                    pair = fut.result()
                    if pair is not None:
                        idx, text = pair
                        if text:
                            cancel.set()  # signal others to stop
                            winner = type(self.providers[idx]).__name__
                            self._win_counts[idx] = self._win_counts.get(idx, 0) + 1
                            logger.info(f"Race winner: contestant {idx} ({winner})")
                            return text
                except Exception as e:
                    errors.append(e)

        raise LLMAPIRequestError(
            f"All {len(self.providers)} race contestants failed: "
            + "; ".join(str(e) for e in errors[:3])
        )


# =========================
# Factory
# =========================
def get_llm_provider(model_name: str, api_key: Optional[str] = None) -> LLMProvider:
    # Mistral models
    if model_name.startswith("codestral-") or model_name == "codestral-latest" or model_name.startswith("mistral-"):
        return MistralAPIProvider(api_key=api_key)
    # DeepSeek models (API-only, not Ollama format like deepseek-r1:32b)
    if model_name.startswith("deepseek-") and ":" not in model_name:
        return DeepSeekProvider(api_key=api_key)
    # RunPod / remote OpenAI-compatible endpoint (env var takes priority over local Ollama)
    runpod_url = os.getenv("CLOUD_URL")
    if runpod_url:
        runpod_key = api_key or os.getenv("RUNPOD_API_KEY", "ollama")
        # Check for secondary cloud URLs for parallel race
        cloud_urls_raw = os.getenv("CLOUD_URLS", "")  # comma-separated
        extra_urls = [u.strip().rstrip("/") for u in cloud_urls_raw.split(",") if u.strip()]
        if extra_urls:
            providers = [OpenAICompatibleProvider(base_url=runpod_url, api_key=runpod_key, model=model_name)]
            for url in extra_urls:
                # Each extra endpoint uses the same API key (SaladCloud)
                providers.append(OpenAICompatibleProvider(base_url=url, api_key=runpod_key, model=model_name))
            logger.info(f"Building RaceLLMProvider with {len(providers)} endpoints")
            return RaceLLMProvider(providers, label="cloud_race")
        return OpenAICompatibleProvider(base_url=runpod_url, api_key=runpod_key, model=model_name)
    # Default: local Ollama
    return OllamaProvider(model=model_name)


def ollama_chat_api(
    model_name: str,
    system_prompt: str,
    user_prompt: str,
    seed: int = 42,
    api_key: Optional[str] = None,
) -> str:
    provider = get_llm_provider(model_name, api_key=api_key)
    model = model_name.replace(":", "-") if isinstance(provider, MistralAPIProvider) else model_name
    return provider.generate(system_prompt=system_prompt, user_prompt=user_prompt, model=model, seed=seed)


# =========================
# Hybrid Provider
# =========================
class HybridLLMProvider:
    """
    Hybrid routing between local (Ollama) and cloud (Mistral).
    mode:
      - "hybrid": route by size/errors
      - "local_only": ALWAYS local, and if local fails -> raise (NO cloud fallback)
      - "cloud_only": ALWAYS cloud
    """

    def __init__(
        self,
        local_model: str = "qwen2.5-coder:7b-instruct-q4_K_M",
        cloud_model: str = "codestral-2508",
        api_key: Optional[str] = None,
        cloud_file_size_limit: int = 15000,
        local_context_limit: int = 30000,
        local_error_threshold: int = 5,
        mode: str = "hybrid",
        cloud_provider_type: str = "auto",
    ):
        self.local_model = local_model
        self.cloud_model = cloud_model
        self.cloud_file_size_limit = cloud_file_size_limit
        self.local_context_limit = local_context_limit
        self.local_error_threshold = local_error_threshold
        self.mode = mode
        self.cloud_provider_type = cloud_provider_type

        self.has_local = False
        self.has_cloud = False
        self.local_provider = None
        self.cloud_provider = None

        if mode in ("hybrid", "local_only"):
            self.local_provider = OllamaProvider(model=local_model)
            self.has_local = True

        if mode in ("hybrid", "cloud_only"):
            # Choose cloud provider based on cloud_provider_type or model name
            resolved_type = cloud_provider_type
            if resolved_type == "auto":
                if cloud_model.startswith("deepseek-"):
                    resolved_type = "deepseek"
                elif os.getenv("CLOUD_URL"):
                    resolved_type = "runpod"
                else:
                    resolved_type = "mistral"

            if resolved_type == "deepseek":
                deepseek_key = api_key or os.getenv("DEEPSEEK_API_KEY")
                self.cloud_provider = DeepSeekProvider(api_key=deepseek_key)
                logger.info(f"☁️ Cloud provider: DeepSeek ({cloud_model})")
            elif resolved_type in ("runpod", "openai_compatible"):
                runpod_url = os.getenv("CLOUD_URL", "")
                runpod_key = api_key or os.getenv("RUNPOD_API_KEY", "ollama")
                self.cloud_provider = OpenAICompatibleProvider(
                    base_url=runpod_url, api_key=runpod_key, model=cloud_model
                )
                logger.info(f"☁️ Cloud provider: RunPod/OpenAI-compat ({cloud_model}) → {runpod_url}")
            else:
                self.cloud_provider = MistralAPIProvider(api_key=api_key)
                logger.info(f"☁️ Cloud provider: Mistral ({cloud_model})")
            self.has_cloud = True

        if not self.has_local and not self.has_cloud:
            raise LLMAPIError("No LLM provider available! Check Ollama or API key.")

        self.stats = {
            "local_calls": 0,
            "cloud_calls": 0,
            "local_success": 0,
            "cloud_success": 0,
            "cloud_rate_limits": 0,
            "cloud_fallbacks": 0,
            "cost_saved": 0.0,
        }

        self._cloud_consecutive_fails = 0
        self._cloud_cooldown_until = 0.0
        self._CLOUD_COOLDOWN_THRESHOLD = 2
        self._CLOUD_COOLDOWN_SECONDS = 300

        if mode == "local_only":
            logger.info("🏠 LOCAL ONLY mode: All requests → Ollama (no cloud fallback)")
        elif mode == "cloud_only":
            logger.info("☁️ CLOUD ONLY mode: All requests → Mistral")
        else:
            logger.info("🔀 HYBRID mode: smart routing")

    def choose_provider(self, file_size: int, error_count: int, is_header: bool = False) -> Tuple[LLMProvider, str]:
        if self.mode == "local_only":
            if not self.has_local:
                raise LLMAPIError("LOCAL_ONLY mode but Ollama not available!")
            return self.local_provider, "local_only_mode"

        if self.mode == "cloud_only":
            if not self.has_cloud:
                raise LLMAPIError("CLOUD_ONLY mode but cloud not available!")
            return self.cloud_provider, "cloud_only_mode"

        # hybrid
        now = time.time()
        if self.has_cloud and self._cloud_consecutive_fails >= self._CLOUD_COOLDOWN_THRESHOLD:
            if now < self._cloud_cooldown_until and self.has_local:
                remaining = int(self._cloud_cooldown_until - now)
                logger.info(f"☁️ Cloud on cooldown ({remaining}s left), routing to local")
                return self.local_provider, "cloud_cooldown"
            if now >= self._cloud_cooldown_until:
                self._cloud_consecutive_fails = 0

        if is_header and self.has_cloud:
            return self.cloud_provider, "header_critical"

        # ── Deterministic easy-task shortcut: few errors + small file → local ──
        if error_count <= 3 and file_size <= 5000 and self.has_local:
            return self.local_provider, "easy_task_local"

        # ── Deterministic hard-task shortcut: many errors or large context → cloud ──
        if (error_count > 20 or file_size > 25000) and self.has_cloud:
            return self.cloud_provider, "hard_task_cloud"

        if file_size > self.cloud_file_size_limit and self.has_local:
            return self.local_provider, "file_too_large_use_local"
        if error_count > self.local_error_threshold and self.has_cloud:
            return self.cloud_provider, "too_many_errors"
        if file_size <= self.cloud_file_size_limit and self.has_cloud:
            return self.cloud_provider, "small_file_use_cloud"
        if self.has_local:
            return self.local_provider, "cloud_unavailable"

        raise LLMAPIError("No LLM provider available")

    def generate(
        self,
        system_prompt: str,
        user_prompt: str,
        model: Optional[str] = None,
        seed: Optional[int] = None,
        file_size: int = 10000,
        error_count: int = 3,
        is_header: bool = False,
    ) -> str:
        provider, reason = self.choose_provider(file_size, error_count, is_header)
        cloud_name = "DeepSeek" if isinstance(self.cloud_provider, DeepSeekProvider) else "Mistral"
        provider_name = "Local (Ollama)" if provider == self.local_provider else f"Cloud ({cloud_name})"
        logger.info(f"Using {provider_name} (reason: {reason})")

        if provider == self.local_provider:
            self.stats["local_calls"] += 1
        else:
            self.stats["cloud_calls"] += 1

        try:
            result = provider.generate(
                system_prompt=system_prompt,
                user_prompt=user_prompt,
                model=model or (self.local_model if provider == self.local_provider else self.cloud_model),
                seed=seed,
            )
            if provider == self.local_provider:
                self.stats["local_success"] += 1
                self.stats["cost_saved"] += 0.08
            else:
                self.stats["cloud_success"] += 1
                self._cloud_consecutive_fails = 0
            return result

        except Exception as e:
            logger.error(f"Provider failed: {e}", exc_info=True)

            # ✅ CRITICAL: local_only means NO fallback
            if self.mode == "local_only":
                raise LLMAPIRequestError(
                    f"Local-only mode: local provider failed and cloud fallback is disabled. Cause: {e}"
                ) from e

            # Hybrid fallback behavior
            is_rate_limit = "rate limit" in str(e).lower() or "429" in str(e)
            if provider == self.cloud_provider and is_rate_limit:
                self._cloud_consecutive_fails += 1
                self.stats["cloud_rate_limits"] += 1
                if self._cloud_consecutive_fails >= self._CLOUD_COOLDOWN_THRESHOLD:
                    self._cloud_cooldown_until = time.time() + self._CLOUD_COOLDOWN_SECONDS
                    logger.warning(
                        f"☁️ Cloud hit {self._cloud_consecutive_fails} consecutive rate limits, "
                        f"cooling down for {self._CLOUD_COOLDOWN_SECONDS}s"
                    )

            if provider == self.local_provider and self.has_cloud:
                logger.info("Falling back to cloud provider...")
                self.stats["cloud_calls"] += 1
                try:
                    result = self.cloud_provider.generate(
                        system_prompt=system_prompt,
                        user_prompt=user_prompt,
                        model=self.cloud_model,
                        seed=seed,
                    )
                    self.stats["cloud_success"] += 1
                    return result
                except Exception as e2:
                    logger.error(f"Cloud fallback also failed: {e2}", exc_info=True)
                    raise

            if provider == self.cloud_provider and self.has_local:
                logger.info("Cloud failed, falling back to local Ollama...")
                self.stats["cloud_fallbacks"] += 1
                self.stats["local_calls"] += 1
                try:
                    result = self.local_provider.generate(
                        system_prompt=system_prompt,
                        user_prompt=user_prompt,
                        model=self.local_model,
                        seed=seed,
                    )
                    self.stats["local_success"] += 1
                    self.stats["cost_saved"] += 0.08
                    return result
                except Exception as e2:
                    logger.error(f"Local fallback also failed: {e2}", exc_info=True)
                    raise

            raise

    def generate_chat(self, messages: list, model: Optional[str] = None, seed: Optional[int] = None, **kwargs) -> str:
        # Keep compatibility; route by using text size heuristic
        joined = "\n".join([(m.get("content") or "") for m in messages])
        return self.generate(
            system_prompt="",
            user_prompt=joined,
            model=model,
            seed=seed,
            file_size=len(joined),
            error_count=kwargs.get("error_count", 0),
            is_header=kwargs.get("is_header", False),
        )