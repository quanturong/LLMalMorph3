import json
import os

import requests


DEFAULT_OLLAMA_BASE_URL = os.getenv(
    "OLLAMA_BASE_URL",
    os.getenv("CLOUD_URL", "https://r9wu0wuqw3guyw-11434.proxy.runpod.net/"),
).rstrip("/")
DEFAULT_OLLAMA_MODEL = os.getenv("OLLAMA_MODEL", os.getenv("LLM_CLOUD_MODEL", "devstral-small-2:24b"))
DEFAULT_OLLAMA_TIMEOUT_S = int(os.getenv("OLLAMA_TIMEOUT_S", os.getenv("LLM_REQUEST_TIMEOUT_S", "600")))
DEFAULT_OLLAMA_NUM_CTX = int(os.getenv("OLLAMA_NUM_CTX", "65536"))


def _resolve_model_name(model_name):
    if not model_name:
        return DEFAULT_OLLAMA_MODEL
    lowered = model_name.lower()
    if lowered.startswith(("codestral", "mistral")):
        return DEFAULT_OLLAMA_MODEL
    return model_name


def _build_endpoint(base_url=None):
    base = (base_url or DEFAULT_OLLAMA_BASE_URL).rstrip("/")
    if base.endswith("/v1"):
        base = base[:-3]
    return f"{base}/api/chat"


def ollama_chat_api(model_name, system_prompt, user_prompt, seed=42, base_url=None, timeout=None, num_ctx=None):
    """Call Ollama chat directly and return the assistant text content."""
    payload = {
        "model": _resolve_model_name(model_name),
        "messages": [
            {"role": "system", "content": system_prompt},
            {"role": "user", "content": user_prompt},
        ],
        "stream": False,
        "options": {
            "temperature": 0.1,
            "num_ctx": int(num_ctx or DEFAULT_OLLAMA_NUM_CTX),
        },
    }

    endpoint = _build_endpoint(base_url)
    response = requests.post(endpoint, json=payload, timeout=timeout or DEFAULT_OLLAMA_TIMEOUT_S)
    response.raise_for_status()
    return response.json()["message"]["content"]


def ollama_generate_api(model_name, prompt):
    """Generate API wrapper kept for backward compatibility."""
    return ollama_chat_api(model_name or DEFAULT_OLLAMA_MODEL, "", prompt, seed=42)


def ollama_openai_chat_api(openai_client, model_name, system_prompt, user_prompt):
    """OpenAI-compatible wrapper kept for backward compatibility."""
    return ollama_chat_api(model_name or DEFAULT_OLLAMA_MODEL, system_prompt, user_prompt, seed=42)


def print_model_names():
    print(f"Available model: {DEFAULT_OLLAMA_MODEL}")

