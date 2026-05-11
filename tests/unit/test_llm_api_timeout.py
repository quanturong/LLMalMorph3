import pytest

import src.llm_api as llm_api
import src.ollama_api as ollama_api
from src.llm_api import LLMAPIRequestError, OpenAICompatibleProvider, OllamaProvider


class _FakeStreamResponse:
    def __init__(self, lines):
        self._lines = list(lines)
        self.closed = False

    def raise_for_status(self):
        return None

    def iter_lines(self, decode_unicode=True):
        yield from self._lines

    def close(self):
        self.closed = True


def test_openai_compatible_stream_returns_content(monkeypatch):
    response = _FakeStreamResponse(
        [
            'data: {"choices":[{"delta":{"content":"hel"}}]}',
            'data: {"choices":[{"delta":{"content":"lo"}}]}',
            "data: [DONE]",
        ]
    )

    monkeypatch.setattr(llm_api.requests, "post", lambda *args, **kwargs: response)

    provider = OpenAICompatibleProvider(
        base_url="https://example.test/v1",
        api_key="test",
        model="test-model",
    )

    assert provider.generate("system", "user", timeout=30) == "hello"
    assert response.closed is True


def test_openai_compatible_stream_enforces_total_deadline(monkeypatch):
    responses = []

    def fake_post(*args, **kwargs):
        response = _FakeStreamResponse(
            [
                'data: {"choices":[{"delta":{}}]}',
                'data: {"choices":[{"delta":{}}]}',
                'data: {"choices":[{"delta":{}}]}',
                'data: {"choices":[{"delta":{}}]}',
            ]
        )
        responses.append(response)
        return response

    tick = {"value": 0.0}

    def fake_monotonic():
        tick["value"] += 1.0
        return tick["value"]

    monkeypatch.setattr(llm_api.requests, "post", fake_post)
    monkeypatch.setattr(llm_api.time, "monotonic", fake_monotonic)
    monkeypatch.setattr(llm_api.time, "sleep", lambda _: None)

    provider = OpenAICompatibleProvider(
        base_url="https://example.test/v1",
        api_key="test",
        model="test-model",
    )

    with pytest.raises(LLMAPIRequestError, match="total timeout"):
        provider.generate("system", "user", timeout=3)

    assert responses
    assert all(response.closed for response in responses)


def test_ollama_provider_returns_message_content(monkeypatch):
    class _FakeOllamaResponse:
        def raise_for_status(self):
            return None

        def json(self):
            return {"message": {"content": "hello from ollama"}}

    captured = {}

    def fake_post(url, **kwargs):
        captured["url"] = url
        captured["payload"] = kwargs.get("json")
        captured["timeout"] = kwargs.get("timeout")
        return _FakeOllamaResponse()

    monkeypatch.setattr(llm_api.requests, "post", fake_post)

    provider = OllamaProvider(
        base_url="https://qxdhstvip7o8az-11434.proxy.runpod.net/",
        api_key="",
        model="devstral-small-2:24b",
        timeout=600,
        num_ctx=65536,
    )

    assert provider.generate("system", "user", timeout=600) == "hello from ollama"
    assert captured["url"] == "https://qxdhstvip7o8az-11434.proxy.runpod.net/api/chat"
    assert captured["payload"]["model"] == "devstral-small-2:24b"
    assert captured["payload"]["options"]["temperature"] == 0.3
    assert captured["payload"]["options"]["num_ctx"] == 65536
    assert captured["timeout"] == 600


def test_ollama_chat_api_returns_message_content(monkeypatch):
    class _FakeResponse:
        def raise_for_status(self):
            return None

        def json(self):
            return {"message": {"content": "legacy helper ok"}}

    captured = {}

    def fake_post(url, **kwargs):
        captured["url"] = url
        captured["payload"] = kwargs.get("json")
        captured["timeout"] = kwargs.get("timeout")
        return _FakeResponse()

    monkeypatch.setattr(ollama_api.requests, "post", fake_post)

    text = ollama_api.ollama_chat_api(
        "codestral-2508",
        "system",
        "user",
        base_url="https://qxdhstvip7o8az-11434.proxy.runpod.net/",
        timeout=600,
        num_ctx=65536,
    )

    assert text == "legacy helper ok"
    assert captured["url"] == "https://qxdhstvip7o8az-11434.proxy.runpod.net/api/chat"
    assert captured["payload"]["model"] == "devstral-small-2:24b"
    assert captured["payload"]["stream"] is False
    assert captured["payload"]["options"]["num_ctx"] == 65536
    assert captured["timeout"] == 600
