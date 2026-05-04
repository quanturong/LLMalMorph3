import pytest

import src.llm_api as llm_api
from src.llm_api import LLMAPIRequestError, OpenAICompatibleProvider


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
