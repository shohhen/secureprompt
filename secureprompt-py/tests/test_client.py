"""Unit tests for SecurePromptClient.

Uses respx to mock httpx transport — no real HTTP calls.
"""

from __future__ import annotations

import json

import pytest
import respx
from httpx import Response

from secureprompt import AsyncSecurePromptClient, SecurePromptClient
from secureprompt._models import (
    ChatCompletion,
    ChatCompletionChunk,
    CreateEmbeddingResponse,
)


# -- Fixtures ------------------------------------------------------------------

FAKE_CHAT_RESPONSE = {
    "id": "chatcmpl-test",
    "object": "chat.completion",
    "created": 1700000000,
    "model": "gpt-4o",
    "choices": [
        {
            "index": 0,
            "message": {"role": "assistant", "content": "Hello!"},
            "finish_reason": "stop",
        }
    ],
    "usage": {"prompt_tokens": 10, "completion_tokens": 5, "total_tokens": 15},
}

FAKE_EMBEDDING_RESPONSE = {
    "object": "list",
    "data": [{"object": "embedding", "index": 0, "embedding": [0.1, 0.2, 0.3]}],
    "model": "text-embedding-3-small",
    "usage": {"prompt_tokens": 4, "completion_tokens": 0, "total_tokens": 4},
}

FAKE_SSE_CHUNK = json.dumps({
    "id": "chatcmpl-chunk",
    "object": "chat.completion.chunk",
    "created": 1700000000,
    "model": "gpt-4o",
    "choices": [{"index": 0, "delta": {"content": "Hi"}, "finish_reason": None}],
})


# -- Sync client tests ---------------------------------------------------------

class TestSecurePromptClientInstantiation:
    def test_instantiates_with_explicit_key(self) -> None:
        client = SecurePromptClient(api_key="sp_test", base_url="http://localhost:8080")
        assert client is not None
        client.close()

    def test_instantiates_with_env_var(self, monkeypatch: pytest.MonkeyPatch) -> None:
        monkeypatch.setenv("SECUREPROMPT_API_KEY", "sp_from_env")
        monkeypatch.setenv("SECUREPROMPT_BASE_URL", "http://localhost:8080")
        client = SecurePromptClient()
        assert client is not None
        client.close()

    def test_raises_without_api_key(self, monkeypatch: pytest.MonkeyPatch) -> None:
        monkeypatch.delenv("SECUREPROMPT_API_KEY", raising=False)
        with pytest.raises(ValueError, match="api_key must be provided"):
            SecurePromptClient(base_url="http://localhost:8080")

    def test_has_chat_and_embeddings_namespaces(self) -> None:
        client = SecurePromptClient(api_key="sp_test", base_url="http://localhost:8080")
        assert hasattr(client, "chat")
        assert hasattr(client.chat, "completions")
        assert hasattr(client, "embeddings")
        client.close()


class TestChatCompletions:
    @respx.mock
    def test_non_streaming_returns_chat_completion(self) -> None:
        respx.post("http://localhost:8080/v1/chat/completions").mock(
            return_value=Response(200, json=FAKE_CHAT_RESPONSE)
        )
        client = SecurePromptClient(api_key="sp_test", base_url="http://localhost:8080")
        result = client.chat.completions.create(
            model="gpt-4o",
            messages=[{"role": "user", "content": "Hello"}],
        )
        assert isinstance(result, ChatCompletion)
        assert result.choices[0].message.content == "Hello!"
        client.close()

    @respx.mock
    def test_authorization_header_sent(self) -> None:
        route = respx.post("http://localhost:8080/v1/chat/completions").mock(
            return_value=Response(200, json=FAKE_CHAT_RESPONSE)
        )
        client = SecurePromptClient(api_key="sp_mykey", base_url="http://localhost:8080")
        client.chat.completions.create(model="gpt-4o", messages=[])
        assert route.calls[0].request.headers["authorization"] == "Bearer sp_mykey"
        client.close()


class TestEmbeddings:
    @respx.mock
    def test_embeddings_create(self) -> None:
        respx.post("http://localhost:8080/v1/embeddings").mock(
            return_value=Response(200, json=FAKE_EMBEDDING_RESPONSE)
        )
        client = SecurePromptClient(api_key="sp_test", base_url="http://localhost:8080")
        result = client.embeddings.create(input="Hello world")
        assert isinstance(result, CreateEmbeddingResponse)
        assert len(result.data) == 1
        assert result.data[0].embedding == [0.1, 0.2, 0.3]
        client.close()


# -- Async client tests --------------------------------------------------------

class TestAsyncSecurePromptClient:
    async def test_instantiates(self) -> None:
        client = AsyncSecurePromptClient(api_key="sp_test", base_url="http://localhost:8080")
        assert client is not None
        await client.aclose()

    @respx.mock
    async def test_async_chat_completion(self) -> None:
        respx.post("http://localhost:8080/v1/chat/completions").mock(
            return_value=Response(200, json=FAKE_CHAT_RESPONSE)
        )
        async with AsyncSecurePromptClient(
            api_key="sp_test", base_url="http://localhost:8080"
        ) as client:
            result = await client.chat.completions.create(
                model="gpt-4o",
                messages=[{"role": "user", "content": "Hello"}],
            )
        assert isinstance(result, ChatCompletion)
        assert result.id == "chatcmpl-test"


# -- Model validation tests ----------------------------------------------------

class TestModels:
    def test_chat_completion_chunk_parses(self) -> None:
        chunk = ChatCompletionChunk.from_json(FAKE_SSE_CHUNK)
        assert chunk.choices[0].delta.content == "Hi"

    def test_chat_completion_parses(self) -> None:
        cc = ChatCompletion.from_dict(FAKE_CHAT_RESPONSE)
        assert cc.model == "gpt-4o"
        assert cc.usage is not None
        assert cc.usage.total_tokens == 15
