"""SecurePrompt client classes.

Mirrors openai-python client shape (D-06) for drop-in substitution:
    client = SecurePromptClient(api_key="...", base_url="...")
    client.chat.completions.create(model="...", messages=[...])
    client.chat.completions.create(model="...", messages=[...], stream=True)
    client.embeddings.create(input="...", model="...")

    async_client = AsyncSecurePromptClient(...)
    await async_client.chat.completions.create(...)

Constructor args (D-06, SDK-03):
    api_key:  API key. Falls back to SECUREPROMPT_API_KEY env var.
    base_url: Gateway base URL. Falls back to SECUREPROMPT_BASE_URL env var,
              then http://localhost:8080.
    timeout:  Request timeout in seconds (default 60).
"""

from __future__ import annotations

import os
from typing import TYPE_CHECKING, Any, Union, overload

import httpx

from secureprompt._models import ChatCompletion, CreateEmbeddingResponse
from secureprompt._streaming import AsyncChatCompletionStream, ChatCompletionStream

if TYPE_CHECKING:
    pass


# -- Synchronous namespaces ----------------------------------------------------

class _Completions:
    """client.chat.completions namespace."""

    def __init__(self, http: httpx.Client) -> None:
        self._http = http

    @overload
    def create(
        self,
        *,
        model: str,
        messages: list[dict[str, Any]],
        stream: bool = False,
        max_tokens: int | None = None,
        temperature: float | None = None,
        **kwargs: Any,
    ) -> ChatCompletion: ...

    @overload
    def create(
        self,
        *,
        model: str,
        messages: list[dict[str, Any]],
        stream: bool = True,
        max_tokens: int | None = None,
        temperature: float | None = None,
        **kwargs: Any,
    ) -> ChatCompletionStream: ...

    def create(
        self,
        *,
        model: str,
        messages: list[dict[str, Any]],
        stream: bool = False,
        max_tokens: int | None = None,
        temperature: float | None = None,
        **kwargs: Any,
    ) -> Union[ChatCompletion, ChatCompletionStream]:
        """Create a chat completion.

        Args:
            model: Model identifier (e.g. 'gpt-4o', 'claude-3-5-sonnet-20241022').
            messages: List of message dicts with 'role' and 'content'.
            stream: If True, returns a ChatCompletionStream iterator (D-07).
            max_tokens: Maximum tokens to generate.
            temperature: Sampling temperature (0.0-2.0).
            **kwargs: Additional parameters forwarded to the API.

        Returns:
            ChatCompletion (non-streaming) or ChatCompletionStream (streaming).
        """
        payload: dict[str, Any] = {
            "model": model,
            "messages": messages,
            "stream": stream,
        }
        if max_tokens is not None:
            payload["max_tokens"] = max_tokens
        if temperature is not None:
            payload["temperature"] = temperature
        payload.update(kwargs)

        if stream:
            response = self._http.stream("POST", "/v1/chat/completions", json=payload)
            # Enter the context manager to start the request.
            ctx = response.__enter__()
            ctx.raise_for_status()
            return ChatCompletionStream(ctx)
        else:
            response = self._http.post("/v1/chat/completions", json=payload)
            response.raise_for_status()
            return ChatCompletion.from_dict(response.json())


class _Chat:
    """client.chat namespace."""

    def __init__(self, http: httpx.Client) -> None:
        self.completions = _Completions(http)


class _Embeddings:
    """client.embeddings namespace."""

    def __init__(self, http: httpx.Client) -> None:
        self._http = http

    def create(
        self,
        *,
        input: str | list[str],  # noqa: A002
        model: str = "text-embedding-3-small",
        **kwargs: Any,
    ) -> CreateEmbeddingResponse:
        """Create embeddings for text.

        Args:
            input: Text or list of texts to embed.
            model: Embedding model identifier.
            **kwargs: Additional parameters forwarded to the API.

        Returns:
            CreateEmbeddingResponse with embedding vectors.
        """
        payload: dict[str, Any] = {"input": input, "model": model, **kwargs}
        response = self._http.post("/v1/embeddings", json=payload)
        response.raise_for_status()
        return CreateEmbeddingResponse.from_dict(response.json())


# -- Async namespaces ----------------------------------------------------------

class _AsyncCompletions:
    """async_client.chat.completions namespace."""

    def __init__(self, http: httpx.AsyncClient) -> None:
        self._http = http

    async def create(
        self,
        *,
        model: str,
        messages: list[dict[str, Any]],
        stream: bool = False,
        max_tokens: int | None = None,
        temperature: float | None = None,
        **kwargs: Any,
    ) -> Union[ChatCompletion, AsyncChatCompletionStream]:
        """Async create chat completion (streaming or non-streaming)."""
        payload: dict[str, Any] = {
            "model": model,
            "messages": messages,
            "stream": stream,
        }
        if max_tokens is not None:
            payload["max_tokens"] = max_tokens
        if temperature is not None:
            payload["temperature"] = temperature
        payload.update(kwargs)

        if stream:
            response = await self._http.send(
                self._http.build_request("POST", "/v1/chat/completions", json=payload),
                stream=True,
            )
            response.raise_for_status()
            return AsyncChatCompletionStream(response)
        else:
            response = await self._http.post("/v1/chat/completions", json=payload)
            response.raise_for_status()
            return ChatCompletion.from_dict(response.json())


class _AsyncChat:
    """async_client.chat namespace."""

    def __init__(self, http: httpx.AsyncClient) -> None:
        self.completions = _AsyncCompletions(http)


class _AsyncEmbeddings:
    """async_client.embeddings namespace."""

    def __init__(self, http: httpx.AsyncClient) -> None:
        self._http = http

    async def create(
        self,
        *,
        input: str | list[str],  # noqa: A002
        model: str = "text-embedding-3-small",
        **kwargs: Any,
    ) -> CreateEmbeddingResponse:
        payload: dict[str, Any] = {"input": input, "model": model, **kwargs}
        response = await self._http.post("/v1/embeddings", json=payload)
        response.raise_for_status()
        return CreateEmbeddingResponse.from_dict(response.json())


# -- Public client classes -----------------------------------------------------

class SecurePromptClient:
    """Synchronous SecurePrompt gateway client.

    Mirrors the openai.OpenAI client shape for drop-in substitution (D-06).

    Example:
        client = SecurePromptClient(api_key="sp_...", base_url="https://gateway.example.com")
        response = client.chat.completions.create(
            model="gpt-4o",
            messages=[{"role": "user", "content": "Hello"}],
        )
        print(response.choices[0].message.content)
    """

    def __init__(
        self,
        api_key: str | None = None,
        base_url: str | None = None,
        timeout: float = 60.0,
    ) -> None:
        # Env-var fallbacks (SDK-03).
        resolved_key = api_key or os.environ.get("SECUREPROMPT_API_KEY")
        if not resolved_key:
            raise ValueError(
                "api_key must be provided or SECUREPROMPT_API_KEY env var must be set"
            )
        resolved_url = (
            base_url
            or os.environ.get("SECUREPROMPT_BASE_URL", "http://localhost:8080")
        ).rstrip("/")

        self._http = httpx.Client(
            base_url=resolved_url,
            headers={"Authorization": f"Bearer {resolved_key}"},
            timeout=timeout,
        )
        # Sub-namespaces matching openai client shape (D-06).
        self.chat = _Chat(self._http)
        self.embeddings = _Embeddings(self._http)

    def close(self) -> None:
        """Close the underlying HTTP client."""
        self._http.close()

    def __enter__(self) -> SecurePromptClient:
        return self

    def __exit__(self, *args: object) -> None:
        self.close()


class AsyncSecurePromptClient:
    """Asynchronous SecurePrompt gateway client.

    Mirrors the openai.AsyncOpenAI client shape.

    Example:
        async with AsyncSecurePromptClient(api_key="sp_...") as client:
            response = await client.chat.completions.create(
                model="gpt-4o",
                messages=[{"role": "user", "content": "Hello"}],
            )
    """

    def __init__(
        self,
        api_key: str | None = None,
        base_url: str | None = None,
        timeout: float = 60.0,
    ) -> None:
        resolved_key = api_key or os.environ.get("SECUREPROMPT_API_KEY")
        if not resolved_key:
            raise ValueError(
                "api_key must be provided or SECUREPROMPT_API_KEY env var must be set"
            )
        resolved_url = (
            base_url
            or os.environ.get("SECUREPROMPT_BASE_URL", "http://localhost:8080")
        ).rstrip("/")

        self._http = httpx.AsyncClient(
            base_url=resolved_url,
            headers={"Authorization": f"Bearer {resolved_key}"},
            timeout=timeout,
        )
        self.chat = _AsyncChat(self._http)
        self.embeddings = _AsyncEmbeddings(self._http)

    async def aclose(self) -> None:
        await self._http.aclose()

    async def __aenter__(self) -> AsyncSecurePromptClient:
        return self

    async def __aexit__(self, *args: object) -> None:
        await self.aclose()
