"""Streaming iterator classes for SSE responses.

SecurePrompt API streams chat completions as Server-Sent Events:
    data: {"id":"...","object":"chat.completion.chunk",...}\n\n
    data: [DONE]\n\n

Sync and async variants both yield ChatCompletionChunk objects.
"""

from __future__ import annotations

from collections.abc import AsyncIterator, Iterator
from typing import TYPE_CHECKING

import httpx

from secureprompt._models import ChatCompletionChunk

if TYPE_CHECKING:
    pass


class ChatCompletionStream:
    """Synchronous SSE streaming iterator.

    Usage:
        with client.chat.completions.create(model=..., messages=..., stream=True) as stream:
            for chunk in stream:
                print(chunk.choices[0].delta.content or "", end="")
    """

    def __init__(self, response: httpx.Response) -> None:
        self._response = response

    def __iter__(self) -> Iterator[ChatCompletionChunk]:
        for line in self._response.iter_lines():
            if not line.startswith("data: "):
                continue
            data = line[6:].strip()
            if data == "[DONE]":
                break
            try:
                yield ChatCompletionChunk.from_json(data)
            except Exception:  # noqa: BLE001
                # Skip malformed chunks — do not crash the stream.
                pass

    def __enter__(self) -> ChatCompletionStream:
        return self

    def __exit__(self, *args: object) -> None:
        self._response.close()


class AsyncChatCompletionStream:
    """Asynchronous SSE streaming iterator.

    Usage:
        async with await client.chat.completions.create(..., stream=True) as stream:
            async for chunk in stream:
                print(chunk.choices[0].delta.content or "", end="")
    """

    def __init__(self, response: httpx.Response) -> None:
        self._response = response

    def __aiter__(self) -> AsyncIterator[ChatCompletionChunk]:
        return self._async_iter()

    async def _async_iter(self) -> AsyncIterator[ChatCompletionChunk]:
        async for line in self._response.aiter_lines():
            if not line.startswith("data: "):
                continue
            data = line[6:].strip()
            if data == "[DONE]":
                break
            try:
                yield ChatCompletionChunk.from_json(data)
            except Exception:  # noqa: BLE001
                pass

    async def __aenter__(self) -> AsyncChatCompletionStream:
        return self

    async def __aexit__(self, *args: object) -> None:
        await self._response.aclose()
