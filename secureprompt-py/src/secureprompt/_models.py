"""Response model types for the SecurePrompt client.

Uses stdlib dataclasses + json.loads for parsing. No third-party deps (SDK-04).
Models mirror OpenAI API shapes so existing OpenAI streaming consumers can swap
the client with minimal changes (D-07).
"""

from __future__ import annotations

import json
from dataclasses import dataclass
from typing import Any, Optional


@dataclass
class ChatCompletionMessage:
    role: str
    content: Optional[str] = None

    @classmethod
    def from_dict(cls, d: dict[str, Any]) -> ChatCompletionMessage:
        return cls(role=d["role"], content=d.get("content"))


@dataclass
class ChatCompletionChoice:
    index: int
    message: ChatCompletionMessage
    finish_reason: Optional[str] = None

    @classmethod
    def from_dict(cls, d: dict[str, Any]) -> ChatCompletionChoice:
        return cls(
            index=d["index"],
            message=ChatCompletionMessage.from_dict(d["message"]),
            finish_reason=d.get("finish_reason"),
        )


@dataclass
class Usage:
    prompt_tokens: int = 0
    completion_tokens: int = 0
    total_tokens: int = 0

    @classmethod
    def from_dict(cls, d: dict[str, Any]) -> Usage:
        return cls(
            prompt_tokens=d.get("prompt_tokens", 0),
            completion_tokens=d.get("completion_tokens", 0),
            total_tokens=d.get("total_tokens", 0),
        )


@dataclass
class ChatCompletion:
    id: str
    created: int
    model: str
    choices: list[ChatCompletionChoice]
    object: str = "chat.completion"
    usage: Optional[Usage] = None

    @classmethod
    def from_dict(cls, d: dict[str, Any]) -> ChatCompletion:
        return cls(
            id=d["id"],
            created=d["created"],
            model=d["model"],
            choices=[ChatCompletionChoice.from_dict(c) for c in d.get("choices", [])],
            object=d.get("object", "chat.completion"),
            usage=Usage.from_dict(d["usage"]) if d.get("usage") else None,
        )


# -- Streaming chunk models ----------------------------------------------------

@dataclass
class DeltaMessage:
    role: Optional[str] = None
    content: Optional[str] = None

    @classmethod
    def from_dict(cls, d: dict[str, Any]) -> DeltaMessage:
        return cls(role=d.get("role"), content=d.get("content"))


@dataclass
class ChatCompletionChunkChoice:
    index: int
    delta: DeltaMessage
    finish_reason: Optional[str] = None

    @classmethod
    def from_dict(cls, d: dict[str, Any]) -> ChatCompletionChunkChoice:
        return cls(
            index=d["index"],
            delta=DeltaMessage.from_dict(d.get("delta", {})),
            finish_reason=d.get("finish_reason"),
        )


@dataclass
class ChatCompletionChunk:
    id: str
    created: int
    model: str
    choices: list[ChatCompletionChunkChoice]
    object: str = "chat.completion.chunk"

    @classmethod
    def from_dict(cls, d: dict[str, Any]) -> ChatCompletionChunk:
        return cls(
            id=d["id"],
            created=d["created"],
            model=d["model"],
            choices=[ChatCompletionChunkChoice.from_dict(c) for c in d.get("choices", [])],
            object=d.get("object", "chat.completion.chunk"),
        )

    @classmethod
    def from_json(cls, raw: str) -> ChatCompletionChunk:
        return cls.from_dict(json.loads(raw))


# -- Embeddings ----------------------------------------------------------------

@dataclass
class EmbeddingObject:
    index: int
    embedding: list[float]
    object: str = "embedding"

    @classmethod
    def from_dict(cls, d: dict[str, Any]) -> EmbeddingObject:
        return cls(
            index=d["index"],
            embedding=d["embedding"],
            object=d.get("object", "embedding"),
        )


@dataclass
class CreateEmbeddingResponse:
    data: list[EmbeddingObject]
    model: str
    object: str = "list"
    usage: Optional[Usage] = None

    @classmethod
    def from_dict(cls, d: dict[str, Any]) -> CreateEmbeddingResponse:
        return cls(
            data=[EmbeddingObject.from_dict(e) for e in d.get("data", [])],
            model=d["model"],
            object=d.get("object", "list"),
            usage=Usage.from_dict(d["usage"]) if d.get("usage") else None,
        )
