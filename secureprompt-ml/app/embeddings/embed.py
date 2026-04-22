import os

import torch
from sentence_transformers import SentenceTransformer


def _load_embedder() -> SentenceTransformer:
    return SentenceTransformer(
        "sentence-transformers/all-MiniLM-L6-v2",
        cache_folder=os.environ.get("HF_HUB_CACHE") or os.environ.get("SENTENCE_TRANSFORMERS_HOME"),
        device="cpu",
        local_files_only=os.environ.get("TRANSFORMERS_OFFLINE") == "1",
    )


async def embed_text(text: str, model) -> dict:
    """Generate embedding. Accepts model as argument for testability."""
    with torch.inference_mode():
        embedding = model.encode(text, convert_to_numpy=True)
    return {"embedding": embedding.tolist()}


def embed(model: SentenceTransformer, text: str) -> list[float]:
    """Synchronous wrapper for use in asyncio.to_thread."""
    with torch.inference_mode():
        embedding = model.encode(text, convert_to_numpy=True)
    return embedding.tolist()
