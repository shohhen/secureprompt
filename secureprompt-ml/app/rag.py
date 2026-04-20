"""
RAG check for SecurePrompt ML sidecar (Phase 7 / Plan 07-03 — QD-01..03).
SECURITY CRITICAL: Every Qdrant query MUST include workspace_id filter.
"""
import asyncio
from typing import Optional
from fastapi import HTTPException
from qdrant_client import QdrantClient
from qdrant_client.models import FieldCondition, Filter, MatchValue


def rag_check(
    client: QdrantClient,
    embedder,
    text: str,
    workspace_id: str,
    score_threshold: float = 0.85,
    limit: int = 5,
    _precomputed_embedding: Optional[list] = None,
) -> list:
    """
    Synchronous RAG check — run via asyncio.to_thread.
    ALWAYS filters by workspace_id. No unfiltered code path exists.
    """
    if _precomputed_embedding is not None:
        embedding = _precomputed_embedding
    else:
        embedding = embedder.encode(text, convert_to_tensor=False).tolist()

    results = client.query_points(
        collection_name="policy_rag",
        query=embedding,
        query_filter=Filter(
            must=[
                FieldCondition(
                    key="workspace_id",
                    match=MatchValue(value=workspace_id),
                )
            ]
        ),
        score_threshold=score_threshold,
        limit=limit,
        with_payload=True,
    )
    return [
        {"rule_id": p.payload["rule_id"], "score": float(p.score)}
        for p in results.points
        if p.payload and "rule_id" in p.payload
    ]
