"""
Qdrant collection initialization (Phase 7 / Plan 07-03 — QD-01, QD-02, QD-03).
CRITICAL: Both VectorParams(on_disk=True) AND HnswConfigDiff(on_disk=True) must be set.
"""
import os
from qdrant_client import QdrantClient
from qdrant_client.models import (
    Distance,
    HnswConfigDiff,
    PayloadSchemaType,
    VectorParams,
)

QDRANT_URL: str = os.environ.get("QDRANT_URL", "http://qdrant:6333")


def get_qdrant_client() -> QdrantClient:
    return QdrantClient(url=QDRANT_URL)


def ensure_collections(client: QdrantClient) -> None:
    """Idempotently create policy_rag and prompt_similarity collections."""
    specs = [
        ("policy_rag", True),       # (name, has_rule_id_index)
        ("prompt_similarity", False),
    ]
    for name, has_rule_id_index in specs:
        if not client.collection_exists(name):
            client.create_collection(
                collection_name=name,
                vectors_config=VectorParams(
                    size=384,
                    distance=Distance.COSINE,
                    on_disk=True,
                ),
                hnsw_config=HnswConfigDiff(
                    on_disk=True,
                    m=16,
                    ef_construct=100,
                ),
                on_disk_payload=True,
            )
            client.create_payload_index(
                collection_name=name,
                field_name="workspace_id",
                field_schema=PayloadSchemaType.KEYWORD,
            )
            client.create_payload_index(
                collection_name=name,
                field_name="doc_type",
                field_schema=PayloadSchemaType.KEYWORD,
            )
            if has_rule_id_index:
                client.create_payload_index(
                    collection_name=name,
                    field_name="rule_id",
                    field_schema=PayloadSchemaType.KEYWORD,
                )
