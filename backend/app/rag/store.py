
import os
import uuid

from functools import lru_cache
from qdrant_client import QdrantClient
from qdrant_client.models import Distance, VectorParams, PointStruct

from .embed import embed

COLLECTION = "security_knowledge"
DIM = 768  # Size of nomic-embed-text vectors


@lru_cache
def get_client() -> QdrantClient:
    return QdrantClient(
        url=os.getenv("QDRANT_URL", "http://localhost:6333")
    )


def ensure_collection():
    c = get_client()

    if not c.collection_exists(COLLECTION):
        c.create_collection(
            COLLECTION,
            vectors_config=VectorParams(
                size=DIM,
                distance=Distance.COSINE
            )
        )

        c.create_payload_index(
            COLLECTION,
            "kind",
            "keyword"
        )


def make_id(*parts) -> str:
    """Same input produces the same ID, preventing duplicate points."""
    return str(
        uuid.uuid5(
            uuid.NAMESPACE_URL,
            "|".join(map(str, parts))
        )
    )


def upsert_chunks(chunks: list[dict], batch: int = 32):
    """
    Each chunk contains:
    {
        "key": str,
        "source": str,
        "text": str,
        "meta": dict
    }
    """
    c = get_client()

    for i in range(0, len(chunks), batch):
        b = chunks[i:i + batch]

        vectors = embed([x["text"] for x in b])

        c.upsert(
            COLLECTION,
            points=[
                PointStruct(
                    id=make_id(x["source"], x["key"]),
                    vector=v,
                    payload={
                        "text": x["text"],
                        "source": x["source"],
                        **x["meta"]
                    }
                )
                for x, v in zip(b, vectors)
            ]
        )

        print(f"  stored {min(i + batch, len(chunks))}/{len(chunks)}")
