import os
import requests

OLLAMA = os.getenv("OLLAMA_URL", "http://localhost:11434")
MODEL = os.getenv("EMBED_MODEL", "nomic-embed-text")


def embed(texts: list[str], prefix: str = "search_document: ") -> list[list[float]]:
    """nomic-embed-text expects a task prefix: 'search_document: ' for stored
    text and 'search_query: ' for questions."""
    r = requests.post(
        f"{OLLAMA}/api/embed",
        json={"model": MODEL, "input": [prefix + t for t in texts]},
        timeout=300
    )
    r.raise_for_status()
    return r.json()["embeddings"]