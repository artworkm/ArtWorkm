
import json
import os

import requests

OLLAMA = os.getenv("OLLAMA_URL", "http://localhost:11434")
MODEL = os.getenv("LLM_MODEL", "llama3.2:3b")


def call_llm(system: str, user: str, schema: dict) -> dict:
    """Ask Ollama for JSON that matches the supplied schema."""

    r = requests.post(
        f"{OLLAMA}/api/chat",
        timeout=600,
        json={
            "model": MODEL,
            "stream": False,
            "format": schema,
            "options": {
                "temperature": 0.1,
                "num_ctx": 4096
            },
            "messages": [
                {"role": "system", "content": system},
                {"role": "user", "content": user}
            ],
        },
    )

    r.raise_for_status()

    return json.loads(r.json()["message"]["content"])
