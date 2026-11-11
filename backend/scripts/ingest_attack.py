import json
import re
from collections import defaultdict
from pathlib import Path

from app.rag.chunking import chunk_text
from app.rag.store import ensure_collection, upsert_chunks


FILE = (
    Path(__file__).resolve().parents[2]
    / "data"
    / "knowledge"
    / "enterprise-attack.json"
)


def clean(t: str) -> str:
    t = re.sub(r"\(Citation: [^)]+\)", "", t or "")
    t = re.sub(r"</?code>", "`", t)
    return re.sub(r"\s+", " ", t).strip()


def active(o: dict) -> bool:
    return not o.get("revoked") and not o.get("x_mitre_deprecated")


with open(FILE, encoding="utf-8") as f:
    objs = json.load(f)["objects"]

by_id = {o["id"]: o for o in objs}

mitigations = defaultdict(list)

for o in objs:
    if (
        o.get("type") == "relationship"
        and o.get("relationship_type") == "mitigates"
        and active(o)
    ):
        src = by_id.get(o["source_ref"])

        if (
            src
            and src.get("type") == "course-of-action"
            and active(src)
        ):
            mitigations[o["target_ref"]].append(
                f"{src['name']}: {clean(o.get('description'))}"
            )


chunks = []

for o in objs:
    if o.get("type") != "attack-pattern" or not active(o):
        continue

    ref = next(
        (
            r for r in o.get("external_references", [])
            if r.get("source_name") == "mitre-attack"
        ),
        None,
    )

    if not ref:
        continue

    tid = ref["external_id"]
    name = o["name"]

    tactics = ", ".join(
        p["phase_name"] for p in o.get("kill_chain_phases", [])
    )

    text = (
        f"{tid} {name} "
        f"(MITRE ATT&CK technique; tactics: {tactics})\n"
        f"{clean(o.get('description'))}"
    )

    if o.get("x_mitre_detection"):
        text += f"\nDetection: {clean(o['x_mitre_detection'])}"

    if mitigations[o["id"]]:
        text += "\nMitigations:\n- " + "\n- ".join(
            mitigations[o["id"]]
        )

    for i, piece in enumerate(chunk_text(text)):
        body = (
            piece
            if i == 0
            else f"{tid} {name} (continued)\n{piece}"
        )

        chunks.append({
            "key": f"{tid}-{i}",
            "source": "mitre-attack",
            "text": body,
            "meta": {
                "kind": "technique",
                "technique_id": tid,
                "name": name,
                "url": ref.get("url", ""),
            },
        })


print(f"{len(chunks)} chunks from ATT&CK")

ensure_collection()
upsert_chunks(chunks)