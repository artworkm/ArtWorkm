from pathlib import Path

from app.rag.chunking import chunk_text
from app.rag.store import ensure_collection, upsert_chunks


ROOT = Path(__file__).resolve().parents[2]

FOLDERS = [
    (ROOT / "rag" / "playbooks", "playbook"),
    (ROOT / "data" / "knowledge" / "docs", "doc"),
]

chunks = []

for folder, kind in FOLDERS:
    if not folder.exists():
        continue

    for path in sorted(folder.iterdir()):
        ext = path.suffix.lower()

        if ext in (".md", ".txt"):
            text = path.read_text(
                encoding="utf-8",
                errors="ignore"
            )

        elif ext == ".pdf":
            from pypdf import PdfReader

            text = "\n\n".join(
                page.extract_text() or ""
                for page in PdfReader(path).pages
            )

        else:
            continue

        title = path.stem

        for i, piece in enumerate(chunk_text(text)):
            chunks.append({
                "key": f"{path.name}-{i}",
                "source": kind,
                "text": f"{title.replace('_', ' ')}\n{piece}",
                "meta": {
                    "kind": kind,
                    "title": title,
                },
            })


print(f"{len(chunks)} document chunks")

ensure_collection()
upsert_chunks(chunks)