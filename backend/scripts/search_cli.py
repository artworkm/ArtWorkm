import sys

from app.rag.retrieve import search


query = " ".join(sys.argv[1:])

if not query.strip():
    print("Usage: python -m scripts.search_cli <your question>")
    sys.exit(1)

results = search(query, k=5)

if not results:
    print("No relevant knowledge found.")
    sys.exit(0)

for r in results:
    ref = (
        r.get("technique_id")
        or r.get("cve_id")
        or r.get("title")
        or r.get("name")
        or "N/A"
    )

    print(f"{r['score']:.3f} [{r['kind']}] {ref}")
    print("    ", r["text"][:150].replace("\n", " "))
    print()