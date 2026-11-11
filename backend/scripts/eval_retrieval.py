import json
from pathlib import Path

from app.rag.retrieve import search


FILE = (
    Path(__file__).resolve().parents[2]
    / "rag"
    / "eval_questions.json"
)

with open(FILE, encoding="utf-8") as f:
    items = json.load(f)


def hit(results, item):
    for r in results:
        if "expect_technique" in item:
            if (r.get("technique_id") or "").startswith(
                item["expect_technique"]
            ):
                return True

        if "expect_title" in item:
            if item["expect_title"].lower() in (
                r.get("title") or ""
            ).lower():
                return True

    return False


totals = {1: 0, 3: 0, 5: 0}

for number, item in enumerate(items, start=1):
    results = search(item["q"], k=5)

    for k in totals:
        totals[k] += hit(results[:k], item)

    if not hit(results, item):
        references = [
            r.get("technique_id")
            or r.get("title")
            or r.get("cve_id")
            or r.get("name")
            for r in results
        ]

        print(
            f"MISS {number}: {item['q']}"
            f"\n  Expected: {item.get('expect_technique') or item.get('expect_title')}"
            f"\n  Retrieved: {references}"
        )


print("\n===== RETRIEVAL EVALUATION =====")

for k, value in totals.items():
    percentage = value / len(items) * 100

    print(
        f"hit@{k}: {value}/{len(items)} "
        f"= {percentage:.1f}%"
    )

print(f"\nTotal questions: {len(items)}")