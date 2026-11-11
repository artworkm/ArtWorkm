import json
from pathlib import Path

from app.rag.store import ensure_collection, upsert_chunks


FILE = (
    Path(__file__).resolve().parents[2]
    / "data"
    / "knowledge"
    / "kev.json"
)

with open(FILE, encoding="utf-8") as f:
    vulns = json.load(f)["vulnerabilities"]

chunks = []

for v in vulns:
    text = (
        f"{v['cveID']} - {v.get('vulnerabilityName', '')}\n"
        f"Vendor/Product: {v.get('vendorProject', '')} "
        f"{v.get('product', '')}\n"
        f"{v.get('shortDescription', '')}\n"
        f"Required action: {v.get('requiredAction', '')}\n"
        f"Known ransomware campaign use: "
        f"{v.get('knownRansomwareCampaignUse', 'Unknown')}"
    )

    chunks.append({
        "key": v["cveID"],
        "source": "cisa-kev",
        "text": text,
        "meta": {
            "kind": "kev",
            "cve_id": v["cveID"],
            "vendor": v.get("vendorProject", ""),
            "product": v.get("product", ""),
            "date_added": v.get("dateAdded", ""),
        },
    })

print(f"{len(chunks)} KEV entries")

ensure_collection()
upsert_chunks(chunks)