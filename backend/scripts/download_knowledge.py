
from pathlib import Path
import requests

DATA = Path(__file__).resolve().parents[2] / "data" / "knowledge"
(DATA / "docs").mkdir(parents=True, exist_ok=True)

BIG = {
    "enterprise-attack.json": (
        "https://raw.githubusercontent.com/mitre-attack/"
        "attack-stix-data/master/enterprise-attack/enterprise-attack.json"
    ),
    "kev.json": (
        "https://www.cisa.gov/sites/default/files/feeds/"
        "known_exploited_vulnerabilities.json"
    ),
}

OWASP_BASE = (
    "https://raw.githubusercontent.com/OWASP/CheatSheetSeries/"
    "master/cheatsheets/"
)

OWASP = [
    "SQL_Injection_Prevention_Cheat_Sheet.md",
    "Authentication_Cheat_Sheet.md",
    "Credential_Stuffing_Prevention_Cheat_Sheet.md",
    "Denial_of_Service_Cheat_Sheet.md",
    "Input_Validation_Cheat_Sheet.md",
    "Logging_Cheat_Sheet.md",
]


def get(url: str, dest: Path):
    try:
        r = requests.get(
            url,
            timeout=120,
            headers={"User-Agent": "SentinelAI-student-project"}
        )
        r.raise_for_status()

        dest.write_bytes(r.content)

        print("OK  ", dest.name, f"({len(r.content) // 1024} KB)")

    except Exception as e:
        print(
            "FAIL", dest.name, "-", e,
            "\n     -> download it manually in your browser and save it to",
            dest
        )


for name, url in BIG.items():
    get(url, DATA / name)

for name in OWASP:
    get(OWASP_BASE + name, DATA / "docs" / name)
