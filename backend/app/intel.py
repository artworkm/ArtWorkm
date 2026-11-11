
import ipaddress
import os

from datetime import datetime, timedelta

import requests
from sqlalchemy.orm import Session

from . import models


TTL = timedelta(hours=24)


def is_public_ip(ip: str) -> bool:
    try:
        return ipaddress.ip_address(ip).is_global
    except ValueError:
        return False


def _abuseipdb(ip: str):
    key = os.getenv("ABUSEIPDB_KEY")

    if not key:
        return None

    r = requests.get(
        "https://api.abuseipdb.com/api/v2/check",
        headers={
            "Key": key,
            "Accept": "application/json"
        },
        params={
            "ipAddress": ip,
            "maxAgeInDays": 90
        },
        timeout=15
    )

    r.raise_for_status()
    d = r.json()["data"]

    return {
        "abuse_confidence_score": d["abuseConfidenceScore"],
        "total_reports": d["totalReports"],
        "country": d.get("countryCode"),
        "isp": d.get("isp"),
        "usage_type": d.get("usageType")
    }


def _otx(ip: str):
    key = os.getenv("OTX_KEY")

    if not key:
        return None

    kind = "IPv6" if ":" in ip else "IPv4"

    r = requests.get(
        f"https://otx.alienvault.com/api/v1/indicators/{kind}/{ip}/general",
        headers={"X-OTX-API-KEY": key},
        timeout=15
    )

    r.raise_for_status()

    return {
        "otx_pulse_count": r.json().get(
            "pulse_info", {}
        ).get("count", 0)
    }


def enrich_ip(db: Session, ip: str) -> dict:

    if not is_public_ip(ip):
        return {
            "ip": ip,
            "note": "private or reserved address; no external intelligence applies"
        }

    row = (
        db.query(models.ThreatIndicator)
        .filter_by(indicator=ip, type="ip")
        .first()
    )

    if row and datetime.utcnow() - row.fetched_at < TTL:
        return row.data

    data = {"ip": ip}
    failed = False

    for fn in (_abuseipdb, _otx):
        try:
            result = fn(ip)

            if result:
                data.update(result)

        except requests.RequestException:
            failed = True

    if len(data) == 1:
        data["note"] = (
            "no intelligence available "
            "(providers not configured or unreachable)"
        )

    if failed:
        return data

    if row:
        row.data = data
        row.fetched_at = datetime.utcnow()
    else:
        db.add(
            models.ThreatIndicator(
                indicator=ip,
                type="ip",
                data=data
            )
        )

    db.commit()

    return data
