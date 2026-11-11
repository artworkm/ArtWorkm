
from test_api import register, make_key, SQLI_EVENT


SOURCES = [
    {
        "score": 0.9,
        "text": "SQL injection prevention guidance.",
        "source": "doc",
        "title": "SQL_Injection_Prevention"
    }
]


FAKE = {
    "summary": "Possible SQL injection attempt.",
    "likely_attack_technique": "T1190 Exploit Public-Facing Application",
    "severity_assessment": "high",
    "evidence_used": ["S1", "S9"],
    "recommended_actions": [
        "Use parameterized queries"
    ],
    "confidence": "high",
    "limitations": "Single request observed."
}


def setup(client, monkeypatch, llm_output=None):
    from app import analyze

    # Mock the RAG knowledge search.
    monkeypatch.setattr(
        analyze,
        "search_knowledge",
        lambda q, k=6: SOURCES
    )

    # Mock threat intelligence enrichment.
    monkeypatch.setattr(
        analyze.intel,
        "enrich_ip",
        lambda db, ip: {"ip": ip}
    )

    # Mock the LLM response.
    monkeypatch.setattr(
        analyze,
        "call_llm",
        lambda s, u, schema: dict(llm_output or FAKE)
    )

    # Register an organization and authenticate.
    headers = register(client, "a@x.com", "OrgA")

    # Create an API key.
    api_key = make_key(client, headers)

    # Submit an SQL injection event.
    client.post(
        "/events",
        json=SQLI_EVENT,
        headers={"X-API-Key": api_key}
    )

    # Retrieve the generated detection.
    detections = client.get(
        "/detections",
        headers=headers
    )

    det_id = detections.json()[0]["id"]

    return headers, det_id


def test_invented_citations_are_dropped(client, monkeypatch):
    headers, det_id = setup(client, monkeypatch)

    response = client.post(
        f"/detections/{det_id}/analyze",
        headers=headers
    )

    assert response.status_code == 200
    assert response.json()["analysis"]["evidence_used"] == ["S1"]
    assert response.json()["grounded"] is True


def test_uncited_answer_is_marked_ungrounded(client, monkeypatch):
    headers, det_id = setup(
        client,
        monkeypatch,
        {
            **FAKE,
            "evidence_used": []
        }
    )

    response = client.post(
        f"/detections/{det_id}/analyze",
        headers=headers
    )

    assert response.status_code == 200

    result = response.json()

    assert result["grounded"] is False
    assert result["analysis"]["confidence"] == "low"


def test_analysis_tenant_isolation(client, monkeypatch):
    headers_a, det_id = setup(client, monkeypatch)

    # Organization A performs the analysis.
    response = client.post(
        f"/detections/{det_id}/analyze",
        headers=headers_a
    )

    assert response.status_code == 200

    # Register a second organization.
    headers_b = register(client, "b@x.com", "OrgB")

    # Organization B must not analyze Organization A's detection.
    analyze_response = client.post(
        f"/detections/{det_id}/analyze",
        headers=headers_b
    )

    assert analyze_response.status_code == 404

    # Organization B must not retrieve Organization A's analysis.
    retrieve_response = client.get(
        f"/detections/{det_id}/analysis",
        headers=headers_b
    )

    assert retrieve_response.status_code == 404
