
def register(client, email, org):
    response = client.post(
        "/auth/register",
        json={
            "email": email,
            "password": "StrongPass123",
            "org_name": org
        }
    )

    assert response.status_code == 200

    return {
        "Authorization": (
            f"Bearer {response.json()['access_token']}"
        )
    }


def make_key(client, headers):
    response = client.post(
        "/api-keys",
        json={"name": "Test API Key"},
        headers=headers
    )

    assert response.status_code == 200
    return response.json()["api_key"]


SQLI_EVENT = {
    "event_type": "web_request",
    "source_ip": "5.5.5.5",
    "request_path": "/x?id=1' OR 1=1 --"
}


def test_login_wrong_password(client):
    register(client, "a@x.com", "OrgA")

    response = client.post(
        "/auth/login",
        json={
            "email": "a@x.com",
            "password": "wrong-password"
        }
    )

    assert response.status_code == 401


def test_weak_password_rejected(client):
    response = client.post(
        "/auth/register",
        json={
            "email": "b@x.com",
            "password": "short",
            "org_name": "OrgB"
        }
    )

    assert response.status_code == 422


def test_events_require_api_key(client):
    # Missing API key
    response = client.post(
        "/events",
        json=SQLI_EVENT
    )

    assert response.status_code == 401

    # Invalid API key
    response = client.post(
        "/events",
        json=SQLI_EVENT,
        headers={"X-API-Key": "sk_fake"}
    )

    assert response.status_code == 401


def test_dashboard_requires_login(client):
    assert client.get("/detections").status_code in (401, 403)


def test_sqli_event_creates_detection(client):
    headers = register(client, "a@x.com", "OrgA")
    api_key = make_key(client, headers)

    response = client.post(
        "/events",
        json=SQLI_EVENT,
        headers={"X-API-Key": api_key}
    )

    assert response.status_code == 200
    assert response.json()["detections"][0]["predicted_label"] == "SQLInjection"

    detections = client.get(
        "/detections",
        headers=headers
    )

    assert detections.status_code == 200
    assert len(detections.json()) == 1


def test_tenant_isolation(client):
    # Create two separate organizations.
    headers_a = register(client, "a@x.com", "OrgA")
    headers_b = register(client, "b@x.com", "OrgB")

    # Create an API key for Organization A.
    api_key_a = make_key(client, headers_a)

    # Submit an event only to Organization A.
    response = client.post(
        "/events",
        json=SQLI_EVENT,
        headers={"X-API-Key": api_key_a}
    )

    assert response.status_code == 200

    # Organization A should see its detection.
    detections_a = client.get(
        "/detections",
        headers=headers_a
    )

    assert len(detections_a.json()) == 1

    # Organization B must not see Organization A's detection.
    detections_b = client.get(
        "/detections",
        headers=headers_b
    )

    assert detections_b.status_code == 200
    assert detections_b.json() == []

    # Organization B must not see Organization A's events.
    events_b = client.get(
        "/events",
        headers=headers_b
    )

    assert events_b.status_code == 200
    assert events_b.json() == []
