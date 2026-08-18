from __future__ import annotations

from tests.conftest import get_csrf_token, login


def _create_credential(client, name="stripe-api-key", criticality="high"):
    token = get_csrf_token(client, "/credentials/new")
    r = client.post("/credentials/new", data={"name": name, "criticality": criticality, "csrf_token": token})
    assert r.status_code == 303
    return r.headers["location"]


def _create_project(client, name="checkout-service", environment="production"):
    token = get_csrf_token(client, "/projects/new")
    r = client.post("/projects/new", data={"name": name, "environment": environment, "csrf_token": token})
    assert r.status_code == 303
    return r.headers["location"]


def test_credential_names_must_be_unique(client, editor_user):
    login(client, "editor")
    _create_credential(client, name="dup")
    token = get_csrf_token(client, "/credentials/new")
    r = client.post("/credentials/new", data={"name": "dup", "criticality": "low", "csrf_token": token})
    assert r.status_code == 409


def test_vault_reference_rejects_raw_looking_secrets(client, editor_user):
    login(client, "editor")
    token = get_csrf_token(client, "/credentials/new")
    r = client.post(
        "/credentials/new",
        data={
            "name": "suspicious",
            "criticality": "low",
            # Deliberately NOT shaped like any real provider's secret format
            # (Stripe, AWS, GitHub, etc.) -- using a real-looking prefix like
            # "sk_live_..." here would make gitleaks (correctly!) flag this
            # test fixture as a leaked credential on every scan, forever,
            # since git history is immutable. This still exercises the same
            # validation path: alphanumeric, no spaces, no separators.
            "vault_reference": "totallyNotARealSecretValue12345",
            "csrf_token": token,
        },
    )
    assert r.status_code == 400
    assert "pointer" in r.text.lower()


def test_vault_reference_accepts_a_real_pointer(client, editor_user):
    login(client, "editor")
    token = get_csrf_token(client, "/credentials/new")
    r = client.post(
        "/credentials/new",
        data={
            "name": "fine",
            "criticality": "low",
            "vault_reference": "vault://secret/prod/db-password",
            "csrf_token": token,
        },
    )
    assert r.status_code == 303


def test_linking_credential_to_project_shows_up_in_blast_radius(client, editor_user):
    login(client, "editor")
    cred_url = _create_credential(client)
    proj_url = _create_project(client)

    token = get_csrf_token(client, cred_url)
    r = client.post(
        "/mappings/new",
        data={
            "credential_id": "1",
            "project_id": "1",
            "usage_location": "env var STRIPE_KEY in checkout deployment",
            "csrf_token": token,
            "redirect_to": cred_url,
        },
    )
    assert r.status_code == 303

    r = client.get(cred_url)
    assert "checkout-service" in r.text
    assert "env-production" in r.text

    r = client.get(proj_url)
    assert "stripe-api-key" in r.text


def test_deleting_credential_cascades_its_usage_links(client, editor_user):
    login(client, "editor")
    cred_url = _create_credential(client)
    proj_url = _create_project(client)
    token = get_csrf_token(client, cred_url)
    client.post(
        "/mappings/new",
        data={"credential_id": "1", "project_id": "1", "usage_location": "x", "csrf_token": token, "redirect_to": cred_url},
    )

    token2 = get_csrf_token(client, cred_url)
    r = client.post(f"{cred_url}/delete", data={"csrf_token": token2})
    assert r.status_code == 303

    r = client.get(proj_url)
    assert "stripe-api-key" not in r.text


def test_unmapped_credential_shows_empty_blast_radius(client, editor_user):
    login(client, "editor")
    cred_url = _create_credential(client)
    r = client.get(cred_url)
    assert "blast radius is unknown" in r.text.lower()


def test_overly_long_credential_name_is_rejected(client, editor_user):
    login(client, "editor")
    token = get_csrf_token(client, "/credentials/new")
    r = client.post("/credentials/new", data={"name": "x" * 500, "criticality": "low", "csrf_token": token})
    assert r.status_code == 400
