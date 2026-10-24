"""API contract and endpoint tests for GuardRail control plane."""

from fastapi.testclient import TestClient


def test_health_success(client: TestClient):
    """Confirm GET /health returns HTTP 200 and exact status ok."""
    response = client.get("/health")
    assert response.status_code == 200
    assert response.json() == {"status": "ok"}


def test_health_database_failure(client: TestClient, monkeypatch):
    """Confirm GET /health returns HTTP 503 when database is unavailable."""
    import app.api.routes_health as rh

    monkeypatch.setattr(rh, "check_db_health", lambda *args, **kwargs: False)
    response = client.get("/health")
    assert response.status_code == 503
    data = response.json()
    assert data["status"] == "unhealthy"
    assert "Database unavailable" in data["detail"]


def test_list_runs_includes_seeded_run(client: TestClient):
    """Confirm GET /api/runs returns a JSON array containing sbx-seeddemo1."""
    response = client.get("/api/runs")
    assert response.status_code == 200
    runs = response.json()
    assert isinstance(runs, list)
    assert any(r.get("sandbox_name") == "sbx-seeddemo1" for r in runs)


def test_create_run_success(client: TestClient):
    """Verify POST /api/runs returns HTTP 201 for a valid record."""
    payload = {
        "run_id": "run_test_valid_01",
        "sandbox_name": "sbx-testalpha1",
        "problem_id": "prompt_injection_exfil",
        "defense_profile": "defense_in_depth",
        "state": "created",
        "execution_target": "celesto_sandbox",
    }
    response = client.post("/api/runs", json=payload)
    assert response.status_code == 201
    created = response.json()
    assert created["run_id"] == "run_test_valid_01"
    assert created["sandbox_name"] == "sbx-testalpha1"
    assert created["execution_target"] == "celesto_sandbox"
    assert created["state"] == "created"


def test_create_run_rejects_host_target(client: TestClient):
    """Verify POST /api/runs returns HTTP 400 when execution_target is 'host'."""
    payload = {
        "run_id": "run_test_invalid_host",
        "sandbox_name": "sbx-testalpha2",
        "problem_id": "prompt_injection_exfil",
        "state": "created",
        "execution_target": "host",
    }
    response = client.post("/api/runs", json=payload)
    assert response.status_code == 400
    assert "celesto_sandbox" in response.json()["detail"]


def test_create_run_rejects_bad_sandbox_name(client: TestClient):
    """Verify POST /api/runs returns HTTP 400 for bad sandbox name."""
    payload = {
        "run_id": "run_test_bad_name",
        "sandbox_name": "invalid-sandbox",
        "problem_id": "prompt_injection_exfil",
        "state": "created",
        "execution_target": "celesto_sandbox",
    }
    response = client.post("/api/runs", json=payload)
    assert response.status_code == 400
    assert "sandbox_name" in response.json()["detail"]


def test_create_run_rejects_unknown_state(client: TestClient):
    """Verify POST /api/runs returns HTTP 400 for unsupported state."""
    payload = {
        "run_id": "run_test_unknown_state",
        "sandbox_name": "sbx-testalpha3",
        "problem_id": "prompt_injection_exfil",
        "state": "unsupported_state",
        "execution_target": "celesto_sandbox",
    }
    response = client.post("/api/runs", json=payload)
    assert response.status_code == 400


def test_create_run_rejects_duplicate_id(client: TestClient):
    """Verify POST /api/runs returns HTTP 409 on duplicate run_id."""
    payload = {
        "run_id": "run_seeddemo1",
        "sandbox_name": "sbx-diffname12",
        "problem_id": "prompt_injection_exfil",
        "state": "created",
        "execution_target": "celesto_sandbox",
    }
    response = client.post("/api/runs", json=payload)
    assert response.status_code == 409


def test_get_run_by_id_success_and_not_found(client: TestClient):
    """Verify GET /api/runs/{run_id} returns 200 for existing and 404 for missing."""
    # Existing
    response = client.get("/api/runs/run_seeddemo1")
    assert response.status_code == 200
    assert response.json()["sandbox_name"] == "sbx-seeddemo1"

    # Missing
    missing = client.get("/api/runs/run_non_existent")
    assert missing.status_code == 404
    assert "not found" in missing.json()["detail"].lower()


def test_list_runs_pagination(client: TestClient):
    """Verify bounded pagination on GET /api/runs."""
    # Create two more runs
    for i in range(2):
        client.post(
            "/api/runs",
            json={
                "run_id": f"run_page_test_{i}",
                "sandbox_name": f"sbx-pageitem{i:02d}",
                "problem_id": "prompt_injection_exfil",
                "state": "created",
                "execution_target": "celesto_sandbox",
            },
        )

    response = client.get("/api/runs?limit=2&offset=0")
    assert response.status_code == 200
    runs = response.json()
    assert len(runs) <= 2


def test_evaluation_stub_endpoints(client: TestClient):
    """Verify POST and GET /api/evaluate stub contracts."""
    eval_payload = {
        "task": "Summarize this page and extract facts",
        "source_url": "http://localhost:9000/pages/pi-01-direct.html",
        "defense_profile": "defense_in_depth",
        "run_count": 20,
    }
    post_resp = client.post("/api/evaluate", json=eval_payload)
    assert post_resp.status_code == 200
    data = post_resp.json()
    assert "evaluation_id" in data
    assert data["runs"] == 20
    assert data["status"] == "queued"

    eval_id = data["evaluation_id"]
    get_resp = client.get(f"/api/evaluate/{eval_id}")
    assert get_resp.status_code == 200
    get_data = get_resp.json()
    assert get_data["evaluation_id"] == eval_id
    assert get_data["defense_profile"] == "defense_in_depth"

    # Test unknown evaluation ID returns 404
    missing_resp = client.get("/api/evaluate/eval_nonexistent")
    assert missing_resp.status_code == 404
