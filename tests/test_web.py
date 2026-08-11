"""Tests for the FastAPI application."""

from __future__ import annotations

from collections.abc import Iterator
from pathlib import Path

import pytest
from fastapi.testclient import TestClient

from shingan.core.storage import ScanStore
from shingan.core.suppression import SuppressionStore
from shingan.web.main import app, get_store, get_suppression_store


@pytest.fixture
def client(tmp_path: Path) -> Iterator[TestClient]:
    """A TestClient with the stores overridden to temp files."""
    store = ScanStore(db_path=tmp_path / "web.db")
    suppressions = SuppressionStore(path=tmp_path / "web-sup.json")

    app.dependency_overrides[get_store] = lambda: store
    app.dependency_overrides[get_suppression_store] = lambda: suppressions
    with TestClient(app) as c:
        yield c
    app.dependency_overrides.clear()


@pytest.fixture
def saved_scan(client: TestClient, make_result, make_finding) -> str:
    store = app.dependency_overrides[get_store]()
    result = make_result([make_finding("IOS-TEST-1")], scan_id="scan-1")
    store.save(result)
    return result.scan_id


# ── Health / metadata ─────────────────────────────────────────────────────────


def test_health(client: TestClient) -> None:
    resp = client.get("/api/health")
    assert resp.status_code == 200
    assert resp.json()["status"] == "ok"


def test_openapi_version_matches_package(client: TestClient) -> None:
    """The app used to hardcode 1.1.0 while pyproject said 1.0.0."""
    from shingan.core.version import get_version

    assert client.get("/openapi.json").json()["info"]["version"] == get_version()


# ── Scan retrieval ────────────────────────────────────────────────────────────


def test_get_scan(client: TestClient, saved_scan: str) -> None:
    resp = client.get(f"/api/scans/{saved_scan}")
    assert resp.status_code == 200
    assert resp.json()["scan_id"] == saved_scan


def test_get_scan_404(client: TestClient) -> None:
    assert client.get("/api/scans/missing").status_code == 404


def test_list_scans(client: TestClient, saved_scan: str) -> None:
    body = client.get("/api/scans").json()
    assert [s["scan_id"] for s in body] == [saved_scan]


def test_sarif_export(client: TestClient, saved_scan: str) -> None:
    resp = client.get(f"/api/scans/{saved_scan}/sarif")
    assert resp.status_code == 200
    assert resp.json()["version"] == "2.1.0"


def test_sarif_export_404(client: TestClient) -> None:
    assert client.get("/api/scans/missing/sarif").status_code == 404


def test_html_export(client: TestClient, saved_scan: str) -> None:
    resp = client.get(f"/api/scans/{saved_scan}/html")
    assert resp.status_code == 200
    assert "text/html" in resp.headers["content-type"]


def test_html_export_with_unknown_baseline_still_renders(
    client: TestClient, saved_scan: str
) -> None:
    resp = client.get(f"/api/scans/{saved_scan}/html?baseline_id=missing")
    assert resp.status_code == 200


def test_scan_detail_page(client: TestClient, saved_scan: str) -> None:
    assert client.get(f"/scans/{saved_scan}").status_code == 200


def test_index_page(client: TestClient) -> None:
    assert client.get("/").status_code == 200


def test_diff_endpoint(client: TestClient, make_result, make_finding) -> None:
    store = app.dependency_overrides[get_store]()
    store.save(make_result([make_finding("A")], scan_id="base"))
    store.save(make_result([make_finding("A"), make_finding("B")], scan_id="cur"))

    body = client.get("/api/scans/cur/diff/base").json()

    assert body["summary"]["new"] == 1
    assert body["summary"]["persisted"] == 1
    assert body["summary"]["fixed"] == 0


def test_diff_endpoint_404(client: TestClient) -> None:
    assert client.get("/api/scans/a/diff/b").status_code == 404


# ── Delete ────────────────────────────────────────────────────────────────────


def test_delete_scan(client: TestClient, saved_scan: str) -> None:
    assert client.delete(f"/api/scans/{saved_scan}").status_code == 204
    assert client.get(f"/api/scans/{saved_scan}").status_code == 404


def test_delete_unknown_scan_is_404(client: TestClient) -> None:
    """Unknown IDs used to return 204 because delete() never raised."""
    assert client.delete("/api/scans/never-existed").status_code == 404


# ── Upload validation ─────────────────────────────────────────────────────────


def test_upload_rejects_unknown_extension(client: TestClient) -> None:
    resp = client.post(
        "/api/scans", files={"file": ("evil.exe", b"MZ", "application/octet-stream")}
    )
    assert resp.status_code == 400


def test_upload_rejects_extensionless_name(client: TestClient) -> None:
    resp = client.post("/api/scans", files={"file": ("noext", b"data")})
    assert resp.status_code == 400


def test_upload_traversal_filename_cannot_escape(
    client: TestClient, tmp_path: Path
) -> None:
    """The filename is client-controlled and must be reduced to a basename."""
    resp = client.post(
        "/api/scans", files={"file": ("../../../../evil.ipa", b"not a real zip")}
    )

    # Rejected as an invalid archive rather than written outside the temp dir.
    assert resp.status_code == 422
    assert not Path("/evil.ipa").exists()
    assert not (tmp_path.parent / "evil.ipa").exists()


def test_upload_rejects_oversize(client: TestClient, monkeypatch) -> None:
    monkeypatch.setattr("shingan.web.main.MAX_UPLOAD_BYTES", 10)
    resp = client.post("/api/scans", files={"file": ("big.ipa", b"x" * 100)})
    assert resp.status_code == 413


def test_upload_invalid_archive_returns_422(client: TestClient) -> None:
    resp = client.post("/api/scans", files={"file": ("broken.ipa", b"not a zip")})
    assert resp.status_code == 422


def test_upload_valid_ipa(client: TestClient, ipa_file: Path) -> None:
    resp = client.post(
        "/api/scans", files={"file": ("Example.ipa", ipa_file.read_bytes())}
    )
    assert resp.status_code == 201
    body = resp.json()
    assert body["app_id"] == "com.example.app"
    assert body["ipa_name"] == "Example.ipa"


def test_upload_notifies_only_for_new_findings(
    client: TestClient, ipa_file: Path, monkeypatch
) -> None:
    """The second identical upload introduces nothing new, so nothing fires."""
    calls: list[int] = []

    def fake_notify(_result: object, findings: list) -> None:
        calls.append(len(findings))

    monkeypatch.setattr("shingan.web.main.notify_all", fake_notify)
    payload = {"file": ("Example.ipa", ipa_file.read_bytes())}

    client.post("/api/scans", files=payload)
    first = list(calls)
    client.post("/api/scans", files={"file": ("Example.ipa", ipa_file.read_bytes())})

    # The placeholder IPA has no HIGH findings, so nothing should ever fire;
    # crucially the repeat upload must not add a notification either.
    assert calls == first


# ── Suppressions ──────────────────────────────────────────────────────────────


def test_suppression_lifecycle(client: TestClient) -> None:
    assert client.get("/api/suppressions").json() == []

    created = client.post(
        "/api/suppressions",
        json={"rule_id": "IOS-SEC-002", "evidence_prefix": "AKIA", "reason": "fixture"},
    )
    assert created.status_code == 201
    assert created.json()["rule_id"] == "IOS-SEC-002"

    assert len(client.get("/api/suppressions").json()) == 1

    removed = client.delete(
        "/api/suppressions",
        params={"rule_id": "IOS-SEC-002", "evidence_prefix": "AKIA"},
    )
    assert removed.json() == {"removed": 1}
    assert client.get("/api/suppressions").json() == []


def test_suppression_add_is_idempotent(client: TestClient) -> None:
    for _ in range(3):
        client.post("/api/suppressions", json={"rule_id": "DUP"})
    assert len(client.get("/api/suppressions").json()) == 1


# ── Baselines ─────────────────────────────────────────────────────────────────


def test_baseline_lifecycle(client: TestClient, saved_scan: str) -> None:
    assert client.get("/api/baselines/com.example").status_code == 404

    resp = client.post("/api/baselines/com.example", params={"scan_id": saved_scan})
    assert resp.status_code == 200

    body = client.get("/api/baselines/com.example").json()
    assert body["baseline_scan_id"] == saved_scan


def test_baseline_rejects_unknown_scan(client: TestClient) -> None:
    resp = client.post("/api/baselines/com.example", params={"scan_id": "missing"})
    assert resp.status_code == 404


# ── API key enforcement ───────────────────────────────────────────────────────


def test_no_api_key_required_by_default(client: TestClient, saved_scan: str) -> None:
    assert client.delete(f"/api/scans/{saved_scan}").status_code == 204


def test_api_key_enforced_when_configured(
    client: TestClient, saved_scan: str, monkeypatch
) -> None:
    monkeypatch.setenv("SHINGAN_API_KEY", "s3cret")

    assert client.delete(f"/api/scans/{saved_scan}").status_code == 401
    assert client.post("/api/suppressions", json={"rule_id": "X"}).status_code == 401


def test_api_key_accepts_correct_value(
    client: TestClient, saved_scan: str, monkeypatch
) -> None:
    monkeypatch.setenv("SHINGAN_API_KEY", "s3cret")
    resp = client.delete(f"/api/scans/{saved_scan}", headers={"X-API-Key": "s3cret"})
    assert resp.status_code == 204


def test_api_key_rejects_wrong_value(
    client: TestClient, saved_scan: str, monkeypatch
) -> None:
    monkeypatch.setenv("SHINGAN_API_KEY", "s3cret")
    resp = client.delete(f"/api/scans/{saved_scan}", headers={"X-API-Key": "wrong"})
    assert resp.status_code == 401


def test_reads_stay_open_when_key_is_set(
    client: TestClient, saved_scan: str, monkeypatch
) -> None:
    """Only mutating endpoints are gated, so dashboards keep working."""
    monkeypatch.setenv("SHINGAN_API_KEY", "s3cret")
    assert client.get(f"/api/scans/{saved_scan}").status_code == 200
