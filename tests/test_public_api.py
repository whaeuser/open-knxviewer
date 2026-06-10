"""API tests for the public read-only server (server_public.py)."""

import pytest
import server_public

from tests.conftest import KNXPROJ_ETS6, KNXPROJ_NOPASS


# ---------------------------------------------------------------------------
# Meta / static endpoints
# ---------------------------------------------------------------------------

async def test_mode_returns_public(public_client):
    r = await public_client.get("/api/mode")
    assert r.status_code == 200
    data = r.json()
    assert data["public"] is True
    assert data["default_theme"] in ("default", "voltlogik")
    assert "branding" in data


async def test_chrome_devtools_suppressed(public_client):
    r = await public_client.get("/.well-known/appspecific/com.chrome.devtools.json")
    assert r.status_code == 200
    assert r.json() == {}


# ---------------------------------------------------------------------------
# Private-only routes must not exist on the public server
# ---------------------------------------------------------------------------

async def test_gateway_not_available(public_client):
    r = await public_client.get("/api/gateway")
    assert r.status_code == 404


async def test_current_values_not_available(public_client):
    r = await public_client.get("/api/current-values")
    assert r.status_code == 404


async def test_annotations_not_available(public_client):
    r = await public_client.get("/api/annotations")
    assert r.status_code == 404


async def test_log_not_available(public_client):
    r = await public_client.get("/api/log")
    assert r.status_code == 404


async def test_last_project_info_not_available(public_client):
    r = await public_client.get("/api/last-project/info")
    assert r.status_code == 404


async def test_ws_not_available(public_client):
    r = await public_client.get("/ws")
    # FastAPI returns 403 for websocket upgrade on non-websocket route, or 404
    assert r.status_code in (403, 404)


# ---------------------------------------------------------------------------
# Parse .knxproj  (also available on public server)
# ---------------------------------------------------------------------------

@pytest.mark.skipif(not KNXPROJ_ETS6.exists(), reason="Test resources not available")
async def test_parse_ets6_project(public_client):
    with open(KNXPROJ_ETS6, "rb") as f:
        r = await public_client.post(
            "/api/parse",
            files={"file": ("ets6_free.knxproj", f, "application/zip")},
            data={"password": "", "language": "de-DE"},
        )
    assert r.status_code == 200
    data = r.json()
    assert "devices" in data
    assert "group_addresses" in data


@pytest.mark.skipif(not KNXPROJ_NOPASS.exists(), reason="Test resources not available")
async def test_parse_no_password_project(public_client):
    with open(KNXPROJ_NOPASS, "rb") as f:
        r = await public_client.post(
            "/api/parse",
            files={"file": ("test.knxproj", f, "application/zip")},
            data={"password": "", "language": "de-DE"},
        )
    assert r.status_code == 200


# ---------------------------------------------------------------------------
# Demo endpoint
# ---------------------------------------------------------------------------

async def test_demo_available_when_file_exists(public_client, tmp_path, monkeypatch):
    demo = tmp_path / "demo.knxproj"
    demo.write_bytes(b"placeholder")
    monkeypatch.setattr(server_public, "DEMO_PATH", demo)
    r = await public_client.get("/api/demo/available")
    assert r.status_code == 200
    assert r.json() == {"available": True}


async def test_demo_not_available_when_file_missing(public_client, tmp_path, monkeypatch):
    monkeypatch.setattr(server_public, "DEMO_PATH", tmp_path / "nonexistent.knxproj")
    r = await public_client.get("/api/demo/available")
    assert r.status_code == 200
    assert r.json() == {"available": False}


async def test_demo_returns_404_when_file_missing(public_client, tmp_path, monkeypatch):
    monkeypatch.setattr(server_public, "DEMO_PATH", tmp_path / "nonexistent.knxproj")
    monkeypatch.setattr(server_public, "_demo_cache", None)
    r = await public_client.get("/api/demo")
    assert r.status_code == 404


@pytest.mark.skipif(not KNXPROJ_ETS6.exists(), reason="Test resources not available")
async def test_demo_parses_and_returns_project(public_client, monkeypatch):
    monkeypatch.setattr(server_public, "DEMO_PATH", KNXPROJ_ETS6)
    monkeypatch.setattr(server_public, "_demo_cache", None)
    r = await public_client.get("/api/demo")
    assert r.status_code == 200
    data = r.json()
    assert "devices" in data
    assert "group_addresses" in data


@pytest.mark.skipif(not KNXPROJ_ETS6.exists(), reason="Test resources not available")
async def test_demo_result_is_cached(public_client, monkeypatch):
    monkeypatch.setattr(server_public, "DEMO_PATH", KNXPROJ_ETS6)
    monkeypatch.setattr(server_public, "_demo_cache", None)
    r1 = await public_client.get("/api/demo")
    r2 = await public_client.get("/api/demo")
    assert r1.status_code == 200
    assert r2.status_code == 200
    assert server_public._demo_cache is not None


async def test_parse_invalid_file_returns_error(public_client):
    r = await public_client.post(
        "/api/parse",
        files={"file": ("bad.knxproj", b"not a zip file", "application/zip")},
        data={"password": ""},
    )
    assert r.status_code in (422, 500)


@pytest.mark.skipif(
    not (KNXPROJ_ETS6.parent / "xknx_test_project.knxproj").exists(),
    reason="Test resources not available",
)
async def test_parse_wrong_password_returns_422(public_client):
    protected = KNXPROJ_ETS6.parent / "xknx_test_project.knxproj"
    with open(protected, "rb") as f:
        r = await public_client.post(
            "/api/parse",
            files={"file": ("test.knxproj", f, "application/zip")},
            data={"password": "definitely_wrong"},
        )
    assert r.status_code in (422, 500)
