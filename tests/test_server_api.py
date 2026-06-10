"""API tests for the private server (server.py)."""
import json

import pytest

import server
from tests.conftest import KNXPROJ_ETS6


# ---------------------------------------------------------------------------
# Meta / static endpoints
# ---------------------------------------------------------------------------

async def test_mode_returns_private(server_client):
    r = await server_client.get("/api/mode")
    assert r.status_code == 200
    data = r.json()
    assert data["public"] is False
    assert data["default_theme"] in ("default", "voltlogik")
    assert "branding" in data


async def test_chrome_devtools_suppressed(server_client):
    r = await server_client.get("/.well-known/appspecific/com.chrome.devtools.json")
    assert r.status_code == 200
    assert r.json() == {}


# ---------------------------------------------------------------------------
# Gateway
# ---------------------------------------------------------------------------

async def test_gateway_defaults(server_client):
    r = await server_client.get("/api/gateway")
    assert r.status_code == 200
    data = r.json()
    assert data["ip"] == ""
    assert data["port"] == 3671
    assert data["connected"] is False
    assert data["language"] == "de-DE"


async def test_gateway_reflects_state(server_client):
    server.state["gateway_ip"] = "192.168.1.50"
    server.state["gateway_port"] = 3672
    server.state["connected"] = True
    server.state["language"] = "en-US"
    r = await server_client.get("/api/gateway")
    data = r.json()
    assert data["ip"] == "192.168.1.50"
    assert data["port"] == 3672
    assert data["connected"] is True
    assert data["language"] == "en-US"


async def test_set_gateway_saves_config(server_client, patched_paths, monkeypatch):
    async def noop():
        pass
    monkeypatch.setattr(server, "start_connect_task", noop)

    r = await server_client.post(
        "/api/gateway",
        json={"ip": "10.0.0.1", "port": 3671, "language": "en-US"},
    )
    assert r.status_code == 200
    assert r.json() == {"ok": True}

    cfg = json.loads((patched_paths / "config.json").read_text())
    assert cfg["gateway_ip"] == "10.0.0.1"
    assert cfg["language"] == "en-US"


# ---------------------------------------------------------------------------
# Current values
# ---------------------------------------------------------------------------

async def test_current_values_empty(server_client):
    r = await server_client.get("/api/current-values")
    assert r.status_code == 200
    assert r.json() == {}


async def test_current_values_with_data(server_client):
    server.state["current_values"] = {
        "1/2/3": {"value": "Ein", "ts": "2024-01-01 00:00:00.000"}
    }
    r = await server_client.get("/api/current-values")
    data = r.json()
    assert "1/2/3" in data
    assert data["1/2/3"]["value"] == "Ein"


# ---------------------------------------------------------------------------
# Last project
# ---------------------------------------------------------------------------

async def test_last_project_info_404_when_empty(server_client):
    r = await server_client.get("/api/last-project/info")
    assert r.status_code == 404


async def test_last_project_info_404_when_only_config(server_client, patched_paths):
    # Config has filename but no project file on disk → 404
    (patched_paths / "config.json").write_text(
        json.dumps({"last_project_filename": "missing.knxproj"})
    )
    r = await server_client.get("/api/last-project/info")
    assert r.status_code == 404


async def test_last_project_info_ok(server_client, patched_paths):
    (patched_paths / "config.json").write_text(
        json.dumps({"last_project_filename": "home.knxproj"})
    )
    (patched_paths / "last_project.json").write_text("{}")
    r = await server_client.get("/api/last-project/info")
    assert r.status_code == 200
    assert r.json()["filename"] == "home.knxproj"


async def test_last_project_data_404_when_empty(server_client):
    r = await server_client.get("/api/last-project/data")
    assert r.status_code == 404


async def test_last_project_data_with_state(server_client):
    server.state["project_data"] = {"devices": {}, "group_addresses": {}}
    r = await server_client.get("/api/last-project/data")
    assert r.status_code == 200
    assert "devices" in r.json()


# ---------------------------------------------------------------------------
# Annotations
# ---------------------------------------------------------------------------

async def test_annotations_default_when_no_file(server_client):
    r = await server_client.get("/api/annotations")
    assert r.status_code == 200
    assert r.json() == {"devices": {}, "group_addresses": {}}


async def test_annotations_reads_existing_file(server_client, patched_paths):
    data = {"devices": {"1.1.1": {"name": "Taster"}}, "group_addresses": {}}
    (patched_paths / "annotations.json").write_text(json.dumps(data))
    r = await server_client.get("/api/annotations")
    assert r.json()["devices"]["1.1.1"]["name"] == "Taster"


async def test_annotations_save_and_retrieve(server_client):
    payload = {
        "devices": {"1.1.5": {"name": "Lichtschalter", "description": "EG Flur"}},
        "group_addresses": {"1/2/3": {"name": "Licht EG"}},
    }
    r = await server_client.post("/api/annotations", json=payload)
    assert r.status_code == 200
    assert r.json() == {"ok": True}

    r = await server_client.get("/api/annotations")
    data = r.json()
    assert data["devices"]["1.1.5"]["name"] == "Lichtschalter"
    assert data["group_addresses"]["1/2/3"]["name"] == "Licht EG"


async def test_annotations_persisted_to_disk(server_client, patched_paths):
    payload = {"devices": {}, "group_addresses": {"2/3/4": {"name": "Rolllade"}}}
    await server_client.post("/api/annotations", json=payload)
    saved = json.loads((patched_paths / "annotations.json").read_text())
    assert saved["group_addresses"]["2/3/4"]["name"] == "Rolllade"


# ---------------------------------------------------------------------------
# Log
# ---------------------------------------------------------------------------

async def test_log_empty_when_no_file(server_client):
    r = await server_client.get("/api/log")
    assert r.status_code == 200
    assert r.json() == []


async def test_log_returns_parsed_entries(server_client, patched_paths):
    log_path = patched_paths / "knx_bus.log"
    log_path.write_text(
        "2024-01-15 14:32:01.234 | 1.1.5 | Taster EG | 1/2/3 | Licht Küche | Ein\n"
        "2024-01-15 14:33:00.000 | 1.1.6 | Sensor | 2/3/4 | Temperatur | 21.50 °C\n"
    )
    r = await server_client.get("/api/log")
    assert r.status_code == 200
    entries = r.json()
    assert len(entries) == 2
    assert entries[0]["src"] == "1.1.5"
    assert entries[0]["ga"] == "1/2/3"
    assert entries[1]["value"] == "21.50 °C"


async def test_log_skips_malformed_lines(server_client, patched_paths):
    (patched_paths / "knx_bus.log").write_text(
        "bad line\n"
        "2024-01-15 14:32:01.234 | 1.1.5 | Gerät | 1/2/3 | GA | Ein\n"
    )
    entries = (await server_client.get("/api/log")).json()
    assert len(entries) == 1


async def test_log_lines_parameter(server_client, patched_paths):
    lines = [
        f"2024-01-15 14:32:01.234 | 1.1.5 | Gerät | 1/2/{i} | GA | Ein\n"
        for i in range(20)
    ]
    (patched_paths / "knx_bus.log").write_text("".join(lines))
    entries = (await server_client.get("/api/log?lines=5")).json()
    assert len(entries) == 5


# ---------------------------------------------------------------------------
# Parse .knxproj
# ---------------------------------------------------------------------------

@pytest.mark.skipif(not KNXPROJ_ETS6.exists(), reason="Test resources not available")
async def test_parse_ets6_project(server_client, patched_paths):
    with open(KNXPROJ_ETS6, "rb") as f:
        r = await server_client.post(
            "/api/parse",
            files={"file": ("ets6_free.knxproj", f, "application/zip")},
            data={"password": "", "language": "de-DE"},
        )
    assert r.status_code == 200
    data = r.json()
    assert "devices" in data
    assert "group_addresses" in data
    assert "communication_objects" in data


@pytest.mark.skipif(not KNXPROJ_ETS6.exists(), reason="Test resources not available")
async def test_parse_updates_state(server_client, patched_paths):
    with open(KNXPROJ_ETS6, "rb") as f:
        await server_client.post(
            "/api/parse",
            files={"file": ("ets6_free.knxproj", f, "application/zip")},
            data={"password": "", "language": "de-DE"},
        )
    assert server.state["project_data"] is not None
    assert isinstance(server.state["ga_dpt_map"], dict)


@pytest.mark.skipif(not KNXPROJ_ETS6.exists(), reason="Test resources not available")
async def test_parse_persists_project_file(server_client, patched_paths):
    with open(KNXPROJ_ETS6, "rb") as f:
        await server_client.post(
            "/api/parse",
            files={"file": ("ets6_free.knxproj", f, "application/zip")},
            data={"password": "", "language": "de-DE"},
        )
    assert (patched_paths / "last_project.json").exists()
    assert (patched_paths / "config.json").exists()
    cfg = json.loads((patched_paths / "config.json").read_text())
    assert cfg["last_project_filename"] == "ets6_free.knxproj"


@pytest.mark.skipif(not KNXPROJ_ETS6.exists(), reason="Test resources not available")
async def test_parse_then_last_project_info(server_client, patched_paths):
    with open(KNXPROJ_ETS6, "rb") as f:
        await server_client.post(
            "/api/parse",
            files={"file": ("ets6_free.knxproj", f, "application/zip")},
            data={"password": "", "language": "de-DE"},
        )
    r = await server_client.get("/api/last-project/info")
    assert r.status_code == 200
    assert r.json()["filename"] == "ets6_free.knxproj"


async def test_parse_wrong_password_returns_422(server_client):
    # Create a minimal zip file that is recognized as knxproj but has bad password
    # Use the password-protected project file
    protected = KNXPROJ_ETS6.parent / "xknx_test_project.knxproj"
    if not protected.exists():
        pytest.skip("Password-protected test file not available")
    with open(protected, "rb") as f:
        r = await server_client.post(
            "/api/parse",
            files={"file": ("test.knxproj", f, "application/zip")},
            data={"password": "wrong_password"},
        )
    assert r.status_code in (422, 500)


async def test_parse_invalid_file_returns_error(server_client):
    r = await server_client.post(
        "/api/parse",
        files={"file": ("bad.knxproj", b"not a zip file at all", "application/zip")},
        data={"password": ""},
    )
    assert r.status_code in (422, 500)
