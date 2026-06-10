"""Tests for /api/recent-projects — listing, data loading, notes, slug validation."""
import json

import core
import server


_PROJECT = {
    "info": {"name": "Testprojekt"},
    "devices": {"1.1.1": {"name": "Taster"}},
    "group_addresses": {
        "ga1": {"address": "1/2/3", "name": "Licht", "dpt": {"main": 1, "sub": 1}},
    },
}


def _store_project(filename="haus.knxproj"):
    core.add_to_recent_projects(filename, _PROJECT)
    return core.project_slug(filename)


# ---------------------------------------------------------------------------
# Listing / metadata
# ---------------------------------------------------------------------------

async def test_empty_list(server_client):
    r = await server_client.get("/api/recent-projects")
    assert r.status_code == 200
    assert r.json() == []


async def test_add_and_list(server_client, patched_paths):
    slug = _store_project()
    r = await server_client.get("/api/recent-projects")
    items = r.json()
    assert len(items) == 1
    assert items[0]["slug"] == slug
    assert items[0]["project_name"] == "Testprojekt"
    assert items[0]["device_count"] == 1
    assert items[0]["ga_count"] == 1


async def test_max_recent_projects(server_client, patched_paths):
    for i in range(core.MAX_RECENT_PROJECTS + 3):
        core.add_to_recent_projects(f"projekt_{i}.knxproj", _PROJECT)
    items = (await server_client.get("/api/recent-projects")).json()
    assert len(items) == core.MAX_RECENT_PROJECTS


# ---------------------------------------------------------------------------
# Project data
# ---------------------------------------------------------------------------

async def test_get_data_updates_state(server_client, patched_paths):
    slug = _store_project()
    r = await server_client.get(f"/api/recent-projects/{slug}/data")
    assert r.status_code == 200
    assert r.json()["info"]["name"] == "Testprojekt"
    # Loading must rebuild the GA lookup maps in server state
    assert server.state["ga_dpt_map"]["1/2/3"] == {"main": 1, "sub": 1}
    assert server.state["ga_name_map"]["1/2/3"] == "Licht"


async def test_get_data_unknown_slug_404(server_client, patched_paths):
    r = await server_client.get("/api/recent-projects/unknown.knxproj/data")
    assert r.status_code == 404


async def test_get_raw(server_client, patched_paths):
    slug = _store_project()
    r = await server_client.get(f"/api/recent-projects/{slug}/raw")
    assert r.status_code == 200
    assert r.json()["devices"]["1.1.1"]["name"] == "Taster"


async def test_delete(server_client, patched_paths):
    slug = _store_project()
    r = await server_client.delete(f"/api/recent-projects/{slug}")
    assert r.status_code == 200
    assert (await server_client.get("/api/recent-projects")).json() == []
    assert not (core.PROJECTS_DIR / f"{slug}.json").exists()


# ---------------------------------------------------------------------------
# Notes
# ---------------------------------------------------------------------------

async def test_notes_roundtrip(server_client, patched_paths):
    slug = _store_project()
    r = await server_client.post(
        f"/api/recent-projects/{slug}/notes", json={"text": "Meine Notiz"}
    )
    assert r.status_code == 200
    notes = (await server_client.get("/api/recent-projects/notes")).json()
    assert notes[slug] == "Meine Notiz"


async def test_notes_unknown_project_404(server_client, patched_paths):
    core.PROJECTS_DIR.mkdir(exist_ok=True)
    r = await server_client.post(
        "/api/recent-projects/unknown/notes", json={"text": "x"}
    )
    assert r.status_code == 404


# ---------------------------------------------------------------------------
# Slug validation — path traversal must be rejected
# ---------------------------------------------------------------------------

async def test_traversal_slug_rejected(server_client, patched_paths):
    # Write a file outside PROJECTS_DIR that a traversal would reach.
    # Both rejection paths are fine (400 from validation, 404 from routing) —
    # the file content must never be returned.
    (patched_paths / "secret.json").write_text(json.dumps({"secret": True}))
    core.PROJECTS_DIR.mkdir(exist_ok=True)
    for slug in ("..%2Fsecret", "..%5Csecret", "%2e%2e%2fsecret"):
        for endpoint in ("data", "raw", "xml", "knxproj"):
            r = await server_client.get(f"/api/recent-projects/{slug}/{endpoint}")
            assert r.status_code in (400, 404), f"{slug}/{endpoint}"
            assert b"secret" not in r.content or r.status_code != 200


async def test_backslash_slug_rejected_by_validation(server_client, patched_paths):
    # Backslash passes Starlette routing but must hit our slug validation
    core.PROJECTS_DIR.mkdir(exist_ok=True)
    r = await server_client.get("/api/recent-projects/..%5Cfoo/raw")
    assert r.status_code == 400


async def test_traversal_slug_rejected_on_notes_write(server_client, patched_paths):
    (patched_paths / "victim.json").write_text("{}")
    core.PROJECTS_DIR.mkdir(exist_ok=True)
    r = await server_client.post(
        "/api/recent-projects/..%5Cvictim/notes", json={"text": "pwned"}
    )
    assert r.status_code in (400, 404)
    assert not (patched_paths / "victim.notes.md").exists()


async def test_dotdot_slug_rejected(server_client, patched_paths):
    r = await server_client.get("/api/recent-projects/../raw")
    # httpx normalizes "../"; send encoded variant explicitly
    r = await server_client.get("/api/recent-projects/%2E%2E/raw")
    assert r.status_code in (400, 404)


def test_project_slug_sanitizes():
    assert core.project_slug("mein haus.knxproj") == "mein_haus.knxproj"
    assert "/" not in core.project_slug("a/b/c")
    assert core.project_slug("../etc/passwd") == ".._etc_passwd"
