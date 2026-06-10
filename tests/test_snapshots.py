"""Tests for /api/snapshots — create, list, delete, diff."""
import server


def _load_project():
    server.state["project_data"] = {
        "info": {"name": "Snap Test"},
        "group_addresses": {
            "ga1": {"address": "1/2/3", "name": "Licht", "dpt": {"main": 1, "sub": 1}},
        },
    }


async def test_list_empty_without_project(server_client):
    r = await server_client.get("/api/snapshots")
    assert r.status_code == 200
    assert r.json() == {"snapshots": []}


async def test_create_requires_project(server_client, patched_paths):
    r = await server_client.post("/api/snapshots", json={"name": "x"})
    assert r.status_code == 400


async def test_create_and_list(server_client, patched_paths):
    _load_project()
    server.state["current_values"] = {"1/2/3": {"value": "Ein", "ts": "2026-01-01 00:00:00"}}
    r = await server_client.post("/api/snapshots", json={"name": "Vorher"})
    assert r.status_code == 200
    snap = r.json()["snapshot"]
    assert snap["name"] == "Vorher"
    assert snap["count"] == 1

    items = (await server_client.get("/api/snapshots")).json()["snapshots"]
    assert len(items) == 1
    assert items[0]["id"] == snap["id"]


async def test_delete(server_client, patched_paths):
    _load_project()
    sid = (await server_client.post("/api/snapshots", json={})).json()["snapshot"]["id"]
    r = await server_client.delete(f"/api/snapshots/{sid}")
    assert r.status_code == 200
    assert (await server_client.get("/api/snapshots")).json()["snapshots"] == []


async def test_delete_unknown_404(server_client, patched_paths):
    _load_project()
    r = await server_client.delete("/api/snapshots/nope")
    assert r.status_code == 404


async def test_diff_against_current(server_client, patched_paths):
    _load_project()
    server.state["current_values"] = {"1/2/3": {"value": "Ein", "ts": "t1"}}
    sid = (await server_client.post("/api/snapshots", json={})).json()["snapshot"]["id"]

    # Change a value and add a new GA
    server.state["current_values"] = {
        "1/2/3": {"value": "Aus", "ts": "t2"},
        "4/5/6": {"value": "21.50 °C", "ts": "t2"},
    }
    r = await server_client.get(f"/api/snapshots/diff?a={sid}&b=current")
    assert r.status_code == 200
    data = r.json()
    assert data["stats"]["changed"] == 1
    assert data["stats"]["only_b"] == 1
    changed = next(row for row in data["rows"] if row["address"] == "1/2/3")
    assert changed["value_a"] == "Ein"
    assert changed["value_b"] == "Aus"
    assert changed["name"] == "Licht"
    assert changed["dpt"] == "1.001"


async def test_diff_unknown_snapshot_404(server_client, patched_paths):
    _load_project()
    r = await server_client.get("/api/snapshots/diff?a=missing&b=current")
    assert r.status_code == 404
