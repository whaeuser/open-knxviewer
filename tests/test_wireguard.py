"""Tests for WireGuard integration: allowed actions, capability gating, API endpoints."""
import pytest
from httpx import ASGITransport, AsyncClient

import server
from server import _compute_allowed_actions


# ── Pure function tests ────────────────────────────────────────────────────────

def test_allowed_none():
    assert _compute_allowed_actions(None) == ["monitor"]


def test_allowed_fast():
    result = _compute_allowed_actions(30)
    assert result == ["monitor", "ga_rw", "ets_params", "ets_program"]


def test_allowed_medium():
    result = _compute_allowed_actions(100)
    assert "ets_program" not in result
    assert "ets_params" in result
    assert "ga_rw" in result
    assert "monitor" in result


def test_allowed_slow():
    result = _compute_allowed_actions(300)
    assert result == ["monitor", "ga_rw"]


def test_allowed_very_slow():
    result = _compute_allowed_actions(600)
    assert result == ["monitor"]


def test_allowed_boundary_50():
    """Exactly 50ms → medium bucket (50–150ms)."""
    result = _compute_allowed_actions(50)
    assert "ets_program" not in result
    assert "ets_params" in result


def test_allowed_boundary_150():
    """Exactly 150ms → slow bucket (150–500ms)."""
    result = _compute_allowed_actions(150)
    assert result == ["monitor", "ga_rw"]


# ── Latency parse test ─────────────────────────────────────────────────────────

def test_measure_latency_parse():
    """_measure_latency extracts avg RTT from ping output."""
    import re
    ping_output = (
        "PING 10.100.0.2 (10.100.0.2) 56(84) bytes of data.\n"
        "64 bytes from 10.100.0.2: icmp_seq=1 ttl=64 time=12.3 ms\n"
        "64 bytes from 10.100.0.2: icmp_seq=2 ttl=64 time=11.8 ms\n"
        "64 bytes from 10.100.0.2: icmp_seq=3 ttl=64 time=12.1 ms\n"
        "\n"
        "--- 10.100.0.2 ping statistics ---\n"
        "3 packets transmitted, 3 received, 0% packet loss, time 2003ms\n"
        "rtt min/avg/max/mdev = 11.800/12.067/12.300/0.204 ms\n"
    )
    m = re.search(r"min/avg/max/\w+ = [\d.]+/([\d.]+)/", ping_output)
    assert m is not None
    assert float(m.group(1)) == pytest.approx(12.067)


# ── API endpoint tests ─────────────────────────────────────────────────────────

@pytest.fixture
async def wg_client(patched_paths):
    """HTTP client for private server without lifespan."""
    async with AsyncClient(
        transport=ASGITransport(app=server.app), base_url="http://test"
    ) as client:
        yield client


async def test_status_endpoint(wg_client):
    resp = await wg_client.get("/api/wireguard/status")
    assert resp.status_code == 200
    data = resp.json()
    assert "enabled" in data
    assert "latency_ms" in data
    assert "peer_connected" in data
    assert "allowed_actions" in data
    assert "ets_port_active" in data
    assert data["allowed_actions"] == ["monitor"]


async def test_ga_write_blocked_by_wireguard(wg_client):
    """WG active, very high latency (>500ms) → ga_write returns 503."""
    server.state["connected"] = True
    server.state["wireguard_enabled"] = True
    server.state["wireguard_latency_ms"] = 600
    server.state["wireguard_allowed_actions"] = _compute_allowed_actions(600)
    server.state["ga_dpt_map"] = {"1/2/3": {"main": 1, "sub": 1}}

    resp = await wg_client.post("/api/ga/write", json={"ga": "1/2/3", "value": "1"})
    assert resp.status_code == 503
    assert "Latenz" in resp.json()["detail"]


async def test_ga_write_allowed_with_wireguard(wg_client, monkeypatch):
    """WG active, low latency → ga_write proceeds (until actual KNX call)."""
    server.state["connected"] = True
    server.state["wireguard_enabled"] = True
    server.state["wireguard_latency_ms"] = 30
    server.state["wireguard_allowed_actions"] = _compute_allowed_actions(30)
    server.state["ga_dpt_map"] = {"1/2/3": {"main": 1, "sub": 1}}

    # Mock xknx.telegrams.put to avoid real KNX connection
    class FakeQueue:
        async def put(self, _): pass

    class FakeXknx:
        telegrams = FakeQueue()

    server.state["xknx"] = FakeXknx()
    server.state["connection_type"] = "local"

    resp = await wg_client.post("/api/ga/write", json={"ga": "1/2/3", "value": "1"})
    assert resp.status_code == 200


async def test_ga_write_not_blocked_when_wg_disabled(wg_client, monkeypatch):
    """WG disabled → high latency state has no effect on ga_write."""
    server.state["connected"] = True
    server.state["wireguard_enabled"] = False
    server.state["wireguard_latency_ms"] = 600
    server.state["wireguard_allowed_actions"] = ["monitor"]
    server.state["ga_dpt_map"] = {"1/2/3": {"main": 1, "sub": 1}}

    class FakeQueue:
        async def put(self, _): pass

    class FakeXknx:
        telegrams = FakeQueue()

    server.state["xknx"] = FakeXknx()
    server.state["connection_type"] = "local"

    resp = await wg_client.post("/api/ga/write", json={"ga": "1/2/3", "value": "1"})
    assert resp.status_code == 200


async def test_peer_config_download(wg_client, patched_paths):
    """GET /api/wireguard/peer-config returns a valid WireGuard INI config."""
    import json
    cfg = {
        "gateway_ip": "", "gateway_port": 3671, "language": "de-DE",
        "connection_type": "local", "remote_gateway_token": "test-token",
        "wireguard_enabled": True,
        "wireguard_interface": "wg0",
        "wireguard_server_ip": "10.100.0.1",
        "wireguard_peer_ip": "10.100.0.2",
        "wireguard_listen_port": 51820,
        "wireguard_ets_port": 13671,
        "wireguard_knx_ip": "192.168.1.100",
        "wireguard_knx_port": 3671,
        "wireguard_peer_public_key": "",
        "wireguard_server_public_key": "FAKEPUBKEY=",
        "wireguard_server_public_ip": "1.2.3.4",
    }
    (patched_paths / "config.json").write_text(json.dumps(cfg))

    resp = await wg_client.get("/api/wireguard/peer-config")
    assert resp.status_code == 200
    text = resp.text
    assert "[Interface]" in text
    assert "[Peer]" in text
    assert "FAKEPUBKEY=" in text
    assert "10.100.0.2/24" in text
    assert "1.2.3.4:51820" in text
    assert "PersistentKeepalive = 25" in text
