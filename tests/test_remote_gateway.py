"""Tests für den Remote-Gateway-Proxy-Mechanismus."""
import json
import uuid
from unittest.mock import AsyncMock, patch

import pytest
from httpx import ASGITransport, AsyncClient

import server
from server import _make_telegram_from_proxy, remote_gateway_endpoint
from xknx.dpt import DPTArray, DPTBinary
from xknx.telegram.apci import GroupValueRead, GroupValueResponse, GroupValueWrite


@pytest.fixture
async def client(patched_paths):
    async with AsyncClient(
        transport=ASGITransport(app=server.app), base_url="http://test"
    ) as c:
        yield c


# ── Test 1: GET /api/gateway enthält neue Felder ──────────────────────────────

async def test_get_gateway_includes_remote_fields(client, patched_paths):
    resp = await client.get("/api/gateway")
    assert resp.status_code == 200
    data = resp.json()
    assert "connection_type" in data
    assert "remote_gateway_token" in data
    assert "remote_gateway_connected" in data
    assert data["connection_type"] == "local"
    assert data["remote_gateway_connected"] is False


# ── Test 2: Token wird auto-generiert wenn leer ───────────────────────────────

async def test_token_auto_generated(client, patched_paths):
    # Config-Datei existiert noch nicht → load_config generiert Token
    resp = await client.get("/api/gateway")
    assert resp.status_code == 200
    token = resp.json()["remote_gateway_token"]
    assert token  # nicht leer
    assert len(token) == 36  # UUID4-Format (xxxxxxxx-xxxx-xxxx-xxxx-xxxxxxxxxxxx)


async def test_token_stable_across_calls(client, patched_paths):
    resp1 = await client.get("/api/gateway")
    resp2 = await client.get("/api/gateway")
    assert resp1.json()["remote_gateway_token"] == resp2.json()["remote_gateway_token"]


# ── Test 3: _make_telegram_from_proxy für binary/array/read ──────────────────

def test_make_telegram_binary():
    msg = {
        "apci": "GroupValueWrite",
        "src": "1.1.1",
        "ga": "0/0/1",
        "payload_type": "binary",
        "payload_value": 1,
    }
    tg = _make_telegram_from_proxy(msg)
    assert str(tg.destination_address) == "0/0/1"
    assert str(tg.source_address) == "1.1.1"
    assert isinstance(tg.payload, GroupValueWrite)
    assert isinstance(tg.payload.value, DPTBinary)
    assert tg.payload.value.value == 1


def test_make_telegram_array():
    msg = {
        "apci": "GroupValueWrite",
        "src": "1.1.2",
        "ga": "1/2/3",
        "payload_type": "array",
        "payload_value": [12, 26],
    }
    tg = _make_telegram_from_proxy(msg)
    assert isinstance(tg.payload, GroupValueWrite)
    assert isinstance(tg.payload.value, DPTArray)
    assert tg.payload.value.value == (12, 26)


def test_make_telegram_read():
    msg = {
        "apci": "GroupValueRead",
        "src": "1.1.3",
        "ga": "2/3/4",
        "payload_type": "none",
    }
    tg = _make_telegram_from_proxy(msg)
    assert isinstance(tg.payload, GroupValueRead)


def test_make_telegram_response():
    msg = {
        "apci": "GroupValueResponse",
        "src": "1.1.4",
        "ga": "3/4/5",
        "payload_type": "binary",
        "payload_value": 0,
    }
    tg = _make_telegram_from_proxy(msg)
    assert isinstance(tg.payload, GroupValueResponse)


# ── Test 4: ga_write im remote_gateway-Modus sendet an Mock-WS ───────────────

async def test_ga_write_remote_sends_to_ws(client, patched_paths):
    mock_ws = AsyncMock()
    server.state["connected"] = True
    server.state["connection_type"] = "remote_gateway"
    server.state["remote_gateway_ws"] = mock_ws
    server.state["ga_dpt_map"]["1/2/3"] = {"main": 1, "sub": 1}
    server.state["project_data"] = {"group_addresses": {}, "devices": {}}

    resp = await client.post("/api/ga/write", json={"ga": "1/2/3", "value": "1"})
    assert resp.status_code == 200
    mock_ws.send_json.assert_called_once()
    call_arg = mock_ws.send_json.call_args[0][0]
    assert call_arg["type"] == "write"
    assert call_arg["ga"] == "1/2/3"


async def test_ga_write_remote_no_ws_raises_503(client, patched_paths):
    server.state["connected"] = True
    server.state["connection_type"] = "remote_gateway"
    server.state["remote_gateway_ws"] = None
    server.state["ga_dpt_map"]["1/2/3"] = {"main": 1, "sub": 1}

    resp = await client.post("/api/ga/write", json={"ga": "1/2/3", "value": "1"})
    assert resp.status_code == 503


# ── Test 5: /ws/remote-gateway schließt mit 4001 bei falschem Token ──────────

async def test_remote_gateway_ws_wrong_token(patched_paths):
    """Endpoint soll bei falschem Token ws.close(4001) aufrufen."""
    correct_token = str(uuid.uuid4())
    cfg_path = patched_paths / "config.json"
    cfg_path.write_text(json.dumps({
        "connection_type": "remote_gateway",
        "remote_gateway_token": correct_token,
    }))
    server.state["connection_type"] = "remote_gateway"

    mock_ws = AsyncMock()
    with patch.object(server, "load_config", return_value={
        "connection_type": "remote_gateway",
        "remote_gateway_token": correct_token,
    }):
        await remote_gateway_endpoint(mock_ws, token="wrong-token-xyz")

    mock_ws.close.assert_called_once_with(code=4001)
    mock_ws.accept.assert_not_called()


# ── Test 6: /ws/remote-gateway schließt mit 4002 wenn Modus "local" ──────────

async def test_remote_gateway_ws_wrong_mode(patched_paths):
    """Endpoint soll bei falscher connection_type ws.close(4002) aufrufen."""
    token = str(uuid.uuid4())
    server.state["connection_type"] = "local"

    mock_ws = AsyncMock()
    with patch.object(server, "load_config", return_value={
        "connection_type": "local",
        "remote_gateway_token": token,
    }):
        # Modus ist "local" aber Token stimmt überein
        await remote_gateway_endpoint(mock_ws, token=token)

    mock_ws.close.assert_called_once_with(code=4002)
    mock_ws.accept.assert_not_called()
