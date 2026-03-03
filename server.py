import asyncio
import csv
import io
import json
import logging
import os
import socket
import struct
import tempfile
import uuid
from collections import deque
from contextlib import asynccontextmanager
from datetime import datetime
from logging.handlers import TimedRotatingFileHandler
from pathlib import Path
from typing import Set

import httpx
from fastapi import FastAPI, File, Form, HTTPException, Query, UploadFile, WebSocket, WebSocketDisconnect
from fastapi.responses import FileResponse, JSONResponse, StreamingResponse

from xknx import XKNX
from xknx.dpt import DPTArray, DPTBase, DPTBinary
from xknx.io import ConnectionConfig, ConnectionType
from xknx.telegram import Telegram
from xknx.telegram.address import GroupAddress, IndividualAddress
from xknx.telegram.apci import GroupValueRead, GroupValueResponse, GroupValueWrite
from xknxproject import XKNXProj
from xknxproject.exceptions import InvalidPasswordException, XknxProjectException
from xknxproject.zip.extractor import extract as knxproj_extract

INDEX_HTML = Path(__file__).parent / "index.html"
CONFIG_PATH = Path(__file__).parent / "config.json"
ANNOTATIONS_PATH = Path(__file__).parent / "annotations.json"
LOG_PATH = Path(__file__).parent / "logs" / "knx_bus.log"
LAST_PROJECT_PATH = Path(__file__).parent / "last_project.json"

state: dict = {
    "xknx": None,
    "connected": False,
    "gateway_ip": "",
    "gateway_port": 3671,
    "language": "de-DE",
    "project_data": None,
    "ga_dpt_map": {},
    "current_values": {},
    "telegram_buffer": deque(maxlen=500),
    "ws_clients": set(),
    "connect_task": None,
    "connection_type": "local",
    "remote_gateway_token": "",
    "remote_gateway_ws": None,
    "remote_gateway_connected": False,
    # Scan state
    "ga_scan_running": False,
    "ga_scan_cancel": False,
    "pa_scan_running": False,
    "pa_scan_cancel": False,
    # WireGuard
    "wireguard_enabled": False,
    "wireguard_peer_connected": False,
    "wireguard_latency_ms": None,
    "wireguard_allowed_actions": ["monitor"],
    "wireguard_latency_task": None,
    "wireguard_ets_port_active": False,
}


WG_HELPER = "/usr/local/bin/openknxviewer-wg-helper"


def load_config() -> dict:
    defaults = {
        "gateway_ip": "", "gateway_port": 3671, "language": "de-DE",
        "connection_type": "local", "remote_gateway_token": "",
        # WireGuard defaults
        "wireguard_enabled": False,
        "wireguard_interface": "wg0",
        "wireguard_server_ip": "10.100.0.1",
        "wireguard_peer_ip": "10.100.0.2",
        "wireguard_listen_port": 51820,
        "wireguard_ets_port": 13671,
        "wireguard_knx_ip": "",
        "wireguard_knx_port": 3671,
        "wireguard_peer_public_key": "",
    }
    if CONFIG_PATH.exists():
        cfg = {**defaults, **json.loads(CONFIG_PATH.read_text())}
    else:
        cfg = defaults
    if not cfg["remote_gateway_token"]:
        cfg["remote_gateway_token"] = str(uuid.uuid4())
        save_config(cfg)
    return cfg


def save_config(cfg: dict):
    CONFIG_PATH.write_text(json.dumps(cfg, indent=2))


# ── WireGuard helpers ──────────────────────────────────────────────────────────

async def _wg_run(*args: str) -> str:
    """Run wg_helper via sudo and return stdout, raise RuntimeError on failure."""
    proc = await asyncio.create_subprocess_exec(
        "sudo", WG_HELPER, *args,
        stdout=asyncio.subprocess.PIPE,
        stderr=asyncio.subprocess.PIPE,
    )
    stdout, stderr = await proc.communicate()
    if proc.returncode != 0:
        raise RuntimeError(stderr.decode().strip() or f"wg_helper exited {proc.returncode}")
    return stdout.decode().strip()


async def wg_setup(cfg: dict) -> str:
    """Generate keys, write wg0.conf via helper, start tunnel. Returns server public key."""
    iface = cfg.get("wireguard_interface", "wg0")
    privkey_file = f"/etc/wireguard/{iface}_private.key"
    # genkey writes private key to file, prints public key to stdout
    pub_key = await _wg_run("genkey", privkey_file)
    await _wg_run(
        "setup", iface,
        cfg["wireguard_server_ip"],
        cfg["wireguard_peer_ip"],
        str(cfg["wireguard_listen_port"]),
        privkey_file,
    )
    return pub_key


async def wg_add_peer(public_key: str, cfg: dict) -> None:
    """Add peer live: wg set <iface> peer <key> allowed-ips <peer_ip>/32."""
    await _wg_run("peer-add", cfg["wireguard_interface"], public_key, cfg["wireguard_peer_ip"])


async def wg_get_status(iface: str = "wg0") -> dict:
    """`wg show <iface> dump` → parsed dict."""
    try:
        output = await _wg_run("status", iface)
    except RuntimeError:
        return {"peer_connected": False}
    lines = output.splitlines()
    result = {"peer_connected": False, "latest_handshake_s": 0, "rx_bytes": 0, "tx_bytes": 0}
    for line in lines[1:]:  # first line is interface itself
        parts = line.split("\t")
        if len(parts) >= 6:
            try:
                handshake = int(parts[4])
            except ValueError:
                handshake = 0
            result["peer_connected"] = handshake > 0
            result["latest_handshake_s"] = handshake
            try:
                result["rx_bytes"] = int(parts[5])
                result["tx_bytes"] = int(parts[6]) if len(parts) > 6 else 0
            except (ValueError, IndexError):
                pass
            break
    return result


async def wg_set_ets_forward(enable: bool, cfg: dict) -> None:
    """Enable/disable iptables DNAT rule for ETS port forwarding."""
    cmd = "nat-add" if enable else "nat-del"
    await _wg_run(
        cmd,
        str(cfg["wireguard_ets_port"]),
        cfg["wireguard_peer_ip"],
        str(cfg["wireguard_knx_port"]),
    )


async def _measure_latency(peer_ip: str) -> float | None:
    """ping -c 3 -W 1 <peer_ip> → average RTT in ms, or None on failure."""
    try:
        proc = await asyncio.create_subprocess_exec(
            "ping", "-c", "3", "-W", "1", peer_ip,
            stdout=asyncio.subprocess.PIPE,
            stderr=asyncio.subprocess.DEVNULL,
        )
        stdout, _ = await asyncio.wait_for(proc.communicate(), timeout=10)
        output = stdout.decode()
        # Parse "rtt min/avg/max/mdev = X.XXX/X.XXX/X.XXX/X.XXX ms"
        import re
        m = re.search(r"min/avg/max/\w+ = [\d.]+/([\d.]+)/", output)
        if m:
            return float(m.group(1))
    except Exception:
        pass
    return None


def _compute_allowed_actions(latency_ms: float | None) -> list[str]:
    if latency_ms is None:
        return ["monitor"]
    if latency_ms < 50:
        return ["monitor", "ga_rw", "ets_params", "ets_program"]
    if latency_ms < 150:
        return ["monitor", "ga_rw", "ets_params"]
    if latency_ms < 500:
        return ["monitor", "ga_rw"]
    return ["monitor"]


async def wireguard_monitor_loop():
    """Every 30s: measure latency, update state, broadcast wireguard_status."""
    while True:
        try:
            cfg = load_config()
            peer_ip = cfg.get("wireguard_peer_ip", "10.100.0.2")
            latency = await _measure_latency(peer_ip)
            state["wireguard_latency_ms"] = latency
            state["wireguard_allowed_actions"] = _compute_allowed_actions(latency)
            wg_st = await wg_get_status(cfg.get("wireguard_interface", "wg0"))
            state["wireguard_peer_connected"] = wg_st.get("peer_connected", False)
            await broadcast({
                "type": "wireguard_status",
                "latency_ms": latency,
                "peer_connected": state["wireguard_peer_connected"],
                "allowed_actions": state["wireguard_allowed_actions"],
            })
        except Exception as exc:
            logging.getLogger("knx_bus").warning("WireGuard monitor error: %s", exc)
        await asyncio.sleep(30)


def _build_dpt1_lookup() -> dict[str, str]:
    """Map old xknx enum repr strings (e.g. 'Switch.ON') to 'Ein'/'Aus'."""
    lookup: dict[str, str] = {}
    for sub in range(0, 30):
        try:
            t = DPTBase.parse_transcoder({"main": 1, "sub": sub})
            for bit in (0, 1):
                r = t.from_knx(DPTBinary(bit))
                lookup[str(r)] = "Ein" if bit else "Aus"
        except Exception:
            pass
    return lookup


_DPT1_LEGACY: dict[str, str] = _build_dpt1_lookup()


def setup_log():
    LOG_PATH.parent.mkdir(exist_ok=True)
    handler = TimedRotatingFileHandler(
        LOG_PATH, when="midnight", backupCount=30, encoding="utf-8"
    )
    handler.setFormatter(logging.Formatter("%(message)s"))
    logger = logging.getLogger("knx_bus")
    logger.addHandler(handler)
    logger.setLevel(logging.INFO)
    return logger


bus_logger = setup_log()


async def broadcast(msg: dict):
    dead = set()
    for ws in state["ws_clients"]:
        try:
            await ws.send_json(msg)
        except Exception:
            dead.add(ws)
    state["ws_clients"] -= dead


def telegram_received_cb(telegram):
    asyncio.create_task(_process_telegram(telegram))


async def _process_telegram(telegram):
    src = str(telegram.source_address)
    ga = str(telegram.destination_address)

    device_name = ""
    if state["project_data"]:
        dev = state["project_data"].get("devices", {}).get(src, {})
        device_name = dev.get("name", "")

    ga_name = ""
    if state["project_data"]:
        for gad in state["project_data"].get("group_addresses", {}).values():
            if gad.get("address") == ga:
                ga_name = gad.get("name", "")
                break

    # APCI type (GroupValueWrite / GroupValueRead / GroupValueResponse)
    apci_type = type(telegram.payload).__name__

    # Raw value (payload before DPT decoding)
    if hasattr(telegram.payload, "value") and telegram.payload.value is not None:
        raw_value = str(telegram.payload.value)
    else:
        raw_value = str(telegram.payload)

    # Use xknx's decoded value (DPT-aware) if available, otherwise fall back to raw
    dpt = ""
    dpt_estimate = ""
    if telegram.decoded_data is not None:
        decoded = telegram.decoded_data.value
        transcoder = telegram.decoded_data.transcoder
        unit = getattr(transcoder, "unit", "") or ""
        main = getattr(transcoder, "dpt_main_number", None)
        sub = getattr(transcoder, "dpt_sub_number", None)
        if main is not None:
            dpt = f"{main}.{str(sub).zfill(3)}" if sub is not None else str(main)
        bool_val = decoded if isinstance(decoded, bool) else (decoded.value if isinstance(getattr(decoded, "value", None), bool) else None)
        if bool_val is not None:
            value = "Ein" if bool_val else "Aus"
        elif isinstance(decoded, float):
            value = f"{decoded:.2f}{' ' + unit if unit else ''}"
        else:
            value = f"{decoded}{' ' + unit if unit else ''}"
    else:
        value = raw_value
        # DPT estimate from payload size when no DPT is known
        payload_val = getattr(telegram.payload, "value", None)
        if payload_val is not None:
            if isinstance(payload_val, DPTBinary):
                dpt_estimate = "1.x"
            elif isinstance(payload_val, DPTArray):
                n = len(payload_val.value)
                dpt_estimate = {1: "5.x/17.x/20.x", 2: "9.x/7.x/8.x", 3: "10.x/11.x", 4: "14.x/12.x/13.x"}.get(n, f"?({n}B)")

    ts = datetime.now().strftime("%Y-%m-%d %H:%M:%S.%f")[:-3]

    entry = {
        "type": "telegram",
        "ts": ts,
        "src": src,
        "device": device_name,
        "ga": ga,
        "ga_name": ga_name,
        "value": value,
        "raw": raw_value,
        "dpt": dpt,
        "dpt_estimate": dpt_estimate,
        "apci": apci_type,
    }

    bus_logger.info(f"{ts} | {src} | {device_name} | {ga} | {ga_name} | {value}")

    state["current_values"][ga] = {"value": value, "ts": ts}
    state["telegram_buffer"].append(entry)

    await broadcast(entry)


async def knx_connect_loop():
    cfg = load_config()
    ip = cfg.get("gateway_ip", "")
    port = cfg.get("gateway_port", 3671)
    state["gateway_ip"] = ip
    state["gateway_port"] = port
    state["language"] = cfg.get("language", "de-DE")
    state["connection_type"] = cfg.get("connection_type", "local")
    state["remote_gateway_token"] = cfg.get("remote_gateway_token", "")

    if state["connection_type"] == "remote_gateway":
        return  # Proxy verbindet sich von außen — hier nichts zu tun

    if not ip:
        return

    retry_delay = 10
    while True:
        xknx = XKNX(
            connection_config=ConnectionConfig(
                connection_type=ConnectionType.TUNNELING,
                gateway_ip=ip,
                gateway_port=port,
            )
        )
        state["xknx"] = xknx
        if state["ga_dpt_map"]:
            xknx.group_address_dpt.set(state["ga_dpt_map"])
        try:
            async with xknx:
                xknx.telegram_queue.register_telegram_received_cb(telegram_received_cb)
                state["connected"] = True
                retry_delay = 10  # reset on success
                await broadcast({"type": "status", "connected": True, "ip": ip, "port": port})
                await asyncio.Event().wait()  # block until cancelled or exception
        except asyncio.CancelledError:
            break  # task was cancelled (e.g. new gateway config) — stop retrying
        except Exception as e:
            logging.getLogger("knx_bus").warning(
                "KNX connection lost: %s — retry in %ds", e, retry_delay
            )
            await broadcast({"type": "status", "connected": False, "error": str(e)})
            retry_delay = min(retry_delay * 2, 60)  # exponential backoff, max 60s
        finally:
            state["connected"] = False
            state["xknx"] = None

        try:
            await asyncio.sleep(retry_delay)
        except asyncio.CancelledError:
            break


def load_log_into_buffer():
    """Pre-populate telegram_buffer and current_values from the persisted log file."""
    if not LOG_PATH.exists():
        return
    try:
        with open(LOG_PATH, encoding="utf-8") as f:
            lines = f.readlines()
        for line in lines[-500:]:
            parts = line.strip().split(" | ")
            if len(parts) == 6:
                ts, src, device, ga, ga_name, value = parts
                value = _DPT1_LEGACY.get(value, value)
                entry = {
                    "type": "telegram",
                    "ts": ts, "src": src, "device": device,
                    "ga": ga, "ga_name": ga_name, "value": value,
                }
                state["telegram_buffer"].append(entry)
                # last seen value per GA
                state["current_values"][ga] = {"value": value, "ts": ts}
    except Exception as e:
        logging.getLogger("knx_bus").error("Error loading log: %s", e)


async def start_connect_task():
    if state["connect_task"] and not state["connect_task"].done():
        state["connect_task"].cancel()
        try:
            await state["connect_task"]
        except asyncio.CancelledError:
            pass
    state["connect_task"] = asyncio.create_task(knx_connect_loop())


def load_last_project():
    """Load last parsed project from disk into state on startup."""
    if not LAST_PROJECT_PATH.exists():
        return
    try:
        data = json.loads(LAST_PROJECT_PATH.read_text())
        state["project_data"] = data
        state["ga_dpt_map"] = {
            gad["address"]: gad.get("dpt")
            for gad in data.get("group_addresses", {}).values()
            if gad.get("address")
        }
    except Exception as e:
        logging.getLogger("knx_bus").error("Error loading last project: %s", e)


@asynccontextmanager
async def lifespan(app: FastAPI):
    load_log_into_buffer()
    load_last_project()
    await start_connect_task()
    # Start WireGuard monitor if enabled
    cfg = load_config()
    state["wireguard_enabled"] = cfg.get("wireguard_enabled", False)
    state["wireguard_ets_port_active"] = cfg.get("wireguard_ets_port_active", False)
    if state["wireguard_enabled"]:
        state["wireguard_latency_task"] = asyncio.create_task(wireguard_monitor_loop())
    yield
    if state["connect_task"] and not state["connect_task"].done():
        state["connect_task"].cancel()
    if state["xknx"]:
        await state["xknx"].stop()
    if state["wireguard_latency_task"] and not state["wireguard_latency_task"].done():
        state["wireguard_latency_task"].cancel()


app = FastAPI(title="Open-KNXViewer", lifespan=lifespan)


@app.get("/.well-known/appspecific/com.chrome.devtools.json", include_in_schema=False)
async def chrome_devtools():
    return {}


@app.get("/api/mode")
def get_mode():
    return {"public": False}


@app.get("/")
async def root():
    return FileResponse(INDEX_HTML)


@app.get("/api/gateway")
def get_gateway():
    cfg = load_config()
    return {
        "ip": state["gateway_ip"],
        "port": state["gateway_port"],
        "connected": state["connected"],
        "language": state["language"],
        "connection_type": state.get("connection_type", "local"),
        "remote_gateway_token": cfg.get("remote_gateway_token", ""),
        "remote_gateway_connected": state.get("remote_gateway_connected", False),
    }


@app.get("/api/gateway/description")
async def gateway_description():
    """Fetch KNXnet/IP Description from gateway via UDP (no connection required)."""
    ip = state.get("gateway_ip", "")
    port = state.get("gateway_port", 3671)
    if not ip:
        raise HTTPException(status_code=503, detail="Gateway-IP nicht konfiguriert")
    try:
        result = await asyncio.wait_for(_fetch_gateway_description(ip, port), timeout=5.0)
    except asyncio.TimeoutError:
        raise HTTPException(status_code=504, detail="Gateway antwortet nicht (Timeout)") from None
    except Exception as exc:
        raise HTTPException(status_code=500, detail=str(exc)) from exc
    return result


async def _fetch_gateway_description(ip: str, port: int) -> dict:
    """Send KNXnet/IP DESCRIPTION_REQUEST (0x0203) and parse DESCRIPTION_RESPONSE (0x0204)."""
    # KNXnet/IP header: 06 10 0203 000E + HPAI (08 01 00000000 0000)
    request = bytes([0x06, 0x10, 0x02, 0x03, 0x00, 0x0E,
                     0x08, 0x01, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00])
    loop = asyncio.get_event_loop()
    future: asyncio.Future = loop.create_future()

    class _Proto(asyncio.DatagramProtocol):
        def datagram_received(self, data, addr):
            if not future.done():
                future.set_result(data)
        def error_received(self, exc):
            if not future.done():
                future.set_exception(exc)
        def connection_lost(self, exc):
            if not future.done() and exc:
                future.set_exception(exc)

    transport, _ = await loop.create_datagram_endpoint(
        _Proto, remote_addr=(ip, port), family=socket.AF_INET
    )
    try:
        transport.sendto(request)
        data = await future
    finally:
        transport.close()

    return _parse_knxip_description(data)


def _parse_knxip_description(data: bytes) -> dict:
    if len(data) < 6:
        return {"error": "Antwort zu kurz"}
    _, _, service_id, _ = struct.unpack_from("!BBHH", data)
    if service_id != 0x0204:
        return {"error": f"Unerwarteter Service-Typ: {service_id:#06x}"}
    result: dict = {}
    pos = 6
    while pos < len(data):
        if pos + 2 > len(data):
            break
        dib_len = data[pos]
        dib_type = data[pos + 1]
        if dib_len == 0:
            break
        block = data[pos:pos + dib_len]
        if dib_type == 0x01 and dib_len >= 54:  # DIB_DEVICE_INFO
            knx_medium = block[2]
            dev_status = block[3]
            ia_high, ia_low = block[4], block[5]
            area = (ia_high >> 4) & 0xF
            line = ia_high & 0xF
            device_num = ia_low
            serial = block[8:14].hex(":").upper()
            mac = ":".join(f"{b:02X}" for b in block[20:26])
            friendly_name = block[26:56].rstrip(b"\x00").decode("latin-1", errors="replace").strip()
            medium_map = {0x01: "TP", 0x02: "PL110", 0x04: "RF", 0x20: "IP"}
            result["device"] = {
                "friendly_name": friendly_name,
                "individual_address": f"{area}.{line}.{device_num}",
                "knx_medium": medium_map.get(knx_medium, f"0x{knx_medium:02X}"),
                "serial_number": serial,
                "mac_address": mac,
                "programming_mode": bool(dev_status & 0x01),
            }
        elif dib_type == 0x02:  # DIB_SUPP_SVC_FAMILIES
            svc_map = {0x02: "Core", 0x03: "Device Management", 0x04: "Tunnelling",
                       0x05: "Routing", 0x06: "Remote Logging", 0x08: "Remote Configuration",
                       0x0A: "KNXnet/IP Security"}
            services = []
            for i in range(2, dib_len - 1, 2):
                svc_id = block[i]
                svc_ver = block[i + 1]
                services.append({"id": svc_id, "name": svc_map.get(svc_id, f"0x{svc_id:02X}"), "version": svc_ver})
            result["services"] = services
        pos += dib_len
    return result


@app.post("/api/gateway")
async def set_gateway(data: dict):
    cfg = load_config()
    cfg.update({
        "gateway_ip": data.get("ip", cfg["gateway_ip"]),
        "gateway_port": data.get("port", cfg["gateway_port"]),
        "language": data.get("language", cfg["language"]),
        "connection_type": data.get("connection_type", cfg["connection_type"]),
    })
    save_config(cfg)
    state["language"] = cfg["language"]
    await start_connect_task()
    return {"ok": True}


@app.get("/api/current-values")
def get_current_values():
    return state["current_values"]


@app.get("/api/last-project/info")
def get_last_project_info():
    filename = load_config().get("last_project_filename", "")
    if not filename or not LAST_PROJECT_PATH.exists():
        raise HTTPException(status_code=404, detail="No last project")
    return {"filename": filename}


@app.get("/api/last-project/data")
def get_last_project_data():
    if not state["project_data"]:
        raise HTTPException(status_code=404, detail="No project data")
    return JSONResponse(content=state["project_data"])


@app.get("/api/annotations")
def get_annotations():
    if ANNOTATIONS_PATH.exists():
        return json.loads(ANNOTATIONS_PATH.read_text())
    return {"devices": {}, "group_addresses": {}}


@app.post("/api/annotations")
async def save_annotations(data: dict):
    ANNOTATIONS_PATH.write_text(json.dumps(data, indent=2, ensure_ascii=False))
    return {"ok": True}


@app.get("/api/log")
def get_log(lines: int = 500):
    if not LOG_PATH.exists():
        return []
    try:
        with open(LOG_PATH, encoding="utf-8") as f:
            raw = f.readlines()
        entries = []
        for line in raw[-lines:]:
            parts = line.strip().split(" | ")
            if len(parts) == 6:
                ts, src, device, ga, ga_name, value = parts
                entries.append({
                    "type": "telegram",
                    "ts": ts, "src": src, "device": device,
                    "ga": ga, "ga_name": ga_name, "value": value,
                })
        return entries
    except Exception as e:
        raise HTTPException(status_code=500, detail=str(e)) from e


@app.get("/api/log/export.csv")
def export_log_csv():
    """Export complete log (all rotated files) as CSV download."""
    log_files = sorted(LOG_PATH.parent.glob("knx_bus.log*"))
    if not log_files:
        raise HTTPException(status_code=404, detail="No log files found")

    def generate():
        buf = io.StringIO()
        writer = csv.writer(buf)
        writer.writerow(["Zeitstempel", "Quell-PA", "Gerät", "GA", "GA-Name", "Wert"])
        yield buf.getvalue()
        for log_file in log_files:
            try:
                with open(log_file, encoding="utf-8") as f:
                    for line in f:
                        parts = line.strip().split(" | ")
                        if len(parts) == 6:
                            buf = io.StringIO()
                            csv.writer(buf).writerow(parts)
                            yield buf.getvalue()
            except Exception:
                continue

    filename = f"knx_bus_{datetime.now().strftime('%Y%m%d_%H%M%S')}.csv"
    return StreamingResponse(
        generate(),
        media_type="text/csv; charset=utf-8",
        headers={"Content-Disposition": f'attachment; filename="{filename}"'},
    )


@app.websocket("/ws")
async def websocket_endpoint(ws: WebSocket):
    await ws.accept()
    state["ws_clients"].add(ws)
    await ws.send_json({
        "type": "status",
        "connected": state["connected"],
        "ip": state["gateway_ip"],
        "port": state["gateway_port"],
        "language": state["language"],
    })
    await ws.send_json({"type": "snapshot", "values": state["current_values"]})
    await ws.send_json({
        "type": "history",
        "entries": list(reversed(list(state["telegram_buffer"]))),  # newest first
    })
    try:
        while True:
            await ws.receive_text()
    except WebSocketDisconnect:
        state["ws_clients"].discard(ws)


# ── Remote Gateway ────────────────────────────────────────────────────────────

def _make_telegram_from_proxy(msg: dict) -> Telegram:
    apci_map = {
        "GroupValueWrite": GroupValueWrite,
        "GroupValueRead": GroupValueRead,
        "GroupValueResponse": GroupValueResponse,
    }
    ApciClass = apci_map[msg["apci"]]
    p_type = msg.get("payload_type", "none")
    p_val = msg.get("payload_value")
    if ApciClass is GroupValueRead:
        payload = GroupValueRead()
    elif p_type == "binary":
        payload = ApciClass(DPTBinary(p_val))
    else:
        payload = ApciClass(DPTArray(tuple(p_val)))
    return Telegram(
        source_address=IndividualAddress(msg["src"]),
        destination_address=GroupAddress(msg["ga"]),
        payload=payload,
    )


@app.websocket("/ws/remote-gateway")
async def remote_gateway_endpoint(ws: WebSocket, token: str = Query(...)):
    cfg = load_config()
    if not cfg.get("remote_gateway_token") or token != cfg["remote_gateway_token"]:
        await ws.close(code=4001)
        return
    if state.get("connection_type") != "remote_gateway":
        await ws.close(code=4002)
        return
    await ws.accept()
    state["remote_gateway_ws"] = ws
    try:
        while True:
            msg = json.loads(await ws.receive_text())
            if msg["type"] == "status":
                state["remote_gateway_connected"] = msg.get("connected", False)
                state["connected"] = state["remote_gateway_connected"]
                await broadcast({
                    "type": "status",
                    "connected": state["connected"],
                    "ip": "remote",
                    "port": 0,
                    "language": state["language"],
                })
            elif msg["type"] == "telegram":
                telegram = _make_telegram_from_proxy(msg)
                asyncio.create_task(_process_telegram(telegram))
    except WebSocketDisconnect:
        pass
    finally:
        state["remote_gateway_ws"] = None
        state["remote_gateway_connected"] = False
        state["connected"] = False
        await broadcast({"type": "status", "connected": False})


# ── GA Write / Read ───────────────────────────────────────────────────────────

@app.post("/api/ga/write")
async def ga_write(data: dict):
    ga_str = data.get("ga", "")
    value_str = str(data.get("value", ""))
    if not state["connected"]:
        raise HTTPException(status_code=503, detail="Kein KNX-Gateway verbunden")
    if state.get("wireguard_enabled") and "ga_rw" not in state["wireguard_allowed_actions"]:
        raise HTTPException(status_code=503, detail=f"Latenz zu hoch ({state['wireguard_latency_ms']} ms) — GA-Schreiben nicht erlaubt")
    dpt_info = state["ga_dpt_map"].get(ga_str)
    if not dpt_info:
        raise HTTPException(status_code=422, detail="DPT für diese GA nicht bekannt")
    try:
        transcoder = DPTBase.parse_transcoder(dpt_info)
        if transcoder is None:
            raise ValueError(f"Unbekannter DPT: {dpt_info}")
        main = dpt_info.get("main")
        if main == 1:
            bool_val = value_str.strip().lower() in ("1", "true", "ein", "an", "on", "yes")
            typed_value = bool_val
            display_value = "Ein" if bool_val else "Aus"
        else:
            typed_value = float(value_str)
            unit = getattr(transcoder, "unit", "") or ""
            display_value = f"{typed_value:.2f}{' ' + unit if unit else ''}"
        payload = GroupValueWrite(transcoder.to_knx(typed_value))
    except Exception as exc:
        raise HTTPException(status_code=422, detail=f"Wert konnte nicht kodiert werden: {exc}") from exc

    telegram = Telegram(destination_address=GroupAddress(ga_str), payload=payload)
    if state.get("connection_type") == "remote_gateway":
        gw_ws = state.get("remote_gateway_ws")
        if gw_ws is None:
            raise HTTPException(status_code=503, detail="Remote-Gateway nicht verbunden")
        raw_payload = payload.value
        if isinstance(raw_payload, DPTBinary):
            p_type, p_val = "binary", raw_payload.value
        else:
            p_type, p_val = "array", list(raw_payload.value)
        await gw_ws.send_json({"type": "write", "ga": ga_str,
                               "payload_type": p_type, "payload_value": p_val})
    else:
        await state["xknx"].telegrams.put(telegram)

    # Update local state so current_values and WebSocket clients reflect the sent value
    ts = datetime.now().strftime("%Y-%m-%d %H:%M:%S.%f")[:-3]
    ga_name = ""
    if state["project_data"]:
        for gad in state["project_data"].get("group_addresses", {}).values():
            if gad.get("address") == ga_str:
                ga_name = gad.get("name", "")
                break
    dpt_main = dpt_info.get("main")
    dpt_sub = dpt_info.get("sub")
    dpt = f"{dpt_main}.{str(dpt_sub).zfill(3)}" if dpt_main is not None and dpt_sub is not None else str(dpt_main or "")
    entry = {
        "type": "telegram",
        "ts": ts,
        "src": "0.0.0",
        "device": "Open-KNXViewer",
        "ga": ga_str,
        "ga_name": ga_name,
        "value": display_value,
        "raw": "",
        "dpt": dpt,
    }
    state["current_values"][ga_str] = {"value": display_value, "ts": ts}
    state["telegram_buffer"].append(entry)
    await broadcast(entry)
    return {"ok": True}


@app.post("/api/ga/read")
async def ga_read(data: dict):
    ga_str = data.get("ga", "")
    if not state["connected"]:
        raise HTTPException(status_code=503, detail="Kein KNX-Gateway verbunden")
    if state.get("wireguard_enabled") and "ga_rw" not in state["wireguard_allowed_actions"]:
        raise HTTPException(status_code=503, detail=f"Latenz zu hoch ({state['wireguard_latency_ms']} ms) — GA-Lesen nicht erlaubt")
    if state.get("connection_type") == "remote_gateway":
        gw_ws = state.get("remote_gateway_ws")
        if gw_ws is None:
            raise HTTPException(status_code=503, detail="Remote-Gateway nicht verbunden")
        await gw_ws.send_json({"type": "read", "ga": ga_str})
    else:
        telegram = Telegram(destination_address=GroupAddress(ga_str), payload=GroupValueRead())
        await state["xknx"].telegrams.put(telegram)
    return {"ok": True}


@app.post("/api/ga/read-all")
async def ga_read_all():
    if not state["connected"]:
        raise HTTPException(status_code=503, detail="Kein KNX-Gateway verbunden")
    if state.get("wireguard_enabled") and "ga_rw" not in state["wireguard_allowed_actions"]:
        raise HTTPException(status_code=503, detail=f"Latenz zu hoch ({state['wireguard_latency_ms']} ms) — GA-Lesen nicht erlaubt")
    gas = list(state["ga_dpt_map"].keys())

    async def _send_all():
        if state.get("connection_type") == "remote_gateway":
            gw_ws = state.get("remote_gateway_ws")
            if gw_ws is None:
                return
            for ga_str in gas:
                await gw_ws.send_json({"type": "read", "ga": ga_str})
                await asyncio.sleep(0.05)
        else:
            for ga_str in gas:
                tg = Telegram(destination_address=GroupAddress(ga_str), payload=GroupValueRead())
                await state["xknx"].telegrams.put(tg)
                await asyncio.sleep(0.05)  # 50 ms between requests to avoid flooding the bus

    asyncio.create_task(_send_all())
    return {"ok": True, "count": len(gas)}


# ── Bus Scan ───────────────────────────────────────────────────────────────────

@app.post("/api/ga/scan")
async def ga_scan(data: dict):
    """Scan a range of group addresses by sending GroupValueRead to each."""
    if not state["connected"]:
        raise HTTPException(status_code=503, detail="Kein KNX-Gateway verbunden")
    if state.get("ga_scan_running"):
        raise HTTPException(status_code=409, detail="GA-Scan läuft bereits")

    start = data.get("start", "0/0/1")
    end = data.get("end", "5/7/255")
    delay_ms = max(50, int(data.get("delay_ms", 100)))

    def _parse_ga(s: str):
        parts = s.split("/")
        return int(parts[0]), int(parts[1]), int(parts[2])

    try:
        sm, sk, ss = _parse_ga(start)
        em, ek, es = _parse_ga(end)
    except Exception:
        raise HTTPException(status_code=422, detail="Ungültiges GA-Format (erwartet: main/middle/sub)") from None

    gas = []
    for m in range(sm, em + 1):
        for k in range(0, 8):
            if m == sm and k < sk:
                continue
            if m == em and k > ek:
                break
            for s in range(0, 256):
                if m == sm and k == sk and s < ss:
                    continue
                if m == em and k == ek and s > es:
                    break
                gas.append(f"{m}/{k}/{s}")

    if len(gas) > 32768:
        raise HTTPException(status_code=422, detail=f"Bereich zu groß ({len(gas)} GAs, max 32768)")

    state["ga_scan_running"] = True
    state["ga_scan_cancel"] = False

    async def _run():
        try:
            for i, ga_str in enumerate(gas):
                if state.get("ga_scan_cancel"):
                    break
                if not state["connected"]:
                    break
                tg = Telegram(destination_address=GroupAddress(ga_str), payload=GroupValueRead())
                await state["xknx"].telegrams.put(tg)
                if i % 20 == 0:
                    await broadcast({"type": "scan_ga_progress", "done": i, "total": len(gas)})
                await asyncio.sleep(delay_ms / 1000)
        finally:
            state["ga_scan_running"] = False
            await broadcast({"type": "scan_ga_complete", "total": len(gas),
                             "cancelled": state.get("ga_scan_cancel", False)})
            state["ga_scan_cancel"] = False

    asyncio.create_task(_run())
    return {"ok": True, "count": len(gas)}


@app.post("/api/ga/scan/cancel")
async def ga_scan_cancel():
    state["ga_scan_cancel"] = True
    return {"ok": True}


@app.post("/api/bus/scan")
async def bus_scan(data: dict):
    """Scan physical addresses on the bus using xknx management P2P connections."""
    if not state["connected"]:
        raise HTTPException(status_code=503, detail="Kein KNX-Gateway verbunden")
    if state.get("connection_type") == "remote_gateway":
        raise HTTPException(status_code=503, detail="PA-Scan nur mit lokaler Gateway-Verbindung")
    if state.get("pa_scan_running"):
        raise HTTPException(status_code=409, detail="PA-Scan läuft bereits")

    area = data.get("area")     # None = alle Bereiche 1-15
    line = data.get("line")     # None = alle Linien 1-15
    device = data.get("device") # None = alle Geräte 1-255
    timeout_ms = max(500, min(5000, int(data.get("timeout_ms", 1500))))

    areas = [area] if area is not None else list(range(1, 16))
    addresses = []
    for a in areas:
        lines = [line] if line is not None else list(range(1, 16))
        for li in lines:
            devices = [device] if device is not None else list(range(1, 256))
            for d in devices:
                addresses.append(f"{a}.{li}.{d}")

    state["pa_scan_running"] = True
    state["pa_scan_cancel"] = False

    async def _check(addr: str) -> bool:
        from xknx.management.procedures import nm_individual_address_check
        try:
            return await asyncio.wait_for(
                nm_individual_address_check(state["xknx"], IndividualAddress(addr)),
                timeout=timeout_ms / 1000
            )
        except (asyncio.TimeoutError, Exception):
            return False

    async def _run():
        found = []
        try:
            for i, addr in enumerate(addresses):
                if state.get("pa_scan_cancel") or not state["connected"]:
                    break
                exists = await _check(addr)
                if exists:
                    found.append(addr)
                    await broadcast({"type": "scan_pa_found", "address": addr})
                if i % 5 == 0:
                    await broadcast({"type": "scan_pa_progress", "done": i, "total": len(addresses)})
        finally:
            state["pa_scan_running"] = False
            await broadcast({"type": "scan_pa_complete", "found": found,
                             "total": len(addresses),
                             "cancelled": state.get("pa_scan_cancel", False)})
            state["pa_scan_cancel"] = False

    asyncio.create_task(_run())
    return {"ok": True, "count": len(addresses)}


@app.post("/api/bus/scan/cancel")
async def bus_scan_cancel():
    state["pa_scan_cancel"] = True
    return {"ok": True}


@app.get("/api/bus/programming-mode")
async def bus_programming_mode(timeout: float = 3.0):
    """Detect all devices currently in programming mode via IndividualAddressRead broadcast."""
    if not state["connected"]:
        raise HTTPException(status_code=503, detail="Kein KNX-Gateway verbunden")
    if state.get("connection_type") == "remote_gateway":
        raise HTTPException(status_code=503, detail="Nur mit lokaler Gateway-Verbindung")
    from xknx.management.procedures import nm_individual_address_read
    try:
        addresses = await asyncio.wait_for(
            nm_individual_address_read(state["xknx"], timeout=timeout),
            timeout=timeout + 1.0,
        )
    except Exception as exc:
        raise HTTPException(status_code=500, detail=str(exc)) from exc
    return {"addresses": [str(a) for a in addresses]}


@app.get("/api/device/{addr}/properties")
async def device_properties(addr: str):
    """Read device properties via xknx management P2P connection."""
    if not state["connected"]:
        raise HTTPException(status_code=503, detail="Kein KNX-Gateway verbunden")
    if state.get("connection_type") == "remote_gateway":
        raise HTTPException(status_code=503, detail="Device-Properties nur mit lokaler Gateway-Verbindung")

    from xknx.telegram import apci as xknx_apci

    # KNX standard Object 0 (Device Object) property IDs
    PROPERTIES = {
        11: "PID_OBJECT_TYPE",
        13: "PID_OBJECT_NAME",
        12: "PID_MANUFACTURER_ID",
        14: "PID_LOAD_STATE",
        56: "PID_SERIAL_NUMBER",
        57: "PID_FIRMWARE_REVISION",
        78: "PID_ORDER_INFO",
    }

    try:
        ia = IndividualAddress(addr)
    except Exception:
        raise HTTPException(status_code=422, detail=f"Ungültige physische Adresse: {addr}") from None

    try:
        async with state["xknx"].management.connection(ia) as conn:
            # Read device descriptor (type info)
            try:
                desc_resp = await asyncio.wait_for(
                    conn.request(
                        payload=xknx_apci.DeviceDescriptorRead(descriptor=0),
                        expected=xknx_apci.DeviceDescriptorResponse,
                    ),
                    timeout=4.0,
                )
                descriptor = desc_resp.payload.value if hasattr(desc_resp.payload, "value") else None
            except Exception:
                descriptor = None

            # Read properties
            props = {}
            for pid, name in PROPERTIES.items():
                try:
                    resp = await asyncio.wait_for(
                        conn.request(
                            payload=xknx_apci.PropertyValueRead(
                                object_index=0, property_id=pid, count=1, start_index=1
                            ),
                            expected=xknx_apci.PropertyValueResponse,
                        ),
                        timeout=3.0,
                    )
                    raw = getattr(resp.payload, "data", b"")
                    props[name] = raw.hex().upper() if raw else None
                except Exception:
                    props[name] = None
    except Exception as exc:
        raise HTTPException(status_code=503, detail=f"Verbindung zu {addr} fehlgeschlagen: {exc}") from exc

    # Decode manufacturer ID (2 bytes big-endian, KNXA manufacturer list)
    mfr_raw = props.get("PID_MANUFACTURER_ID")
    mfr_id = int(mfr_raw, 16) if mfr_raw and len(mfr_raw) == 4 else None

    return {
        "address": addr,
        "descriptor": f"0x{descriptor:04X}" if descriptor is not None else None,
        "manufacturer_id": mfr_id,
        "properties": props,
    }


# ── WireGuard API ─────────────────────────────────────────────────────────────

@app.get("/api/wireguard/status")
async def wg_status():
    cfg = load_config()
    wg_st = {}
    if state.get("wireguard_enabled"):
        try:
            wg_st = await wg_get_status(cfg.get("wireguard_interface", "wg0"))
        except Exception:
            pass
    return {
        "enabled": state.get("wireguard_enabled", False),
        "latency_ms": state.get("wireguard_latency_ms"),
        "peer_connected": state.get("wireguard_peer_connected", False),
        "allowed_actions": state.get("wireguard_allowed_actions", ["monitor"]),
        "ets_port_active": state.get("wireguard_ets_port_active", False),
        **wg_st,
    }


@app.get("/api/wireguard/config")
def wg_config():
    cfg = load_config()
    return {k: v for k, v in cfg.items() if k.startswith("wireguard_") and "private" not in k.lower()}


@app.post("/api/wireguard/setup")
async def wg_setup_endpoint(data: dict):
    cfg = load_config()
    # Update WG config fields from request
    for field in ("server_ip", "peer_ip", "listen_port", "ets_port", "knx_ip", "knx_port"):
        key = f"wireguard_{field}"
        if field in data:
            cfg[key] = data[field]
    cfg["wireguard_enabled"] = True
    save_config(cfg)
    state["wireguard_enabled"] = True

    try:
        server_pubkey = await wg_setup(cfg)
    except RuntimeError as exc:
        raise HTTPException(status_code=500, detail=f"WireGuard-Setup fehlgeschlagen: {exc}") from exc

    # Persist server public key for peer-config download
    cfg["wireguard_server_public_key"] = server_pubkey
    save_config(cfg)

    # Start latency monitor if not running
    if not state.get("wireguard_latency_task") or state["wireguard_latency_task"].done():
        state["wireguard_latency_task"] = asyncio.create_task(wireguard_monitor_loop())

    return {"ok": True, "server_public_key": server_pubkey}


@app.post("/api/wireguard/peer")
async def wg_peer_endpoint(data: dict):
    public_key = data.get("public_key", "").strip()
    if not public_key:
        raise HTTPException(status_code=422, detail="public_key fehlt")
    cfg = load_config()
    cfg["wireguard_peer_public_key"] = public_key
    save_config(cfg)
    try:
        await wg_add_peer(public_key, cfg)
    except RuntimeError as exc:
        raise HTTPException(status_code=500, detail=f"Peer konnte nicht hinzugefügt werden: {exc}") from exc
    return {"ok": True}


@app.get("/api/wireguard/peer-config")
def wg_peer_config():
    cfg = load_config()
    # Read server public key (derived from private key file at runtime)
    # We store it when setup was called; fall back to placeholder if not available
    server_pubkey = cfg.get("wireguard_server_public_key", "<SERVER_PUBLIC_KEY>")
    server_public_ip = cfg.get("wireguard_server_public_ip", "<SERVER_PUBLIC_IP>")
    iface = cfg.get("wireguard_interface", "wg0")
    listen_port = cfg.get("wireguard_listen_port", 51820)
    peer_ip = cfg.get("wireguard_peer_ip", "10.100.0.2")

    config_text = (
        f"[Interface]\n"
        f"PrivateKey = <HIER_EIGENEN_KEY_EINTRAGEN>\n"
        f"Address = {peer_ip}/24\n"
        f"\n"
        f"[Peer]\n"
        f"PublicKey = {server_pubkey}\n"
        f"Endpoint = {server_public_ip}:{listen_port}\n"
        f"AllowedIPs = 0.0.0.0/0\n"
        f"PersistentKeepalive = 25\n"
    )
    from fastapi.responses import PlainTextResponse
    return PlainTextResponse(
        content=config_text,
        headers={"Content-Disposition": f'attachment; filename="{iface}_client.conf"'},
    )


@app.post("/api/wireguard/ets-access")
async def wg_ets_access(data: dict):
    enable = bool(data.get("enable", False))
    cfg = load_config()
    if not state.get("wireguard_enabled"):
        raise HTTPException(status_code=409, detail="WireGuard-Tunnel nicht aktiv")
    try:
        await wg_set_ets_forward(enable, cfg)
    except RuntimeError as exc:
        raise HTTPException(status_code=500, detail=f"iptables-Fehler: {exc}") from exc
    state["wireguard_ets_port_active"] = enable
    cfg["wireguard_ets_port_active"] = enable
    save_config(cfg)
    return {"ok": True, "ets_port_active": enable}


@app.post("/api/wireguard/latency-test")
async def wg_latency_test():
    cfg = load_config()
    if not state.get("wireguard_enabled"):
        raise HTTPException(status_code=409, detail="WireGuard-Tunnel nicht aktiv")
    peer_ip = cfg.get("wireguard_peer_ip", "10.100.0.2")
    latency = await _measure_latency(peer_ip)
    state["wireguard_latency_ms"] = latency
    state["wireguard_allowed_actions"] = _compute_allowed_actions(latency)
    await broadcast({
        "type": "wireguard_status",
        "latency_ms": latency,
        "peer_connected": state["wireguard_peer_connected"],
        "allowed_actions": state["wireguard_allowed_actions"],
    })
    return {"latency_ms": latency, "allowed_actions": state["wireguard_allowed_actions"]}


@app.delete("/api/wireguard/setup")
async def wg_teardown():
    cfg = load_config()
    iface = cfg.get("wireguard_interface", "wg0")
    # Stop latency monitor
    if state.get("wireguard_latency_task") and not state["wireguard_latency_task"].done():
        state["wireguard_latency_task"].cancel()
        state["wireguard_latency_task"] = None
    # Remove ETS port forward if active
    if state.get("wireguard_ets_port_active"):
        try:
            await wg_set_ets_forward(False, cfg)
        except Exception:
            pass
    # Bring down interface
    try:
        await _wg_run("down", iface)
    except RuntimeError:
        pass
    # Update state + config
    state["wireguard_enabled"] = False
    state["wireguard_peer_connected"] = False
    state["wireguard_latency_ms"] = None
    state["wireguard_allowed_actions"] = ["monitor"]
    state["wireguard_ets_port_active"] = False
    cfg["wireguard_enabled"] = False
    cfg["wireguard_ets_port_active"] = False
    save_config(cfg)
    return {"ok": True}


# ── LLM config & analysis ─────────────────────────────────────────────────────

LLM_DEFAULT_MODEL = "z-ai/glm-5"
OPENROUTER_URL = "https://openrouter.ai/api/v1/chat/completions"


def _build_project_summary(project_data: dict) -> str:
    """Build a compact text summary of a KNX project for LLM context."""
    lines = []
    info = project_data.get("info", {})
    lines.append(f"KNX-Projekt: {info.get('name', 'Unbekannt')}")
    lines.append(f"ETS-Version: {info.get('tool_version', '-')}")

    lines.append("\n## Topologie")
    for area_id, area in project_data.get("topology", {}).items():
        lines.append(f"  Bereich {area_id}: {area.get('name', '')}")
        for line_id, line in area.get("lines", {}).items():
            devs = line.get("devices", [])
            lines.append(f"    Linie {area_id}.{line_id}: {line.get('name', '')} ({len(devs)} Geräte)")

    lines.append("\n## Geräte")
    for addr, dev in project_data.get("devices", {}).items():
        lines.append(f"  {addr}: {dev.get('name', '')} — {dev.get('manufacturer_name', '')} {dev.get('order_number', '')}")

    lines.append("\n## Gruppenadressen")
    for _, ga in project_data.get("group_addresses", {}).items():
        dpt = ga.get("dpt")
        dpt_str = f" [DPT {dpt['main']}.{str(dpt.get('sub') or 0).zfill(3)}]" if dpt and dpt.get("main") else ""
        lines.append(f"  {ga.get('address', '')}: {ga.get('name', '')}{dpt_str}")

    funcs = project_data.get("functions", {})
    if funcs:
        lines.append("\n## Funktionen")
        for _, func in funcs.items():
            gas = [v.get("address", "") for v in (func.get("group_addresses") or {}).values()]
            lines.append(f"  {func.get('name', '')}: {', '.join(gas)}")

    return "\n".join(lines)


@app.get("/api/llm/config")
def get_llm_config():
    cfg = load_config()
    key = cfg.get("openrouter_api_key", "")
    return {
        "configured": bool(key),
        "model": cfg.get("llm_model", LLM_DEFAULT_MODEL),
    }


@app.post("/api/llm/config")
async def set_llm_config(data: dict):
    cfg = load_config()
    if "api_key" in data:
        cfg["openrouter_api_key"] = data["api_key"]
    if "model" in data:
        cfg["llm_model"] = data["model"] or LLM_DEFAULT_MODEL
    save_config(cfg)
    return {"ok": True}


@app.post("/api/llm/analyze")
async def llm_analyze(data: dict):
    cfg = load_config()
    api_key = cfg.get("openrouter_api_key", "")
    model = cfg.get("llm_model", LLM_DEFAULT_MODEL)
    question = data.get("question", "").strip() or "Erkläre das Projekt, seine Topologie und die wichtigsten Gruppenadressen."

    if not api_key:
        raise HTTPException(status_code=400, detail="OpenRouter API-Key nicht konfiguriert")
    if not state["project_data"]:
        raise HTTPException(status_code=400, detail="Kein Projekt geladen")

    summary = _build_project_summary(state["project_data"])
    messages = [
        {
            "role": "system",
            "content": (
                "Du bist ein KNX-Experte. KNX ist ein offener Standard für Gebäudeautomation. "
                "Analysiere das folgende KNX-Projekt und beantworte Fragen dazu. "
                "Antworte auf Deutsch, präzise und strukturiert."
            ),
        },
        {
            "role": "user",
            "content": f"Projektdaten:\n\n{summary}\n\nFrage: {question}",
        },
    ]

    async def stream_llm():
        async with httpx.AsyncClient(timeout=60) as client:
            async with client.stream(
                "POST",
                OPENROUTER_URL,
                headers={
                    "Authorization": f"Bearer {api_key}",
                    "Content-Type": "application/json",
                },
                json={"model": model, "messages": messages, "stream": True},
            ) as resp:
                if resp.status_code != 200:
                    body = await resp.aread()
                    yield f"data: {json.dumps({'error': body.decode()})}\n\n"
                    return
                async for line in resp.aiter_lines():
                    if line.startswith("data: "):
                        yield line + "\n\n"

    return StreamingResponse(stream_llm(), media_type="text/event-stream")


def _parse_ets_certificate(raw: str) -> dict:
    """Parse ETS Cloud License certificate format into a dict."""
    import re
    fields = {}
    for m in re.finditer(r'(\w+)=(?:"([^"]*)"|([\w+/=]+))', raw):
        fields[m.group(1)] = m.group(2) if m.group(2) is not None else m.group(3)
    return fields


def _extract_security_data(tmp_path: str, password: str, project: dict) -> dict:
    """Parse KNX Security data (device keys/passwords, GA keys, ETS cert) from raw project XML."""
    import re
    import xml.etree.ElementTree as ET
    import zipfile
    result: dict = {"devices": [], "ga_keys": {}, "ets_certificates": []}
    try:
        with knxproj_extract(tmp_path, password or None) as content:
            f = content.open_project_0()
            xml_str = f.read().decode("utf-8")

        ns_match = re.search(r'xmlns="([^"]+)"', xml_str)
        ns = ns_match.group(1) if ns_match else "http://knx.org/xml/project/21"
        root = ET.fromstring(xml_str)

        # Build raw_address → formatted address map from parsed project
        raw_to_addr: dict[int, str] = {
            ga["raw_address"]: ga["address"]
            for ga in project.get("group_addresses", {}).values()
        }

        # ── Device security — walk topology to reconstruct individual addresses ──
        for area in root.iter(f"{{{ns}}}Area"):
            area_addr = area.get("Address", "0")
            for line in area.iter(f"{{{ns}}}Line"):
                line_addr = line.get("Address", "0")
                for dev in line.iter(f"{{{ns}}}DeviceInstance"):
                    sec = dev.find(f"{{{ns}}}Security")
                    if sec is None:
                        continue
                    dev_addr = dev.get("Address", "0")
                    ia = f"{area_addr}.{line_addr}.{dev_addr}"
                    dev_info = project.get("devices", {}).get(ia, {})
                    ip_cfg = dev.find(f"{{{ns}}}IPConfig")
                    bus_ifaces = []
                    for bi in dev.iter(f"{{{ns}}}BusInterface"):
                        pwd = bi.get("Password")
                        if pwd:
                            bus_ifaces.append({"ref_id": bi.get("RefId", ""), "password": pwd})
                    tool_key = sec.get("ToolKey")
                    device_auth_code = sec.get("DeviceAuthenticationCode")
                    device_mgmt_password = sec.get("DeviceManagementPassword")
                    sequence_number = sec.get("SequenceNumber")
                    # Skip devices with only a default SequenceNumber="0" and no actual keys/passwords
                    # (ETS writes <Security SequenceNumber="0"/> to all devices even in non-secure projects)
                    has_keys = tool_key or device_auth_code or device_mgmt_password or bus_ifaces
                    has_nonzero_seq = sequence_number not in (None, "0")
                    if not has_keys and not has_nonzero_seq:
                        continue
                    result["devices"].append({
                        "address": ia,
                        "name": dev_info.get("name") or dev.get("Name") or "",
                        "ip_address": ip_cfg.get("IPAddress") if ip_cfg is not None else None,
                        "mac_address": ip_cfg.get("MACAddress") if ip_cfg is not None else None,
                        "tool_key": tool_key,
                        "device_auth_code": device_auth_code,
                        "device_mgmt_password": device_mgmt_password,
                        "sequence_number": sequence_number,
                        "bus_interfaces": bus_ifaces or None,
                    })

        # ── GA keys ──────────────────────────────────────────────────────────
        for ga_el in root.iter(f"{{{ns}}}GroupAddress"):
            key = ga_el.get("Key")
            if not key:
                continue
            raw = ga_el.get("Address")
            try:
                raw_int = int(raw) if raw is not None else None
            except ValueError:
                raw_int = None
            formatted = raw_to_addr.get(raw_int, raw or "")
            result["ga_keys"][formatted] = key

        # ── ETS certificates ─────────────────────────────────────────────────
        with zipfile.ZipFile(tmp_path) as zf:
            for name in zf.namelist():
                if name.endswith(".certificate"):
                    raw = zf.read(name).decode("utf-8", errors="replace")
                    cert = _parse_ets_certificate(raw)
                    if cert:
                        result["ets_certificates"].append(cert)

    except Exception as exc:
        logging.getLogger("knx_bus").warning("Security data extraction failed: %s", exc)
    return result


@app.post("/api/parse")
async def parse_project(
    file: UploadFile = File(...),
    password: str = Form(default=""),
    language: str = Form(default=""),
):
    suffix = Path(file.filename or "project.knxproj").suffix or ".knxproj"
    with tempfile.NamedTemporaryFile(delete=False, suffix=suffix) as tmp:
        tmp.write(await file.read())
        tmp_path = tmp.name

    try:
        kwargs: dict = {"path": tmp_path}
        if password:
            kwargs["password"] = password
        if language:
            kwargs["language"] = language

        project = XKNXProj(**kwargs).parse()
        project["_security"] = _extract_security_data(tmp_path, password, project)

        state["project_data"] = project
        state["ga_dpt_map"] = {
            gad["address"]: gad.get("dpt")
            for gad in project.get("group_addresses", {}).values()
            if gad.get("address")
        }
        # Register DPT map with the live xknx instance so future telegrams are decoded
        if state["xknx"]:
            state["xknx"].group_address_dpt.set(state["ga_dpt_map"])

        # Persist parsed project and filename for next startup
        LAST_PROJECT_PATH.write_text(json.dumps(project))
        cfg = load_config()
        cfg["last_project_filename"] = file.filename or "project.knxproj"
        save_config(cfg)

        return JSONResponse(content=project)
    except InvalidPasswordException as exc:
        raise HTTPException(status_code=422, detail=f"Invalid password: {exc}") from exc
    except XknxProjectException as exc:
        raise HTTPException(status_code=500, detail=str(exc)) from exc
    except Exception as exc:
        raise HTTPException(status_code=500, detail=f"Parsing failed: {exc}") from exc
    finally:
        os.unlink(tmp_path)
