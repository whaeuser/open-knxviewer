"""Open-KNXViewer private server (port 8002).

Full feature set: KNX live connection, WebSocket streaming, bus monitor,
annotations, scans, snapshots, WireGuard and KI-Analyse.

Route groups live in routers/; shared state and config in core.py;
helpers shared with the public server in common.py.
"""
import asyncio
import csv
import io
import json
import logging
import os
import socket
import struct
import tempfile
from contextlib import asynccontextmanager
from datetime import datetime
from pathlib import Path

from fastapi import (
    FastAPI,
    File,
    Form,
    HTTPException,
    Query,
    Request,
    UploadFile,
    WebSocket,
    WebSocketDisconnect,
)
from fastapi.responses import FileResponse, JSONResponse, Response, StreamingResponse
from fastapi.staticfiles import StaticFiles
from starlette.middleware.base import BaseHTTPMiddleware

from xknx import XKNX
from xknx.dpt import DPTArray, DPTBase, DPTBinary
from xknx.io import ConnectionConfig, ConnectionType
from xknx.telegram import Telegram
from xknx.telegram.address import GroupAddress, IndividualAddress
from xknx.telegram.apci import GroupValueRead, GroupValueResponse, GroupValueWrite
from xknxproject import XKNXProj
from xknxproject.exceptions import InvalidPasswordException, XknxProjectException

import common
import core
from core import broadcast, bus_logger, load_config, state
from core import save_config  # noqa: F401  (re-exported for tests/backwards compat)
from models import GatewayUpdate
from routers import ga_ops, llm, recent_projects, scan, snapshots, wireguard

# Re-exported for tests and backwards compatibility
from routers.wireguard import compute_allowed_actions as _compute_allowed_actions  # noqa: F401


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


# ── Telegram processing ───────────────────────────────────────────────────────


def telegram_received_cb(telegram):
    core.spawn(_process_telegram(telegram))


async def _process_telegram(telegram):
    src = str(telegram.source_address)
    ga = str(telegram.destination_address)

    device_name = ""
    if state["project_data"]:
        dev = state["project_data"].get("devices", {}).get(src, {})
        device_name = dev.get("name", "")

    ga_name = core.ga_name(ga)

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
        bool_val = (
            decoded
            if isinstance(decoded, bool)
            else (
                decoded.value
                if isinstance(getattr(decoded, "value", None), bool)
                else None
            )
        )
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
                dpt_estimate = {
                    1: "5.x/17.x/20.x",
                    2: "9.x/7.x/8.x",
                    3: "10.x/11.x",
                    4: "14.x/12.x/13.x",
                }.get(n, f"?({n}B)")

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


# ── KNX connection ────────────────────────────────────────────────────────────


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
                await broadcast(
                    {"type": "status", "connected": True, "ip": ip, "port": port}
                )
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
    if not core.LOG_PATH.exists():
        return
    try:
        with open(core.LOG_PATH, encoding="utf-8") as f:
            lines = f.readlines()
        for line in lines[-500:]:
            parts = line.strip().split(" | ")
            if len(parts) == 6:
                ts, src, device, ga, ga_name, value = parts
                value = _DPT1_LEGACY.get(value, value)
                entry = {
                    "type": "telegram",
                    "ts": ts,
                    "src": src,
                    "device": device,
                    "ga": ga,
                    "ga_name": ga_name,
                    "value": value,
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
    state["connect_task"] = core.spawn(knx_connect_loop())


def load_last_project():
    """Load last parsed project from disk into state on startup."""
    if not core.LAST_PROJECT_PATH.exists():
        return
    try:
        core.set_project_data(json.loads(core.LAST_PROJECT_PATH.read_text()))
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
        state["wireguard_latency_task"] = core.spawn(wireguard.wireguard_monitor_loop())
    yield
    if state["connect_task"] and not state["connect_task"].done():
        state["connect_task"].cancel()
    if state["xknx"]:
        await state["xknx"].stop()
    if state["wireguard_latency_task"] and not state["wireguard_latency_task"].done():
        state["wireguard_latency_task"].cancel()


app = FastAPI(title="Open-KNXViewer", lifespan=lifespan)

app.include_router(ga_ops.router)
app.include_router(llm.router)
app.include_router(recent_projects.router)
app.include_router(scan.router)
app.include_router(snapshots.router)
app.include_router(wireguard.router)


class FrameAncestorsMiddleware(BaseHTTPMiddleware):
    async def dispatch(self, request: Request, call_next):
        response = await call_next(request)
        response.headers["Content-Security-Policy"] = (
            "frame-ancestors https://volt-logik.io https://*.volt-logik.io https://portal.nurdaheim.net https://*.nurdaheim.net;"
        )
        return response


app.add_middleware(FrameAncestorsMiddleware)

if core.STATIC_DIR.is_dir():
    app.mount("/static", StaticFiles(directory=str(core.STATIC_DIR)), name="static")


_FAVICON = bytes.fromhex(
    "89504e470d0a1a0a0000000d49484452000000010000000108060000001f15c489"
    "0000000a49444154789c6360000000020001e221bc330000000049454e44ae426082"
)


@app.get("/favicon.ico", include_in_schema=False)
async def favicon():
    return Response(content=_FAVICON, media_type="image/png")


@app.get("/.well-known/appspecific/com.chrome.devtools.json", include_in_schema=False)
async def chrome_devtools():
    return {}


@app.get("/api/mode")
def get_mode(request: Request):
    host = request.headers.get("x-forwarded-host") or request.headers.get("host", "")
    if "volt-logik" in host:
        theme = "voltlogik"
        branding = "voltlogik"
    else:
        theme = os.environ.get("OPENKNXVIEWER_THEME", "default").strip().lower()
        if theme not in ("default", "voltlogik"):
            theme = "default"
        branding = None
    return {"public": False, "default_theme": theme, "branding": branding}


@app.get("/")
async def root():
    return FileResponse(core.INDEX_HTML)


# ── Gateway ───────────────────────────────────────────────────────────────────


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
        result = await asyncio.wait_for(
            _fetch_gateway_description(ip, port), timeout=5.0
        )
    except asyncio.TimeoutError:
        raise HTTPException(
            status_code=504, detail="Gateway antwortet nicht (Timeout)"
        ) from None
    except Exception as exc:
        raise HTTPException(status_code=500, detail=str(exc)) from exc
    return result


async def _fetch_gateway_description(ip: str, port: int) -> dict:
    """Send KNXnet/IP DESCRIPTION_REQUEST (0x0203) and parse DESCRIPTION_RESPONSE (0x0204)."""
    # KNXnet/IP header: 06 10 0203 000E + HPAI (08 01 00000000 0000)
    request = bytes(
        [
            0x06,
            0x10,
            0x02,
            0x03,
            0x00,
            0x0E,
            0x08,
            0x01,
            0x00,
            0x00,
            0x00,
            0x00,
            0x00,
            0x00,
        ]
    )
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
        block = data[pos : pos + dib_len]
        if dib_type == 0x01 and dib_len >= 54:  # DIB_DEVICE_INFO
            knx_medium = block[2]
            dev_status = block[3]
            ia_high, ia_low = block[4], block[5]
            area = (ia_high >> 4) & 0xF
            line = ia_high & 0xF
            device_num = ia_low
            serial = block[8:14].hex(":").upper()
            mac = ":".join(f"{b:02X}" for b in block[20:26])
            friendly_name = (
                block[26:56].rstrip(b"\x00").decode("latin-1", errors="replace").strip()
            )
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
            svc_map = {
                0x02: "Core",
                0x03: "Device Management",
                0x04: "Tunnelling",
                0x05: "Routing",
                0x06: "Remote Logging",
                0x08: "Remote Configuration",
                0x0A: "KNXnet/IP Security",
            }
            services = []
            for i in range(2, dib_len - 1, 2):
                svc_id = block[i]
                svc_ver = block[i + 1]
                services.append(
                    {
                        "id": svc_id,
                        "name": svc_map.get(svc_id, f"0x{svc_id:02X}"),
                        "version": svc_ver,
                    }
                )
            result["services"] = services
        pos += dib_len
    return result


@app.post("/api/gateway")
async def set_gateway(data: GatewayUpdate):
    key_map = {
        "ip": "gateway_ip",
        "port": "gateway_port",
        "language": "language",
        "connection_type": "connection_type",
    }
    updates = {
        key_map[field]: value
        for field, value in data.model_dump(exclude_unset=True).items()
        if value is not None
    }
    cfg = core.update_config(updates)
    state["language"] = cfg["language"]
    await start_connect_task()
    return {"ok": True}


# ── Project / values ──────────────────────────────────────────────────────────


@app.get("/api/current-values")
def get_current_values():
    return state["current_values"]


@app.get("/api/last-project/info")
def get_last_project_info():
    filename = load_config().get("last_project_filename", "")
    if not filename or not core.LAST_PROJECT_PATH.exists():
        raise HTTPException(status_code=404, detail="No last project")
    return {"filename": filename}


@app.get("/api/last-project/data")
def get_last_project_data():
    if not state["project_data"]:
        raise HTTPException(status_code=404, detail="No project data")
    return JSONResponse(content=state["project_data"])


# ── Annotations ───────────────────────────────────────────────────────────────


@app.get("/api/annotations")
def get_annotations():
    if core.ANNOTATIONS_PATH.exists():
        return json.loads(core.ANNOTATIONS_PATH.read_text())
    return {"devices": {}, "group_addresses": {}}


@app.post("/api/annotations")
async def save_annotations(data: dict):
    core.ANNOTATIONS_PATH.write_text(json.dumps(data, indent=2, ensure_ascii=False))
    return {"ok": True}


# ── Log ───────────────────────────────────────────────────────────────────────


@app.get("/api/log")
def get_log(lines: int = 500):
    if not core.LOG_PATH.exists():
        return []
    try:
        with open(core.LOG_PATH, encoding="utf-8") as f:
            raw = f.readlines()
        entries = []
        for line in raw[-lines:]:
            parts = line.strip().split(" | ")
            if len(parts) == 6:
                ts, src, device, ga, ga_name, value = parts
                entries.append(
                    {
                        "type": "telegram",
                        "ts": ts,
                        "src": src,
                        "device": device,
                        "ga": ga,
                        "ga_name": ga_name,
                        "value": value,
                    }
                )
        return entries
    except Exception as e:
        raise HTTPException(status_code=500, detail=str(e)) from e


@app.get("/api/log/export.csv")
def export_log_csv():
    """Export complete log (all rotated files) as CSV download."""
    log_files = sorted(core.LOG_PATH.parent.glob("knx_bus.log*"))
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


# ── XLSX export ───────────────────────────────────────────────────────────────


@app.get("/api/export/xlsx")
def export_xlsx():
    """Export the whole project as a multi-sheet XLSX workbook."""
    project = state.get("project_data")
    if not project:
        raise HTTPException(status_code=400, detail="Kein Projekt geladen")
    xlsx_bytes = common.build_project_xlsx(project)
    return StreamingResponse(
        io.BytesIO(xlsx_bytes),
        media_type="application/vnd.openxmlformats-officedocument.spreadsheetml.sheet",
        headers={"Content-Disposition": f'attachment; filename="{common.xlsx_filename(project)}"'},
    )


# ── WebSocket ─────────────────────────────────────────────────────────────────


@app.websocket("/ws")
async def websocket_endpoint(ws: WebSocket):
    await ws.accept()
    state["ws_clients"].add(ws)
    await ws.send_json(
        {
            "type": "status",
            "connected": state["connected"],
            "ip": state["gateway_ip"],
            "port": state["gateway_port"],
            "language": state["language"],
        }
    )
    await ws.send_json({"type": "snapshot", "values": state["current_values"]})
    await ws.send_json(
        {
            "type": "history",
            "entries": list(reversed(list(state["telegram_buffer"]))),  # newest first
        }
    )
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
                await broadcast(
                    {
                        "type": "status",
                        "connected": state["connected"],
                        "ip": "remote",
                        "port": 0,
                        "language": state["language"],
                    }
                )
            elif msg["type"] == "telegram":
                telegram = _make_telegram_from_proxy(msg)
                core.spawn(_process_telegram(telegram))
    except WebSocketDisconnect:
        pass
    finally:
        state["remote_gateway_ws"] = None
        state["remote_gateway_connected"] = False
        state["connected"] = False
        await broadcast({"type": "status", "connected": False})


# ── Parse .knxproj ────────────────────────────────────────────────────────────


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

        # Parsing is CPU-bound and can take seconds for large projects —
        # run it off the event loop so WebSocket/telegram handling keeps going.
        project = await asyncio.to_thread(lambda: XKNXProj(**kwargs).parse())
        project["_security"] = await asyncio.to_thread(
            common.extract_security_data, tmp_path, password, project
        )

        core.set_project_data(project)

        # Persist parsed project and filename for next startup
        core.LAST_PROJECT_PATH.write_text(json.dumps(project))
        core.update_config({"last_project_filename": file.filename or "project.knxproj"})
        core.add_to_recent_projects(
            file.filename or "project.knxproj", project, source_path=tmp_path
        )

        return JSONResponse(content=project)
    except InvalidPasswordException as exc:
        raise HTTPException(status_code=422, detail=f"Invalid password: {exc}") from exc
    except XknxProjectException as exc:
        raise HTTPException(status_code=500, detail=str(exc)) from exc
    except Exception as exc:
        raise HTTPException(status_code=500, detail=f"Parsing failed: {exc}") from exc
    finally:
        os.unlink(tmp_path)
