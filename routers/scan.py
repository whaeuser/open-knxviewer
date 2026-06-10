"""Bus discovery: GA range scan, physical-address scan, programming-mode detection,
device property reads via P2P management connections."""
import asyncio

from fastapi import APIRouter, HTTPException

from xknx.telegram import Telegram
from xknx.telegram.address import GroupAddress, IndividualAddress
from xknx.telegram.apci import GroupValueRead

import core
from core import broadcast, state
from models import BusScanRequest, GAScanRequest

router = APIRouter(tags=["scan"])


def _require_local_connection(detail: str):
    if not state["connected"]:
        raise HTTPException(status_code=503, detail="Kein KNX-Gateway verbunden")
    if state.get("connection_type") == "remote_gateway":
        raise HTTPException(status_code=503, detail=detail)


@router.post("/api/ga/scan")
async def ga_scan(data: GAScanRequest):
    """Scan a range of group addresses by sending GroupValueRead to each."""
    if not state["connected"]:
        raise HTTPException(status_code=503, detail="Kein KNX-Gateway verbunden")
    if state.get("ga_scan_running"):
        raise HTTPException(status_code=409, detail="GA-Scan läuft bereits")

    delay_ms = max(50, data.delay_ms)

    def _parse_ga(s: str):
        parts = s.split("/")
        return int(parts[0]), int(parts[1]), int(parts[2])

    try:
        sm, sk, ss = _parse_ga(data.start)
        em, ek, es = _parse_ga(data.end)
    except Exception:
        raise HTTPException(
            status_code=422, detail="Ungültiges GA-Format (erwartet: main/middle/sub)"
        ) from None

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
        raise HTTPException(
            status_code=422, detail=f"Bereich zu groß ({len(gas)} GAs, max 32768)"
        )

    state["ga_scan_running"] = True
    state["ga_scan_cancel"] = False

    async def _run():
        try:
            for i, ga_str in enumerate(gas):
                if state.get("ga_scan_cancel"):
                    break
                if not state["connected"]:
                    break
                tg = Telegram(
                    destination_address=GroupAddress(ga_str), payload=GroupValueRead()
                )
                await state["xknx"].telegrams.put(tg)
                if i % 20 == 0:
                    await broadcast(
                        {"type": "scan_ga_progress", "done": i, "total": len(gas)}
                    )
                await asyncio.sleep(delay_ms / 1000)
        finally:
            state["ga_scan_running"] = False
            await broadcast(
                {
                    "type": "scan_ga_complete",
                    "total": len(gas),
                    "cancelled": state.get("ga_scan_cancel", False),
                }
            )
            state["ga_scan_cancel"] = False

    core.spawn(_run())
    return {"ok": True, "count": len(gas)}


@router.post("/api/ga/scan/cancel")
async def ga_scan_cancel():
    state["ga_scan_cancel"] = True
    return {"ok": True}


@router.post("/api/bus/scan")
async def bus_scan(data: BusScanRequest):
    """Scan physical addresses on the bus using xknx management P2P connections."""
    _require_local_connection("PA-Scan nur mit lokaler Gateway-Verbindung")
    if state.get("pa_scan_running"):
        raise HTTPException(status_code=409, detail="PA-Scan läuft bereits")

    timeout_ms = max(500, min(5000, data.timeout_ms))

    areas = [data.area] if data.area is not None else list(range(1, 16))
    addresses = []
    for a in areas:
        lines = [data.line] if data.line is not None else list(range(1, 16))
        for li in lines:
            devices = [data.device] if data.device is not None else list(range(1, 256))
            for d in devices:
                addresses.append(f"{a}.{li}.{d}")

    state["pa_scan_running"] = True
    state["pa_scan_cancel"] = False

    async def _check(addr: str) -> bool:
        from xknx.management.procedures import nm_individual_address_check

        try:
            return await asyncio.wait_for(
                nm_individual_address_check(state["xknx"], IndividualAddress(addr)),
                timeout=timeout_ms / 1000,
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
                    await broadcast(
                        {"type": "scan_pa_progress", "done": i, "total": len(addresses)}
                    )
        finally:
            state["pa_scan_running"] = False
            await broadcast(
                {
                    "type": "scan_pa_complete",
                    "found": found,
                    "total": len(addresses),
                    "cancelled": state.get("pa_scan_cancel", False),
                }
            )
            state["pa_scan_cancel"] = False

    core.spawn(_run())
    return {"ok": True, "count": len(addresses)}


@router.post("/api/bus/scan/cancel")
async def bus_scan_cancel():
    state["pa_scan_cancel"] = True
    return {"ok": True}


@router.get("/api/bus/programming-mode")
async def bus_programming_mode(timeout: float = 3.0):
    """Detect all devices currently in programming mode via IndividualAddressRead broadcast."""
    _require_local_connection("Nur mit lokaler Gateway-Verbindung")
    from xknx.management.procedures import nm_individual_address_read

    try:
        addresses = await asyncio.wait_for(
            nm_individual_address_read(state["xknx"], timeout=timeout),
            timeout=timeout + 1.0,
        )
    except Exception as exc:
        raise HTTPException(status_code=500, detail=str(exc)) from exc
    return {"addresses": [str(a) for a in addresses]}


@router.get("/api/device/{addr}/properties")
async def device_properties(addr: str):
    """Read device properties via xknx management P2P connection."""
    _require_local_connection("Device-Properties nur mit lokaler Gateway-Verbindung")

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
        raise HTTPException(
            status_code=422, detail=f"Ungültige physische Adresse: {addr}"
        ) from None

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
                descriptor = (
                    desc_resp.payload.value
                    if hasattr(desc_resp.payload, "value")
                    else None
                )
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
        raise HTTPException(
            status_code=503, detail=f"Verbindung zu {addr} fehlgeschlagen: {exc}"
        ) from exc

    # Decode manufacturer ID (2 bytes big-endian, KNXA manufacturer list)
    mfr_raw = props.get("PID_MANUFACTURER_ID")
    mfr_id = int(mfr_raw, 16) if mfr_raw and len(mfr_raw) == 4 else None

    return {
        "address": addr,
        "descriptor": f"0x{descriptor:04X}" if descriptor is not None else None,
        "manufacturer_id": mfr_id,
        "properties": props,
    }
