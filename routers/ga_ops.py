"""Group-address write/read operations on the live KNX connection."""
import asyncio
from datetime import datetime

from fastapi import APIRouter, HTTPException

from xknx.dpt import DPTBase, DPTBinary
from xknx.telegram import Telegram
from xknx.telegram.address import GroupAddress
from xknx.telegram.apci import GroupValueRead, GroupValueWrite

import core
from core import broadcast, state
from models import GARead, GAWrite
from routers.wireguard import require_ga_rw

router = APIRouter(prefix="/api/ga", tags=["ga"])


def _require_connection():
    if not state["connected"]:
        raise HTTPException(status_code=503, detail="Kein KNX-Gateway verbunden")
    require_ga_rw()


@router.post("/write")
async def ga_write(data: GAWrite):
    ga_str = data.ga
    value_str = str(data.value)
    _require_connection()
    dpt_info = state["ga_dpt_map"].get(ga_str)
    if not dpt_info:
        raise HTTPException(status_code=422, detail="DPT für diese GA nicht bekannt")
    try:
        transcoder = DPTBase.parse_transcoder(dpt_info)
        if transcoder is None:
            raise ValueError(f"Unbekannter DPT: {dpt_info}")
        main = dpt_info.get("main")
        if main == 1:
            bool_val = value_str.strip().lower() in (
                "1",
                "true",
                "ein",
                "an",
                "on",
                "yes",
            )
            typed_value = bool_val
            display_value = "Ein" if bool_val else "Aus"
        else:
            typed_value = float(value_str)
            unit = getattr(transcoder, "unit", "") or ""
            display_value = f"{typed_value:.2f}{' ' + unit if unit else ''}"
        payload = GroupValueWrite(transcoder.to_knx(typed_value))
    except Exception as exc:
        raise HTTPException(
            status_code=422, detail=f"Wert konnte nicht kodiert werden: {exc}"
        ) from exc

    telegram = Telegram(destination_address=GroupAddress(ga_str), payload=payload)
    if state.get("connection_type") == "remote_gateway":
        gw_ws = state.get("remote_gateway_ws")
        if gw_ws is None:
            raise HTTPException(
                status_code=503, detail="Remote-Gateway nicht verbunden"
            )
        raw_payload = payload.value
        if isinstance(raw_payload, DPTBinary):
            p_type, p_val = "binary", raw_payload.value
        else:
            p_type, p_val = "array", list(raw_payload.value)
        await gw_ws.send_json(
            {
                "type": "write",
                "ga": ga_str,
                "payload_type": p_type,
                "payload_value": p_val,
            }
        )
    else:
        await state["xknx"].telegrams.put(telegram)

    # Update local state so current_values and WebSocket clients reflect the sent value
    ts = datetime.now().strftime("%Y-%m-%d %H:%M:%S.%f")[:-3]
    dpt_main = dpt_info.get("main")
    dpt_sub = dpt_info.get("sub")
    dpt = (
        f"{dpt_main}.{str(dpt_sub).zfill(3)}"
        if dpt_main is not None and dpt_sub is not None
        else str(dpt_main or "")
    )
    entry = {
        "type": "telegram",
        "ts": ts,
        "src": "0.0.0",
        "device": "Open-KNXViewer",
        "ga": ga_str,
        "ga_name": core.ga_name(ga_str),
        "value": display_value,
        "raw": "",
        "dpt": dpt,
    }
    state["current_values"][ga_str] = {"value": display_value, "ts": ts}
    state["telegram_buffer"].append(entry)
    await broadcast(entry)
    return {"ok": True}


@router.post("/read")
async def ga_read(data: GARead):
    ga_str = data.ga
    _require_connection()
    if state.get("connection_type") == "remote_gateway":
        gw_ws = state.get("remote_gateway_ws")
        if gw_ws is None:
            raise HTTPException(
                status_code=503, detail="Remote-Gateway nicht verbunden"
            )
        await gw_ws.send_json({"type": "read", "ga": ga_str})
    else:
        telegram = Telegram(
            destination_address=GroupAddress(ga_str), payload=GroupValueRead()
        )
        await state["xknx"].telegrams.put(telegram)
    return {"ok": True}


@router.post("/read-all")
async def ga_read_all():
    _require_connection()
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
                tg = Telegram(
                    destination_address=GroupAddress(ga_str), payload=GroupValueRead()
                )
                await state["xknx"].telegrams.put(tg)
                await asyncio.sleep(
                    0.05
                )  # 50 ms between requests to avoid flooding the bus

    core.spawn(_send_all())
    return {"ok": True, "count": len(gas)}
