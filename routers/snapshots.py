"""Snapshots of current GA values, stored per project, with diff support."""
import json
import re
from datetime import datetime
from pathlib import Path

from fastapi import APIRouter, HTTPException

import core
from core import state
from models import SnapshotCreate

router = APIRouter(prefix="/api/snapshots", tags=["snapshots"])


def _snapshot_dir() -> Path | None:
    """Return the snapshot folder for the currently loaded project, or None."""
    proj = state.get("project_data")
    if not proj:
        return None
    name = (proj.get("info", {}) or {}).get("name") or "default"
    slug = re.sub(r"[^\w.-]+", "_", name)
    d = core.PROJECTS_DIR / f"{slug}.snapshots"
    d.mkdir(parents=True, exist_ok=True)
    return d


def _snapshot_meta(path: Path) -> dict:
    try:
        data = json.loads(path.read_text())
        return {
            "id": path.stem,
            "ts": data.get("ts", ""),
            "name": data.get("name", ""),
            "count": len(data.get("values", {})),
        }
    except Exception:
        return {"id": path.stem, "ts": "", "name": "", "count": 0}


@router.get("")
def list_snapshots():
    d = _snapshot_dir()
    if d is None:
        return {"snapshots": []}
    items = [_snapshot_meta(p) for p in sorted(d.glob("*.json"), reverse=True)]
    return {"snapshots": items}


@router.post("")
def create_snapshot(data: SnapshotCreate):
    d = _snapshot_dir()
    if d is None:
        raise HTTPException(status_code=400, detail="Kein Projekt geladen")
    sid = datetime.now().strftime("%Y-%m-%dT%H-%M-%S")
    payload = {
        "id": sid,
        "ts": datetime.now().strftime("%Y-%m-%d %H:%M:%S"),
        "name": data.name.strip(),
        "values": dict(state.get("current_values", {})),
    }
    (d / f"{sid}.json").write_text(json.dumps(payload, ensure_ascii=False, indent=2))
    return {"ok": True, "snapshot": _snapshot_meta(d / f"{sid}.json")}


def _load_snapshot_values(sid: str) -> dict:
    """Return {address: {value, ts}} for the given snapshot id, or current state for 'current'."""
    if sid == "current":
        return dict(state.get("current_values", {}))
    d = _snapshot_dir()
    if d is None:
        return {}
    safe = re.sub(r"[^\w.-]+", "_", sid)
    p = d / f"{safe}.json"
    if not p.exists():
        raise HTTPException(status_code=404, detail=f"Snapshot {sid} nicht gefunden")
    return json.loads(p.read_text()).get("values", {}) or {}


@router.get("/diff")
def diff_snapshots(a: str, b: str):
    proj = state.get("project_data")
    if not proj:
        raise HTTPException(status_code=400, detail="Kein Projekt geladen")
    va = _load_snapshot_values(a)
    vb = _load_snapshot_values(b)
    gas = proj.get("group_addresses", {}) or {}
    # Index group addresses by their dotted address
    ga_index = {ga.get("address"): ga for ga in gas.values() if ga.get("address")}

    all_addrs = set(va) | set(vb)
    rows = []
    stats = {"equal": 0, "changed": 0, "only_a": 0, "only_b": 0}
    for addr in sorted(all_addrs, key=lambda s: tuple(int(p) if p.isdigit() else 0 for p in s.split("/"))):
        ea = va.get(addr)
        eb = vb.get(addr)
        meta = ga_index.get(addr, {}) or {}
        dpt = meta.get("dpt") or {}
        dpt_str = ""
        if dpt.get("main") is not None:
            sub = dpt.get("sub")
            dpt_str = f"{dpt['main']}.{str(sub).zfill(3)}" if sub is not None else str(dpt["main"])

        if ea is None and eb is not None:
            status = "only_b"
            stats["only_b"] += 1
        elif eb is None and ea is not None:
            status = "only_a"
            stats["only_a"] += 1
        elif (ea or {}).get("value") != (eb or {}).get("value"):
            status = "changed"
            stats["changed"] += 1
        else:
            status = "equal"
            stats["equal"] += 1

        rows.append({
            "address": addr,
            "name": meta.get("name", ""),
            "dpt": dpt_str,
            "value_a": (ea or {}).get("value"),
            "value_b": (eb or {}).get("value"),
            "ts_a": (ea or {}).get("ts"),
            "ts_b": (eb or {}).get("ts"),
            "status": status,
        })

    return {"rows": rows, "stats": stats}


@router.delete("/{sid}")
def delete_snapshot(sid: str):
    d = _snapshot_dir()
    if d is None:
        raise HTTPException(status_code=400, detail="Kein Projekt geladen")
    safe = re.sub(r"[^\w.-]+", "_", sid)
    p = d / f"{safe}.json"
    if not p.exists():
        raise HTTPException(status_code=404, detail="Snapshot nicht gefunden")
    p.unlink()
    return {"ok": True}
