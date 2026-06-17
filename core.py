"""Shared state, configuration and helpers for the private server.

All file paths live here as module constants so tests can redirect them
with monkeypatch.setattr(core, "CONFIG_PATH", ...). Functions read the
constants at call time (module-global lookup), never at import time.
"""
import asyncio
import json
import logging
import re
import shutil
import threading
import uuid
from collections import deque
from datetime import datetime
from logging.handlers import TimedRotatingFileHandler
from pathlib import Path

INDEX_HTML = Path(__file__).parent / "index.html"
STATIC_DIR = Path(__file__).parent / "static"
CONFIG_PATH = Path(__file__).parent / "config.json"
ANNOTATIONS_PATH = Path(__file__).parent / "annotations.json"
LOG_PATH = Path(__file__).parent / "logs" / "knx_bus.log"
LAST_PROJECT_PATH = Path(__file__).parent / "last_project.json"
RECENT_PROJECTS_PATH = Path(__file__).parent / "recent_projects.json"
PROJECTS_DIR = Path(__file__).parent / "projects"
MAX_RECENT_PROJECTS = 10

WG_HELPER = "/usr/local/bin/openknxviewer-wg-helper"


def initial_state() -> dict:
    """Fresh copy of the global state — also used by tests to reset between runs."""
    return {
        "xknx": None,
        "connected": False,
        "gateway_ip": "",
        "gateway_port": 3671,
        "language": "de-DE",
        "project_data": None,
        "ga_dpt_map": {},
        "ga_name_map": {},
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


state: dict = initial_state()


# ── Config ────────────────────────────────────────────────────────────────────

# Sync endpoints run in a threadpool, so read-modify-write cycles on
# config.json need a real lock to avoid lost updates.
_config_lock = threading.RLock()

CONFIG_DEFAULTS = {
    "gateway_ip": "",
    "gateway_port": 3671,
    "language": "de-DE",
    "connection_type": "local",
    "remote_gateway_token": "",
    # Lokales LLM (LM Studio / mlx-omni-server / o.ä., OpenAI-kompatibel)
    "local_llm_url": "http://localhost:1234/v1",
    "local_llm_token": "",
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


def load_config() -> dict:
    with _config_lock:
        if CONFIG_PATH.exists():
            cfg = {**CONFIG_DEFAULTS, **json.loads(CONFIG_PATH.read_text())}
        else:
            cfg = dict(CONFIG_DEFAULTS)
        if not cfg["remote_gateway_token"]:
            cfg["remote_gateway_token"] = str(uuid.uuid4())
            save_config(cfg)
        return cfg


def save_config(cfg: dict):
    with _config_lock:
        CONFIG_PATH.write_text(json.dumps(cfg, indent=2))


def update_config(updates: dict) -> dict:
    """Atomically merge updates into config.json and return the new config."""
    with _config_lock:
        cfg = load_config()
        cfg.update(updates)
        save_config(cfg)
        return cfg


# ── Recent projects ───────────────────────────────────────────────────────────


def project_slug(filename: str) -> str:
    return re.sub(r"[^\w.-]", "_", filename)


def load_recent_projects() -> list:
    if not RECENT_PROJECTS_PATH.exists():
        return []
    try:
        return json.loads(RECENT_PROJECTS_PATH.read_text())
    except Exception:
        return []


def add_to_recent_projects(filename: str, project: dict, source_path: str | None = None):
    PROJECTS_DIR.mkdir(exist_ok=True)
    slug = project_slug(filename)
    (PROJECTS_DIR / f"{slug}.json").write_text(json.dumps(project))
    knxproj_stored = False
    if source_path:
        try:
            shutil.copy(source_path, PROJECTS_DIR / f"{slug}.knxproj")
            knxproj_stored = True
        except Exception:
            pass
    meta = {
        "filename": filename,
        "project_name": project.get("info", {}).get("name", ""),
        "last_used": datetime.now().isoformat(timespec="seconds"),
        "device_count": len(project.get("devices", {})),
        "ga_count": len(project.get("group_addresses", {})),
        "slug": slug,
        "knxproj_stored": knxproj_stored,
    }
    recent = [r for r in load_recent_projects() if r["filename"] != filename]
    recent = [meta] + recent[: MAX_RECENT_PROJECTS - 1]
    RECENT_PROJECTS_PATH.write_text(json.dumps(recent, indent=2))


# ── Project state ─────────────────────────────────────────────────────────────


def set_project_data(project: dict) -> None:
    """Set the active project and rebuild the GA lookup maps.

    Registers the DPT map with the live xknx instance so incoming telegrams
    are decoded automatically.
    """
    state["project_data"] = project
    gas = project.get("group_addresses", {}).values()
    state["ga_dpt_map"] = {
        gad["address"]: gad.get("dpt") for gad in gas if gad.get("address")
    }
    state["ga_name_map"] = {
        gad["address"]: gad.get("name", "") for gad in gas if gad.get("address")
    }
    if state["xknx"]:
        state["xknx"].group_address_dpt.set(state["ga_dpt_map"])


def ga_name(ga: str) -> str:
    return state["ga_name_map"].get(ga, "")


# ── Bus log ───────────────────────────────────────────────────────────────────


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


# ── WebSocket broadcast / background tasks ────────────────────────────────────


async def broadcast(msg: dict):
    dead = set()
    # Copy: clients may connect/disconnect while we await sends.
    for ws in list(state["ws_clients"]):
        try:
            await ws.send_json(msg)
        except Exception:
            dead.add(ws)
    state["ws_clients"] -= dead


# Keep references so tasks are not garbage-collected mid-flight.
_background_tasks: set[asyncio.Task] = set()


def spawn(coro) -> asyncio.Task:
    """create_task with a held reference (asyncio only keeps weak refs)."""
    task = asyncio.create_task(coro)
    _background_tasks.add(task)
    task.add_done_callback(_background_tasks.discard)
    return task
