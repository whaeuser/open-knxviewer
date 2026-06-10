"""WireGuard tunnel management: setup, peer handling, latency-based capability gating."""
import asyncio
import logging
import re

from fastapi import APIRouter, HTTPException
from fastapi.responses import PlainTextResponse

import core
from core import broadcast, load_config, state
from models import WGEtsAccess, WGPeer, WGSetup

router = APIRouter(prefix="/api/wireguard", tags=["wireguard"])


async def _wg_run(*args: str) -> str:
    """Run wg_helper via sudo and return stdout, raise RuntimeError on failure."""
    proc = await asyncio.create_subprocess_exec(
        "sudo",
        core.WG_HELPER,
        *args,
        stdout=asyncio.subprocess.PIPE,
        stderr=asyncio.subprocess.PIPE,
    )
    stdout, stderr = await proc.communicate()
    if proc.returncode != 0:
        raise RuntimeError(
            stderr.decode().strip() or f"wg_helper exited {proc.returncode}"
        )
    return stdout.decode().strip()


async def wg_setup(cfg: dict) -> str:
    """Generate keys, write wg0.conf via helper, start tunnel. Returns server public key."""
    iface = cfg.get("wireguard_interface", "wg0")
    privkey_file = f"/etc/wireguard/{iface}_private.key"
    # genkey writes private key to file, prints public key to stdout
    pub_key = await _wg_run("genkey", privkey_file)
    await _wg_run(
        "setup",
        iface,
        cfg["wireguard_server_ip"],
        cfg["wireguard_peer_ip"],
        str(cfg["wireguard_listen_port"]),
        privkey_file,
    )
    return pub_key


async def wg_add_peer(public_key: str, cfg: dict) -> None:
    """Add peer live: wg set <iface> peer <key> allowed-ips <peer_ip>/32."""
    await _wg_run(
        "peer-add", cfg["wireguard_interface"], public_key, cfg["wireguard_peer_ip"]
    )


async def wg_get_status(iface: str = "wg0") -> dict:
    """`wg show <iface> dump` → parsed dict."""
    try:
        output = await _wg_run("status", iface)
    except RuntimeError:
        return {"peer_connected": False}
    lines = output.splitlines()
    result = {
        "peer_connected": False,
        "latest_handshake_s": 0,
        "rx_bytes": 0,
        "tx_bytes": 0,
    }
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
            "ping",
            "-c",
            "3",
            "-W",
            "1",
            peer_ip,
            stdout=asyncio.subprocess.PIPE,
            stderr=asyncio.subprocess.DEVNULL,
        )
        stdout, _ = await asyncio.wait_for(proc.communicate(), timeout=10)
        output = stdout.decode()
        # Parse "rtt min/avg/max/mdev = X.XXX/X.XXX/X.XXX/X.XXX ms"
        m = re.search(r"min/avg/max/\w+ = [\d.]+/([\d.]+)/", output)
        if m:
            return float(m.group(1))
    except Exception:
        pass
    return None


def compute_allowed_actions(latency_ms: float | None) -> list[str]:
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
            state["wireguard_allowed_actions"] = compute_allowed_actions(latency)
            wg_st = await wg_get_status(cfg.get("wireguard_interface", "wg0"))
            state["wireguard_peer_connected"] = wg_st.get("peer_connected", False)
            await broadcast(
                {
                    "type": "wireguard_status",
                    "latency_ms": latency,
                    "peer_connected": state["wireguard_peer_connected"],
                    "allowed_actions": state["wireguard_allowed_actions"],
                }
            )
        except Exception as exc:
            logging.getLogger("knx_bus").warning("WireGuard monitor error: %s", exc)
        await asyncio.sleep(30)


def require_ga_rw():
    """Raise 503 when WireGuard latency gating forbids GA read/write."""
    if (
        state.get("wireguard_enabled")
        and "ga_rw" not in state["wireguard_allowed_actions"]
    ):
        raise HTTPException(
            status_code=503,
            detail=f"Latenz zu hoch ({state['wireguard_latency_ms']} ms) — GA-Schreiben/Lesen nicht erlaubt",
        )


# ── Endpoints ─────────────────────────────────────────────────────────────────


@router.get("/status")
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


@router.get("/config")
def wg_config():
    cfg = load_config()
    return {
        k: v
        for k, v in cfg.items()
        if k.startswith("wireguard_") and "private" not in k.lower()
    }


@router.post("/setup")
async def wg_setup_endpoint(data: WGSetup):
    updates = {
        f"wireguard_{field}": value
        for field, value in data.model_dump(exclude_unset=True).items()
        if value is not None
    }
    updates["wireguard_enabled"] = True
    cfg = core.update_config(updates)
    state["wireguard_enabled"] = True

    try:
        server_pubkey = await wg_setup(cfg)
    except RuntimeError as exc:
        raise HTTPException(
            status_code=500, detail=f"WireGuard-Setup fehlgeschlagen: {exc}"
        ) from exc

    # Persist server public key for peer-config download
    core.update_config({"wireguard_server_public_key": server_pubkey})

    # Start latency monitor if not running
    if (
        not state.get("wireguard_latency_task")
        or state["wireguard_latency_task"].done()
    ):
        state["wireguard_latency_task"] = core.spawn(wireguard_monitor_loop())

    return {"ok": True, "server_public_key": server_pubkey}


@router.post("/peer")
async def wg_peer_endpoint(data: WGPeer):
    public_key = data.public_key.strip()
    if not public_key:
        raise HTTPException(status_code=422, detail="public_key fehlt")
    cfg = core.update_config({"wireguard_peer_public_key": public_key})
    try:
        await wg_add_peer(public_key, cfg)
    except RuntimeError as exc:
        raise HTTPException(
            status_code=500, detail=f"Peer konnte nicht hinzugefügt werden: {exc}"
        ) from exc
    return {"ok": True}


@router.get("/peer-config")
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
    return PlainTextResponse(
        content=config_text,
        headers={"Content-Disposition": f'attachment; filename="{iface}_client.conf"'},
    )


@router.post("/ets-access")
async def wg_ets_access(data: WGEtsAccess):
    enable = data.enable
    cfg = load_config()
    if not state.get("wireguard_enabled"):
        raise HTTPException(status_code=409, detail="WireGuard-Tunnel nicht aktiv")
    try:
        await wg_set_ets_forward(enable, cfg)
    except RuntimeError as exc:
        raise HTTPException(status_code=500, detail=f"iptables-Fehler: {exc}") from exc
    state["wireguard_ets_port_active"] = enable
    core.update_config({"wireguard_ets_port_active": enable})
    return {"ok": True, "ets_port_active": enable}


@router.post("/latency-test")
async def wg_latency_test():
    cfg = load_config()
    if not state.get("wireguard_enabled"):
        raise HTTPException(status_code=409, detail="WireGuard-Tunnel nicht aktiv")
    peer_ip = cfg.get("wireguard_peer_ip", "10.100.0.2")
    latency = await _measure_latency(peer_ip)
    state["wireguard_latency_ms"] = latency
    state["wireguard_allowed_actions"] = compute_allowed_actions(latency)
    await broadcast(
        {
            "type": "wireguard_status",
            "latency_ms": latency,
            "peer_connected": state["wireguard_peer_connected"],
            "allowed_actions": state["wireguard_allowed_actions"],
        }
    )
    return {
        "latency_ms": latency,
        "allowed_actions": state["wireguard_allowed_actions"],
    }


@router.delete("/setup")
async def wg_teardown():
    cfg = load_config()
    iface = cfg.get("wireguard_interface", "wg0")
    # Stop latency monitor
    if (
        state.get("wireguard_latency_task")
        and not state["wireguard_latency_task"].done()
    ):
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
    core.update_config({"wireguard_enabled": False, "wireguard_ets_port_active": False})
    return {"ok": True}
