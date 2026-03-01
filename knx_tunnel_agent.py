#!/usr/bin/env python3
"""
KNX Tunnel Agent — Pi-seitig.

Richtet einen WireGuard-Tunnel zum OpenKNXViewer-Server ein und stellt
einen UDP-Echo-Dienst für Latenz-Messungen bereit.

Läuft neben knx_gateway_proxy.py und ergänzt es um:
  - WireGuard-Interface-Setup (wg0)
  - UDP-Echo-Server (Port 51821) für RTT-Messung durch den Server
  - Registrierung des eigenen Public Keys beim Server

Verwendung:
    python3 knx_tunnel_agent.py \\
        --server-url "https://mein-server.de" \\
        --server-token TOKEN \\
        --knx-ip 192.168.1.100 \\
        [--wg-iface wg0] [--echo-port 51821] [--ssl-no-verify]

Optionale Konfigurationsdatei tunnel_config.json (selbes Verzeichnis):
    {
      "server_url": "https://...",
      "server_token": "...",
      "knx_ip": "192.168.1.100",
      "wg_iface": "wg0",
      "echo_port": 51821,
      "ssl_no_verify": false
    }
"""

import argparse
import asyncio
import json
import logging
import os
import ssl
import subprocess
import sys
from pathlib import Path

try:
    import requests
except ImportError:
    sys.exit("Fehler: 'requests' nicht installiert. Bitte: pip3 install requests")

logging.basicConfig(
    level=logging.INFO,
    format="%(asctime)s [%(levelname)s] %(message)s",
    datefmt="%Y-%m-%d %H:%M:%S",
)
log = logging.getLogger("knx_tunnel")


# ── WireGuard-Setup ────────────────────────────────────────────────────────────

def _run(cmd: list[str], check: bool = True) -> str:
    """Shell-Befehl ausführen, stdout zurückgeben."""
    result = subprocess.run(cmd, capture_output=True, text=True)
    if check and result.returncode != 0:
        raise RuntimeError(result.stderr.strip() or f"Befehl fehlgeschlagen: {' '.join(cmd)}")
    return result.stdout.strip()


def setup_wireguard(cfg: dict) -> str:
    """
    WireGuard-Interface auf dem Pi einrichten.

    Schritte:
    1. Private/Public Key erzeugen (falls noch nicht vorhanden)
    2. IP-Forwarding aktivieren
    3. wg0.conf schreiben (ohne [Peer] — wird nach Server-Antwort ergänzt)
    4. Interface hochfahren

    Gibt den eigenen Public Key zurück.
    """
    iface = cfg.get("wg_iface", "wg0")
    privkey_file = f"/etc/wireguard/{iface}_private.key"

    # Verzeichnis anlegen
    os.makedirs("/etc/wireguard", exist_ok=True)

    # Keys generieren falls noch nicht vorhanden
    if not Path(privkey_file).exists():
        log.info("Generiere WireGuard-Keys …")
        privkey = _run(["wg", "genkey"])
        Path(privkey_file).write_text(privkey)
        os.chmod(privkey_file, 0o600)
    else:
        privkey = Path(privkey_file).read_text().strip()

    pubkey = _run(["bash", "-c", f"echo '{privkey}' | wg pubkey"])

    # IP-Forwarding aktivieren
    _run(["sysctl", "-w", "net.ipv4.ip_forward=1"])

    # wg0.conf schreiben (ohne Peer-Sektion — wird nach Registrierung ergänzt)
    peer_ip = cfg.get("peer_ip", "10.100.0.2")
    conf = (
        f"[Interface]\n"
        f"PrivateKey = {privkey}\n"
        f"Address = {peer_ip}/24\n"
    )
    conf_file = f"/etc/wireguard/{iface}.conf"
    Path(conf_file).write_text(conf)
    os.chmod(conf_file, 0o600)

    # Interface hochfahren (ggf. erst herunterfahren)
    _run(["wg-quick", "down", iface], check=False)
    _run(["wg-quick", "up", iface])
    log.info("WireGuard-Interface %s gestartet (%s/24)", iface, peer_ip)

    return pubkey


def add_peer_to_config(cfg: dict, server_pubkey: str, server_endpoint: str) -> None:
    """
    Peer-Sektion in wg0.conf ergänzen und Peer live hinzufügen.
    """
    iface = cfg.get("wg_iface", "wg0")
    conf_file = f"/etc/wireguard/{iface}.conf"
    current = Path(conf_file).read_text()

    # Peer-Sektion anhängen (falls noch nicht vorhanden)
    if "[Peer]" not in current:
        peer_section = (
            f"\n[Peer]\n"
            f"PublicKey = {server_pubkey}\n"
            f"Endpoint = {server_endpoint}\n"
            f"AllowedIPs = 0.0.0.0/0\n"
            f"PersistentKeepalive = 25\n"
        )
        Path(conf_file).write_text(current + peer_section)

    # Peer live hinzufügen
    server_wg_ip = cfg.get("server_wg_ip", "10.100.0.1")
    _run(["wg", "set", iface, "peer", server_pubkey,
          "allowed-ips", f"{server_wg_ip}/32",
          "persistent-keepalive", "25",
          "endpoint", server_endpoint], check=False)
    log.info("Peer %s (%s) hinzugefügt", server_pubkey[:16] + "…", server_endpoint)


# ── Server-Registrierung ───────────────────────────────────────────────────────

def register_with_server(cfg: dict, public_key: str) -> dict:
    """
    POST /api/wireguard/peer mit eigenem Public Key.
    Gibt die Server-Antwort zurück (enthält server_public_key).
    """
    base_url = cfg["server_url"].rstrip("/")
    token = cfg["server_token"]
    ssl_no_verify = cfg.get("ssl_no_verify", False)

    url = f"{base_url}/api/wireguard/peer"
    headers = {"Authorization": f"Bearer {token}", "Content-Type": "application/json"}
    payload = {"public_key": public_key}

    log.info("Registriere bei Server: %s", url)
    try:
        resp = requests.post(
            url, json=payload, headers=headers,
            verify=not ssl_no_verify, timeout=30,
        )
        resp.raise_for_status()
        return resp.json()
    except requests.RequestException as exc:
        raise RuntimeError(f"Registrierung fehlgeschlagen: {exc}") from exc


def get_server_pubkey(cfg: dict) -> str:
    """
    GET /api/wireguard/config — Server-PublicKey abrufen.
    """
    base_url = cfg["server_url"].rstrip("/")
    token = cfg["server_token"]
    ssl_no_verify = cfg.get("ssl_no_verify", False)

    url = f"{base_url}/api/wireguard/config"
    headers = {"Authorization": f"Bearer {token}"}
    try:
        resp = requests.get(url, headers=headers, verify=not ssl_no_verify, timeout=10)
        resp.raise_for_status()
        return resp.json().get("wireguard_server_public_key", "")
    except Exception as exc:
        log.warning("Server-PublicKey konnte nicht abgerufen werden: %s", exc)
        return ""


# ── UDP-Echo-Server ────────────────────────────────────────────────────────────

class _UDPEchoProtocol(asyncio.DatagramProtocol):
    """Jedes empfangene UDP-Datagramm sofort zurücksenden."""

    def connection_made(self, transport):
        self.transport = transport

    def datagram_received(self, data: bytes, addr: tuple):
        self.transport.sendto(data, addr)

    def error_received(self, exc: Exception):
        log.warning("UDP-Echo-Fehler: %s", exc)


async def udp_echo_server(port: int = 51821) -> None:
    """UDP-Echo-Server starten und bis zur Programmbeendigung laufen lassen."""
    loop = asyncio.get_running_loop()
    transport, _ = await loop.create_datagram_endpoint(
        _UDPEchoProtocol,
        local_addr=("0.0.0.0", port),
    )
    log.info("UDP-Echo-Server läuft auf Port %d", port)
    try:
        await asyncio.Event().wait()
    finally:
        transport.close()


# ── Hauptfunktion ──────────────────────────────────────────────────────────────

async def main(cfg: dict) -> None:
    # 1. WireGuard einrichten
    log.info("Richte WireGuard-Interface ein …")
    try:
        public_key = setup_wireguard(cfg)
        log.info("Eigener Public Key: %s", public_key)
    except RuntimeError as exc:
        log.error("WireGuard-Setup fehlgeschlagen: %s", exc)
        sys.exit(1)

    # 2. Beim Server registrieren
    try:
        result = register_with_server(cfg, public_key)
        log.info("Registrierung erfolgreich: %s", result)
    except RuntimeError as exc:
        log.error("%s", exc)
        sys.exit(1)

    # 3. Server-PublicKey + Endpoint laden und Peer hinzufügen
    server_pubkey = get_server_pubkey(cfg)
    if server_pubkey:
        # Endpoint = öffentliche IP des Servers + WireGuard-Port
        server_listen_port = cfg.get("server_wg_port", 51820)
        server_public_ip = cfg["server_url"].split("://")[-1].split("/")[0].split(":")[0]
        server_endpoint = f"{server_public_ip}:{server_listen_port}"
        add_peer_to_config(cfg, server_pubkey, server_endpoint)
    else:
        log.warning("Server-PublicKey nicht verfügbar — Peer muss manuell konfiguriert werden")

    # 4. UDP-Echo-Server starten
    await udp_echo_server(cfg.get("echo_port", 51821))


def _load_tunnel_config() -> dict:
    config_path = Path(__file__).parent / "tunnel_config.json"
    if config_path.exists():
        try:
            return json.loads(config_path.read_text())
        except Exception as exc:
            log.warning("tunnel_config.json konnte nicht geladen werden: %s", exc)
    return {}


def _parse_args() -> argparse.Namespace:
    parser = argparse.ArgumentParser(
        description="KNX Tunnel Agent für OpenKNXViewer (Pi-seitig)",
        formatter_class=argparse.RawDescriptionHelpFormatter,
        epilog=__doc__,
    )
    parser.add_argument("--server-url", help="HTTP(S)-URL des OpenKNXViewer-Servers")
    parser.add_argument("--server-token", help="Authentifizierungs-Token (aus Gateway-Modal)")
    parser.add_argument("--knx-ip", help="IP des lokalen KNX/IP-Gateways")
    parser.add_argument("--wg-iface", default="wg0", help="WireGuard-Interface-Name (Standard: wg0)")
    parser.add_argument("--peer-ip", default="10.100.0.2", help="Pi-IP im WG-Tunnel (Standard: 10.100.0.2)")
    parser.add_argument("--server-wg-ip", default="10.100.0.1", help="Server-IP im WG-Tunnel (Standard: 10.100.0.1)")
    parser.add_argument("--server-wg-port", type=int, default=51820, help="WG-Listen-Port des Servers")
    parser.add_argument("--echo-port", type=int, default=51821, help="UDP-Echo-Port (Standard: 51821)")
    parser.add_argument("--ssl-no-verify", action="store_true",
                        help="TLS-Zertifikatsprüfung deaktivieren (nur für Tests)")
    return parser.parse_args()


if __name__ == "__main__":
    args = _parse_args()
    file_cfg = _load_tunnel_config()

    cfg: dict = {**file_cfg}
    if args.server_url:
        cfg["server_url"] = args.server_url
    if args.server_token:
        cfg["server_token"] = args.server_token
    if args.knx_ip:
        cfg["knx_ip"] = args.knx_ip
    cfg["wg_iface"] = args.wg_iface
    cfg["peer_ip"] = args.peer_ip
    cfg["server_wg_ip"] = args.server_wg_ip
    cfg["server_wg_port"] = args.server_wg_port
    cfg["echo_port"] = args.echo_port
    cfg["ssl_no_verify"] = args.ssl_no_verify or cfg.get("ssl_no_verify", False)

    if not cfg.get("server_url"):
        sys.exit("Fehler: --server-url ist erforderlich")
    if not cfg.get("server_token"):
        sys.exit("Fehler: --server-token ist erforderlich")

    log.info("KNX Tunnel Agent startet")
    log.info("  Server:    %s", cfg["server_url"])
    log.info("  KNX:       %s", cfg.get("knx_ip", "(nicht angegeben)"))
    log.info("  WG-Iface:  %s (%s/24)", cfg["wg_iface"], cfg["peer_ip"])
    log.info("  Echo-Port: %d", cfg["echo_port"])

    try:
        asyncio.run(main(cfg))
    except KeyboardInterrupt:
        log.info("Tunnel Agent beendet.")
