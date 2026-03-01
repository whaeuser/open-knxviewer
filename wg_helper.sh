#!/bin/bash
# OpenKNXViewer WireGuard Helper
# Installieren nach: /usr/local/bin/openknxviewer-wg-helper
# Ausführbar machen: chmod 755 /usr/local/bin/openknxviewer-wg-helper
# Sudoers-Eintrag:   openknxviewer ALL=(ALL) NOPASSWD: /usr/local/bin/openknxviewer-wg-helper
#
# Dieses Skript kapselt alle Root-Operationen für WireGuard, damit
# server.py ohne Root-Rechte laufen kann.

set -euo pipefail

CMD="${1:-}"

usage() {
    cat <<EOF
Verwendung: $0 <Befehl> [Argumente]

Befehle:
  genkey  <keyfile>                          Privaten Key erzeugen, Public Key ausgeben
  setup   <iface> <server-ip> <peer-ip>      WireGuard-Interface einrichten und starten
          <listen-port> <privkey-file>
  peer-add <iface> <pubkey> <peer-ip>        Peer live hinzufügen
  up      <iface>                            Interface hochfahren
  down    <iface>                            Interface herunterfahren
  status  <iface>                            Parsbare Statusinformation ausgeben
  nat-add <ext-port> <peer-ip> <knx-port>    iptables DNAT + FORWARD-Regel hinzufügen
  nat-del <ext-port> <peer-ip> <knx-port>    iptables-Regeln entfernen
EOF
    exit 1
}

require_root() {
    if [[ $EUID -ne 0 ]]; then
        echo "ERROR: Root-Rechte erforderlich" >&2
        exit 1
    fi
}

case "$CMD" in
    genkey)
        require_root
        KEYFILE="${2:-}"
        if [[ -z "$KEYFILE" ]]; then
            echo "ERROR: Keyfile-Pfad fehlt" >&2
            exit 1
        fi
        KEYDIR="$(dirname "$KEYFILE")"
        mkdir -p "$KEYDIR"
        PRIVKEY="$(wg genkey)"
        echo "$PRIVKEY" > "$KEYFILE"
        chmod 600 "$KEYFILE"
        # Public Key auf stdout ausgeben
        echo "$PRIVKEY" | wg pubkey
        ;;

    setup)
        require_root
        IFACE="${2:-wg0}"
        SERVER_IP="${3:-10.100.0.1}"
        PEER_IP="${4:-10.100.0.2}"
        LISTEN_PORT="${5:-51820}"
        PRIVKEY_FILE="${6:-/etc/wireguard/${IFACE}_private.key}"

        if [[ ! -f "$PRIVKEY_FILE" ]]; then
            echo "ERROR: Private-Key-Datei nicht gefunden: $PRIVKEY_FILE" >&2
            exit 1
        fi

        PRIVKEY="$(cat "$PRIVKEY_FILE")"
        CONF_FILE="/etc/wireguard/${IFACE}.conf"

        cat > "$CONF_FILE" <<WGCONF
[Interface]
PrivateKey = ${PRIVKEY}
Address = ${SERVER_IP}/24
ListenPort = ${LISTEN_PORT}
WGCONF
        chmod 600 "$CONF_FILE"

        # Falls Interface bereits läuft, erst herunterfahren
        if ip link show "$IFACE" &>/dev/null; then
            wg-quick down "$IFACE" 2>/dev/null || true
        fi
        wg-quick up "$IFACE"
        echo "OK: Interface $IFACE gestartet (${SERVER_IP}/24, Port ${LISTEN_PORT})"
        ;;

    peer-add)
        require_root
        IFACE="${2:-wg0}"
        PUBKEY="${3:-}"
        PEER_IP="${4:-}"
        if [[ -z "$PUBKEY" || -z "$PEER_IP" ]]; then
            echo "ERROR: pubkey und peer-ip erforderlich" >&2
            exit 1
        fi
        wg set "$IFACE" peer "$PUBKEY" allowed-ips "${PEER_IP}/32" persistent-keepalive 25
        # Konfiguration persistieren
        wg-quick save "$IFACE" 2>/dev/null || true
        echo "OK: Peer $PUBKEY -> $PEER_IP hinzugefügt"
        ;;

    up)
        require_root
        IFACE="${2:-wg0}"
        wg-quick up "$IFACE"
        echo "OK: $IFACE hochgefahren"
        ;;

    down)
        require_root
        IFACE="${2:-wg0}"
        wg-quick down "$IFACE"
        echo "OK: $IFACE heruntergefahren"
        ;;

    status)
        require_root
        IFACE="${2:-wg0}"
        # Parsbare Ausgabe: interface tab peer tab endpoint tab allowed-ips tab latest-handshake tab rx tab tx
        wg show "$IFACE" dump
        ;;

    nat-add)
        require_root
        EXT_PORT="${2:-13671}"
        PEER_IP="${3:-10.100.0.2}"
        KNX_PORT="${4:-3671}"

        # IP-Forwarding aktivieren
        sysctl -w net.ipv4.ip_forward=1 > /dev/null

        # DNAT: eingehende Pakete auf ext-Port → Peer-IP:KNX-Port weiterleiten
        if ! iptables -t nat -C PREROUTING -p udp --dport "$EXT_PORT" \
                -j DNAT --to-destination "${PEER_IP}:${KNX_PORT}" 2>/dev/null; then
            iptables -t nat -A PREROUTING -p udp --dport "$EXT_PORT" \
                -j DNAT --to-destination "${PEER_IP}:${KNX_PORT}"
        fi

        # FORWARD: Pakete zum Peer durchlassen
        if ! iptables -C FORWARD -p udp -d "$PEER_IP" --dport "$KNX_PORT" \
                -j ACCEPT 2>/dev/null; then
            iptables -A FORWARD -p udp -d "$PEER_IP" --dport "$KNX_PORT" -j ACCEPT
        fi

        # Masquerade für Antwortpakete
        if ! iptables -t nat -C POSTROUTING -p udp -d "$PEER_IP" --dport "$KNX_PORT" \
                -j MASQUERADE 2>/dev/null; then
            iptables -t nat -A POSTROUTING -p udp -d "$PEER_IP" --dport "$KNX_PORT" \
                -j MASQUERADE
        fi

        echo "OK: NAT ${EXT_PORT} -> ${PEER_IP}:${KNX_PORT} aktiv"
        ;;

    nat-del)
        require_root
        EXT_PORT="${2:-13671}"
        PEER_IP="${3:-10.100.0.2}"
        KNX_PORT="${4:-3671}"

        iptables -t nat -D PREROUTING -p udp --dport "$EXT_PORT" \
            -j DNAT --to-destination "${PEER_IP}:${KNX_PORT}" 2>/dev/null || true
        iptables -D FORWARD -p udp -d "$PEER_IP" --dport "$KNX_PORT" \
            -j ACCEPT 2>/dev/null || true
        iptables -t nat -D POSTROUTING -p udp -d "$PEER_IP" --dport "$KNX_PORT" \
            -j MASQUERADE 2>/dev/null || true

        echo "OK: NAT-Regeln entfernt"
        ;;

    *)
        usage
        ;;
esac
