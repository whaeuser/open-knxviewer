# OpenKNXViewer — WireGuard-Tunnel & ETS-Fernzugang

Der WireGuard-Tunnel ermöglicht es ETS, einen Raspberry Pi-seitigen KNX-Bus zu erreichen, als wäre er lokal angeschlossen. Er ergänzt den bestehenden WebSocket-Proxy (für Bus-Monitor und GA R/W) um direkten UDP-Tunneling-Zugang.

```
VPS (server.py)                            Raspberry Pi
┌──────────────────────────────┐           ┌──────────────────────────────┐
│  wg0: 10.100.0.1            │◄──WG──────│  wg0: 10.100.0.2            │
│  UDP:13671 → 10.100.0.2:3671│  (51820)  │  knx_tunnel_agent.py        │
│                              │           │  → KNX/IP-Gateway (lokal)   │
│  ETS → VPS-IP:13671         │           │                              │
│  Latenz-Monitor              │◄──ping────│  UDP-Echo Port 51821        │
│  → allowed_actions[]        │           │                              │
│  → WSS-Proxy (bestehend)    │◄──WSS─────│  knx_gateway_proxy.py       │
└──────────────────────────────┘           └──────────────────────────────┘
```

---

## Voraussetzungen

### VPS (Server)

- Linux mit WireGuard-Kernel-Modul: `modprobe wireguard` oder Kernel ≥ 5.6
- `wireguard-tools` installiert: `apt install wireguard-tools`
- Root-Zugriff über `sudo` für den OpenKNXViewer-Benutzer (eingeschränkt via Sudoers)
- Offene Firewall-Ports: UDP 51820 (WireGuard), UDP 13671 (ETS-Zugang)
- `iptables` verfügbar (für Port-Forward)

### Raspberry Pi (Client)

- Raspberry Pi OS (Bullseye oder neuer)
- `wireguard-tools` installiert: `sudo apt install wireguard wireguard-tools`
- Python 3.9+: `python3 --version`
- Root-Zugriff für WG-Interface-Verwaltung

---

## Schritt 1: `wg_helper.sh` auf dem VPS installieren

Das Skript kapselt alle Root-Operationen, damit `server.py` ohne Root läuft:

```bash
# Als Root auf dem VPS:
sudo cp wg_helper.sh /usr/local/bin/openknxviewer-wg-helper
sudo chmod 755 /usr/local/bin/openknxviewer-wg-helper
```

**Sudoers-Eintrag** (als Root, z.B. via `visudo -f /etc/sudoers.d/openknxviewer`):

```
# Ersetze 'openknxviewer' durch den tatsächlichen Systembenutzernamen
openknxviewer ALL=(ALL) NOPASSWD: /usr/local/bin/openknxviewer-wg-helper
```

Test:
```bash
sudo /usr/local/bin/openknxviewer-wg-helper status wg0
# → Fehlermeldung "Interface nicht gefunden" ist normal vor dem ersten Setup
```

---

## Schritt 2: Tunnel über den Browser einrichten

1. **Browser öffnen** → OpenKNXViewer → ⚙ (Gateway-Config-Modal)
2. Ganz unten: **WireGuard Tunnel** → **Einstellungen ↓**
3. Felder ausfüllen:
   - **Server-IP (WG)**: Interne IP des VPS im Tunnel (z.B. `10.100.0.1`)
   - **Pi-IP (WG)**: Interne IP des Pi im Tunnel (z.B. `10.100.0.2`)
   - **WG-Port**: `51820` (UDP, muss in der Firewall offen sein)
   - **ETS-Port**: `13671` (UDP, für ETS-Zugang)
   - **KNX-Gateway-IP (Pi)**: Lokale IP des KNX/IP-Gateways am Pi (z.B. `192.168.1.100`)
   - **Öff. Server-IP**: Öffentliche IP-Adresse des VPS
4. **Tunnel initialisieren** → Der Server-Public-Key wird angezeigt
5. **Pi-Konfiguration ↓** → `wg0_client.conf` herunterladen

---

## Schritt 3: Pi einrichten

### Venv erstellen und Abhängigkeiten installieren

```bash
# Auf dem Pi (im OpenKNXViewer-Verzeichnis):
./knx_tunnel setup
```

### Tunnel Agent starten

```bash
./knx_tunnel \
    --server-url "https://mein-vps.example.com" \
    --server-token DEIN_TOKEN \
    --knx-ip 192.168.1.100

# Oder mit tunnel_config.json:
cat > tunnel_config.json << 'EOF'
{
  "server_url": "https://mein-vps.example.com",
  "server_token": "DEIN_TOKEN",
  "knx_ip": "192.168.1.100"
}
EOF
./knx_tunnel
```

> **Hinweis:** Das Skript benötigt Root-Rechte für WireGuard. Auf dem Pi mit `sudo ./knx_tunnel ...` starten oder dem Benutzer entsprechende Sudo-Rechte geben.

Der Agent:
1. Generiert WireGuard-Keys (falls noch nicht vorhanden)
2. Schreibt `/etc/wireguard/wg0.conf` und startet `wg-quick up wg0`
3. Registriert sich beim Server via `POST /api/wireguard/peer`
4. Startet den UDP-Echo-Server (Port 51821) für Latenz-Messungen

---

## Schritt 4: ETS verbinden

Sobald der Tunnel aktiv ist (Pi-Status = grün im Modal):

1. Im Modal: **ETS-Zugang aktivieren** → iptables-Regel wird gesetzt
2. In ETS:
   - **IP-Adresse**: Öffentliche IP des VPS
   - **Port**: `13671`
   - Verbindungstyp: KNXnet/IP Tunneling

---

## Latenz → Erlaubte Aktionen

Die gemessene Latenz steuert automatisch, welche Aktionen erlaubt sind:

| Latenz | allowed_actions |
|--------|----------------|
| < 50 ms | `monitor`, `ga_rw`, `ets_params`, `ets_program` |
| 50–150 ms | `monitor`, `ga_rw`, `ets_params` |
| 150–500 ms | `monitor`, `ga_rw` |
| > 500 ms / offline | `monitor` |

Der Latenz-Indikator erscheint in der Kopfzeile neben dem Gateway-Status. Der GA-Schreib-Button wird automatisch deaktiviert, wenn die Latenz zu hoch ist.

---

## Systemd-Unit für den Pi (Dauerbetrieb)

```ini
# /etc/systemd/system/knx-tunnel.service
[Unit]
Description=OpenKNXViewer Tunnel Agent
After=network-online.target
Wants=network-online.target

[Service]
Type=simple
User=pi
WorkingDirectory=/home/pi/openknxviewer
ExecStart=/home/pi/openknxviewer/.venv-proxy/bin/python3 \
    /home/pi/openknxviewer/knx_tunnel_agent.py \
    --server-url https://mein-vps.example.com \
    --server-token DEIN_TOKEN \
    --knx-ip 192.168.1.100
Restart=on-failure
RestartSec=10

[Install]
WantedBy=multi-user.target
```

```bash
sudo systemctl enable --now knx-tunnel
sudo systemctl status knx-tunnel
```

---

## Sicherheitshinweise

- **Private Keys** werden nicht in `config.json` gespeichert — nur auf Disk als `/etc/wireguard/wg0_private.key` mit Mode 600
- **Token** in `config.json` sichern (Datei ist in `.gitignore`)
- **Firewall**: Nur UDP 51820 (WG) und UDP 13671 (ETS) öffnen, niemals den ganzen WG-Adressbereich
- **ETS-Zugang**: Nach der Programmier-Session wieder deaktivieren (Modal → "ETS-Zugang deaktivieren")
- **Key-Rotation**: Tunnel abbauen (DELETE `/api/wireguard/setup`), dann neu initialisieren
- **`wg_helper.sh`**: Das Sudoers-Pattern erlaubt nur den spezifischen Skriptpfad — kein vollständiger Root-Zugriff

---

## Fehlerbehebung

### WireGuard-Kernel-Modul fehlt

```bash
modprobe wireguard
echo wireguard >> /etc/modules
```

### `wg-quick` nicht gefunden

```bash
# VPS: apt install wireguard-tools
# Pi:  sudo apt install wireguard wireguard-tools
```

### Tunnel aktiv, aber Ping schlägt fehl

```bash
# Pi: Routing prüfen
ip route show
# VPS: Interface prüfen
sudo wg show wg0
# Pi sollte als Peer mit "last handshake" erscheinen
```

### ETS kann nicht verbinden

```bash
# VPS: iptables prüfen
sudo iptables -t nat -L PREROUTING -n -v
sudo iptables -L FORWARD -n -v
# Firewall: UDP 13671 offen?
```

### Latenz wird nicht gemessen

Der Server pingt die Pi-IP im WG-Tunnel (z.B. `10.100.0.2`). Falls ping fehlschlägt:
- Ist der WG-Tunnel aktiv?
- Gibt es eine Route vom VPS zur Pi-WG-IP?
- Blockiert eine Host-Firewall ICMP?
