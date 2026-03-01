@echo off
:: knx_tunnel.bat — Startskript für den KNX Tunnel Agent (Windows)
::
:: Hinweis: WireGuard-Verwaltung erfordert Linux/Raspberry Pi.
:: Dieses Skript ist fuer Windows-seitige Verwaltung (z.B. zum Herunterladen
:: der Pi-Konfiguration oder zum Testen) gedacht, jedoch nicht für den echten
:: Tunnelbetrieb (wg-quick ist auf Windows nicht verfuegbar).
::
:: Verwendung:
::   knx_tunnel.bat setup                        Venv pruefen/erstellen & Pakete installieren
::   knx_tunnel.bat [OPTIONEN]                   Tunnel Agent starten
::
:: Optionen:
::   --server-url URL      HTTP(S)-URL des OpenKNXViewer-Servers
::   --server-token TOKEN  Authentifizierungs-Token (aus Gateway-Modal)
::   --knx-ip IP           IP des lokalen KNX/IP-Gateways
::   --wg-iface IFACE      WireGuard-Interface (Standard: wg0)
::   --peer-ip IP          Pi-IP im Tunnel (Standard: 10.100.0.2)
::   --server-wg-ip IP     Server-IP im Tunnel (Standard: 10.100.0.1)
::   --server-wg-port PORT WG-Listen-Port des Servers (Standard: 51820)
::   --echo-port PORT      UDP-Echo-Port (Standard: 51821)
::   --ssl-no-verify       TLS-Zertifikat nicht pruefen (nur Tests)
::
:: Konfigurationsdatei (Alternative zu CLI-Argumenten):
::   tunnel_config.json im selben Verzeichnis anlegen:
::   {"server_url": "https://...", "server_token": "...", "knx_ip": "192.168.1.100"}

setlocal EnableDelayedExpansion

set "SCRIPT_DIR=%~dp0"
if "!SCRIPT_DIR:~-1!"=="\" set "SCRIPT_DIR=!SCRIPT_DIR:~0,-1!"

set "AGENT_SCRIPT=!SCRIPT_DIR!\knx_tunnel_agent.py"
set "TUNNEL_CFG=!SCRIPT_DIR!\tunnel_config.json"
set "VENV_DIR=!SCRIPT_DIR!\.venv-proxy"
set "VENV_PYTHON=!VENV_DIR!\Scripts\python.exe"

:: ── System-Python finden ──────────────────────────────────────────────────────
set "SYS_PYTHON="
for %%P in (python python3 py) do (
    if "!SYS_PYTHON!"=="" (
        %%P --version >nul 2>&1
        if not errorlevel 1 (
            for /f "delims=" %%V in ('%%P -c "import sys; print(sys.version_info.major)" 2^>nul') do (
                if "%%V"=="3" set "SYS_PYTHON=%%P"
            )
        )
    )
)

:: ── setup ─────────────────────────────────────────────────────────────────────
if /i "%~1"=="setup" goto :cmd_setup
goto :cmd_start

:cmd_setup
if "!SYS_PYTHON!"=="" (
    echo Fehler: Python 3 nicht gefunden.
    echo Bitte Python 3.9+ von https://www.python.org/downloads/ installieren.
    pause
    exit /b 1
)
for /f "delims=" %%V in ('!SYS_PYTHON! --version 2^>^&1') do echo ==^> Verwende System-Python: %%V

if not exist "!VENV_PYTHON!" (
    echo ==^> Erstelle virtuelle Umgebung in !VENV_DIR! ...
    !SYS_PYTHON! -m venv "!VENV_DIR!"
    if errorlevel 1 (
        echo Fehler beim Erstellen der virtuellen Umgebung.
        pause
        exit /b 1
    )
    echo ==^> Installiere Abhaengigkeiten (xknx, websockets^) ...
    "!VENV_PYTHON!" -m pip install --upgrade pip --quiet
    "!VENV_PYTHON!" -m pip install xknx websockets --quiet
) else (
    echo ==^> Virtuelle Umgebung bereits vorhanden.
)

echo ==^> Installiere requests ...
"!VENV_PYTHON!" -m pip install requests --quiet
if errorlevel 1 (
    echo Fehler bei der Installation von requests.
    pause
    exit /b 1
)
echo.
echo Fertig! Tunnel Agent starten mit:
echo   knx_tunnel.bat --server-url "https://host" --server-token TOKEN --knx-ip 192.168.1.100
echo.
echo Hinweis: WireGuard-Betrieb erfordert Linux/Raspberry Pi (wg-quick).
goto :end

:: ── cmd_start ─────────────────────────────────────────────────────────────────
:cmd_start
if not exist "!VENV_PYTHON!" (
    echo Fehler: Virtuelle Umgebung nicht gefunden.
    echo Bitte zuerst ausfuehren:  knx_tunnel.bat setup
    pause
    exit /b 1
)

if exist "!TUNNEL_CFG!" (
    echo Konfiguration aus tunnel_config.json:
    "!VENV_PYTHON!" -c "import json,sys; d=json.load(open(sys.argv[1])); [print(f'  {k}: ***' if k=='server_token' else f'  {k}: {v}') for k,v in d.items()]" "!TUNNEL_CFG!"
)

set "HAS_ARGS=0"
if not "%~1"=="" set "HAS_ARGS=1"
if "!HAS_ARGS!"=="0" if not exist "!TUNNEL_CFG!" (
    echo.
    echo Verwendung: knx_tunnel.bat [OPTIONEN]
    echo.
    echo   --server-url URL      HTTP(S)-URL des Servers
    echo   --server-token TOKEN  Authentifizierungs-Token
    echo   --knx-ip IP           IP des lokalen KNX/IP-Gateways
    echo   --wg-iface IFACE      WireGuard-Interface ^(Standard: wg0^)
    echo   --peer-ip IP          Pi-IP im Tunnel ^(Standard: 10.100.0.2^)
    echo   --server-wg-ip IP     Server-IP im Tunnel ^(Standard: 10.100.0.1^)
    echo   --echo-port PORT      UDP-Echo-Port ^(Standard: 51821^)
    echo   --ssl-no-verify       TLS-Zertifikat nicht pruefen
    echo.
    echo Venv einrichten:  knx_tunnel.bat setup
    pause
    goto :end
)

echo Starte KNX Tunnel Agent ...
"!VENV_PYTHON!" "!AGENT_SCRIPT!" %*
if errorlevel 1 (
    echo.
    echo Tunnel Agent beendet mit Fehler.
    pause
)

:end
endlocal
