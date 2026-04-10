@echo off
setlocal enabledelayedexpansion

set SCRIPT_DIR=%~dp0
set VENV_DIR=%SCRIPT_DIR%.venv
set LOG_DIR=%SCRIPT_DIR%logs
set CFG=%SCRIPT_DIR%config.json
set PID_FILE=%SCRIPT_DIR%.server.pid
set PID_FILE_PUBLIC=%SCRIPT_DIR%.server-public.pid

if "%1"=="" goto usage
if "%1"=="setup"     goto setup
if "%1"=="start"     goto start
if "%1"=="stop"      goto stop
if "%1"=="status"    goto status
if "%1"=="logs"      goto logs
if "%1"=="gateway"   goto gateway
if "%1"=="update"    goto update
if "%1"=="autostart" goto autostart_note
goto usage

:: ── setup ────────────────────────────────────────────────────────────────────
:setup
echo =^> Erstelle virtuelles Environment ...
python -m venv "%VENV_DIR%"
if errorlevel 1 (
    echo FEHLER: Konnte virtuelles Environment nicht erstellen.
    pause & exit /b 1
)
echo =^> Installiere Abhaengigkeiten ...
"%VENV_DIR%\Scripts\pip" install --upgrade pip --quiet
"%VENV_DIR%\Scripts\pip" install -r "%SCRIPT_DIR%requirements.txt" --quiet
echo.
echo Fertig! Server starten mit:  openknxviewer start
goto end

:: ── start ────────────────────────────────────────────────────────────────────
:start
if not exist "%VENV_DIR%\Scripts\uvicorn.exe" (
    echo Fehler: Virtuelle Umgebung nicht gefunden. Bitte zuerst: openknxviewer setup
    exit /b 1
)
if not exist "%LOG_DIR%" mkdir "%LOG_DIR%"

set PUBLIC=0
set PORT_OVERRIDE=
set _ARG=%2
if "!_ARG!"=="--public" set PUBLIC=1
if "!_ARG!"=="--port" set PORT_OVERRIDE=%3

:: Determine config key and defaults
if %PUBLIC%==1 (
    set CFG_KEY=server_port_public
    set DEFAULT_PORT=8004
    set SERVER=server_public:app
    set STDOUT=%LOG_DIR%\stdout-public.log
    set STDERR=%LOG_DIR%\stderr-public.log
    set PF=%PID_FILE_PUBLIC%
    set LABEL=Oeffentlicher Server
) else (
    set CFG_KEY=server_port
    set DEFAULT_PORT=8002
    set SERVER=server:app
    set STDOUT=%LOG_DIR%\stdout.log
    set STDERR=%LOG_DIR%\stderr.log
    set PF=%PID_FILE%
    set LABEL=Privater Server
)

:: Get or prompt for port
if defined PORT_OVERRIDE (
    set USE_PORT=!PORT_OVERRIDE!
    powershell -NoProfile -Command ^
        "$d=if(Test-Path '!CFG!'){Get-Content '!CFG!'|ConvertFrom-Json}else{[pscustomobject]@{}}; ^
        $d|Add-Member -Force NotePropertyName '!CFG_KEY!' -NotePropertyValue [int]'!USE_PORT!'; ^
        $d|ConvertTo-Json|Set-Content '!CFG!'"
) else (
    powershell -NoProfile -Command "$d=if(Test-Path '!CFG!'){Get-Content '!CFG!'|ConvertFrom-Json}else{[pscustomobject]@{}}; $v=$d.'!CFG_KEY!'; [string]$v" > "%TEMP%\_knxport.tmp" 2>nul
    set STORED=
    set /p STORED= < "%TEMP%\_knxport.tmp"
    del "%TEMP%\_knxport.tmp" 2>nul
    if "!STORED!"=="" (
        set /p USE_PORT=!LABEL! Port [!DEFAULT_PORT!]:
        if "!USE_PORT!"=="" set USE_PORT=!DEFAULT_PORT!
        powershell -NoProfile -Command ^
            "$d=if(Test-Path '!CFG!'){Get-Content '!CFG!'|ConvertFrom-Json}else{[pscustomobject]@{}}; ^
            $d|Add-Member -Force NotePropertyName '!CFG_KEY!' -NotePropertyValue [int]'!USE_PORT!'; ^
            $d|ConvertTo-Json|Set-Content '!CFG!'"
        echo   Port !USE_PORT! in config.json gespeichert.
    ) else (
        set USE_PORT=!STORED!
    )
)

powershell -NoProfile -Command ^
    "$p = Start-Process -FilePath '!VENV_DIR!\Scripts\uvicorn.exe' ^
    -ArgumentList '!SERVER!','--host','0.0.0.0','--port','!USE_PORT!' ^
    -WorkingDirectory '!SCRIPT_DIR!' ^
    -RedirectStandardOutput '!STDOUT!' ^
    -RedirectStandardError '!STDERR!' ^
    -WindowStyle Hidden -PassThru; ^
    $p.Id | Out-File -Encoding ascii '!PF!'"
echo !LABEL! gestartet (Port !USE_PORT!)
goto end

:: ── stop ─────────────────────────────────────────────────────────────────────
:stop
set ALL=0
set PUBLIC=0
if "%2"=="--public" set PUBLIC=1
if "%2"=="--all"    set ALL=1

if %ALL%==1 (
    call :stop_one "%PID_FILE%"        "Privater Server"
    call :stop_one "%PID_FILE_PUBLIC%" "Oeffentlicher Server"
) else if %PUBLIC%==1 (
    call :stop_one "%PID_FILE_PUBLIC%" "Oeffentlicher Server"
) else (
    call :stop_one "%PID_FILE%"        "Privater Server"
)
goto end

:stop_one
set _PF=%~1
set _LBL=%~2
if exist "%_PF%" (
    set /p _PID=<"%_PF%"
    taskkill /PID !_PID! /F >nul 2>&1
    if errorlevel 1 (echo !_LBL! war nicht aktiv.) else (echo !_LBL! gestoppt (PID !_PID!).)
    del "%_PF%"
) else (
    echo Kein PID-File fuer !_LBL! gefunden.
)
goto :eof

:: ── status ───────────────────────────────────────────────────────────────────
:status
for /f "delims=" %%P in ('powershell -NoProfile -Command ^
    "$d=if(Test-Path '%CFG%'){Get-Content '%CFG%'|ConvertFrom-Json}else{[pscustomobject]@{}}; ^
    if($d.server_port){$d.server_port}else{8002}") do set PORT_PRIV=%%P
for /f "delims=" %%P in ('powershell -NoProfile -Command ^
    "$d=if(Test-Path '%CFG%'){Get-Content '%CFG%'|ConvertFrom-Json}else{[pscustomobject]@{}}; ^
    if($d.server_port_public){$d.server_port_public}else{8004}") do set PORT_PUB=%%P

call :status_one "%PID_FILE%"        "Privater Server"     !PORT_PRIV! private
call :status_one "%PID_FILE_PUBLIC%" "Oeffentlicher Server" !PORT_PUB!  public
goto end

:status_one
set _PF=%~1
set _LBL=%~2
set _PORT=%~3
set _TYPE=%~4
if exist "%_PF%" (
    set /p _PID=<"%_PF%"
    tasklist /FI "PID eq !_PID!" 2>nul | find "!_PID!" >nul
    if errorlevel 1 (
        echo !_LBL!: gestoppt (veraltetes PID-File^)
        del "%_PF%"
    ) else (
        echo !_LBL!: laeuft (PID !_PID!, Port !_PORT!)
        if "!_TYPE!"=="private" (
            powershell -NoProfile -Command ^
                "try { $d=(Invoke-RestMethod http://localhost:!_PORT!/api/gateway); ^
                $ok=if($d.connected){'verbunden'}else{'nicht verbunden'}; ^
                Write-Host ('  Gateway: '+$d.ip+':'+$d.port+' - '+$ok+' ['+$d.language+']') } catch {}"
        )
    )
) else (
    echo !_LBL!: gestoppt
)
goto :eof

:: ── logs ─────────────────────────────────────────────────────────────────────
:logs
set LINES=50
set FOLLOW=0
if "%2"=="--lines"  set LINES=%3
if "%2"=="-n"       set LINES=%3
if "%2"=="--follow" set FOLLOW=1
if "%2"=="-f"       set FOLLOW=1

if not exist "%LOG_DIR%\knx_bus.log" (
    echo Keine Logdatei vorhanden: %LOG_DIR%\knx_bus.log
    goto end
)
if %FOLLOW%==1 (
    powershell -NoProfile -Command "Get-Content '%LOG_DIR%\knx_bus.log' -Tail %LINES% -Wait"
) else (
    powershell -NoProfile -Command "Get-Content '%LOG_DIR%\knx_bus.log' -Tail %LINES%"
)
goto end

:: ── gateway ───────────────────────────────────────────────────────────────────
:gateway
set GW_IP=
set GW_PORT=
set GW_LANG=
:gw_parse
if "%~2"=="" goto gw_action
if "%~2"=="--ip"       ( set GW_IP=%~3       & shift & shift & goto gw_parse )
if "%~2"=="--port"     ( set GW_PORT=%~3     & shift & shift & goto gw_parse )
if "%~2"=="--language" ( set GW_LANG=%~3     & shift & shift & goto gw_parse )
shift & goto gw_parse

:gw_action
if "%GW_IP%%GW_PORT%%GW_LANG%"=="" (
    if exist "%CFG%" (
        powershell -NoProfile -Command ^
            "$d=Get-Content '%CFG%'|ConvertFrom-Json; ^
            Write-Host ('Gateway-IP:   '  +$d.gateway_ip); ^
            Write-Host ('Gateway-Port: '  +$d.gateway_port); ^
            Write-Host ('Sprache:      '  +$d.language); ^
            Write-Host ('Server-Port:  '  +$(if($d.server_port){$d.server_port}else{8002})); ^
            Write-Host ('Public-Port:  '  +$(if($d.server_port_public){$d.server_port_public}else{8004}))"
    ) else (
        echo config.json nicht gefunden.
    )
    goto end
)
powershell -NoProfile -Command ^
    "$d=if(Test-Path '%CFG%'){Get-Content '%CFG%'|ConvertFrom-Json}else{[pscustomobject]@{gateway_ip='';gateway_port=3671;language='de-DE'}}; ^
    if('%GW_IP%'){$d.gateway_ip='%GW_IP%'}; ^
    if('%GW_PORT%'){$d.gateway_port=[int]'%GW_PORT%'}; ^
    if('%GW_LANG%'){$d.language='%GW_LANG%'}; ^
    $d|ConvertTo-Json|Set-Content '%CFG%'; ^
    Write-Host ('Gateway gespeichert: '+$d.gateway_ip+':'+$d.gateway_port+', Sprache: '+$d.language)"
goto end

:: ── update ───────────────────────────────────────────────────────────────────
:update
if not exist "%VENV_DIR%\Scripts\pip.exe" (
    echo Fehler: Virtuelle Umgebung nicht gefunden. Bitte zuerst: openknxviewer setup
    exit /b 1
)
echo =^> Aktualisiere Abhaengigkeiten ...
"%VENV_DIR%\Scripts\pip" install --upgrade pip --quiet
"%VENV_DIR%\Scripts\pip" install --upgrade -r "%SCRIPT_DIR%requirements.txt" --quiet
echo.
echo Installierte Versionen:
"%VENV_DIR%\Scripts\pip" show xknxproject xknx fastapi uvicorn 2>nul | findstr /R "^Name ^Version"
goto end

:: ── autostart ────────────────────────────────────────────────────────────────
:autostart_note
echo Autostart wird nur unter macOS unterstuetzt (LaunchAgent^).
echo Unter Windows bitte den Task Scheduler verwenden.
goto end

:: ── usage ────────────────────────────────────────────────────────────────────
:usage
echo Verwendung: openknxviewer ^<Befehl^> [Optionen]
echo.
echo   setup                                         Umgebung erstellen ^& Pakete installieren
echo   start  [--public] [--port N]                  Server starten (fragt Port beim ersten Mal^)
echo   stop   [--public ^| --all]                    Server stoppen
echo   status                                        Server- und Gateway-Status anzeigen
echo   logs   [--lines N] [--follow]                 Bus-Log anzeigen
echo   gateway                                       Konfiguration anzeigen
echo   gateway --ip X [--port Y] [--language L]      KNX-Gateway konfigurieren
echo   update                                        Alle Pakete aktualisieren

:end
endlocal
