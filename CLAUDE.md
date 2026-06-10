# CLAUDE.md

This file provides guidance to Claude Code (claude.ai/code) when working with code in this repository.

## Commands

All operations are handled via the unified CLI `openknxviewer` (bash) / `openknxviewer.bat` (Windows):

```bash
./openknxviewer setup                        # create .venv, install dependencies
./openknxviewer start                        # private server, port 8002
./openknxviewer start --public               # public server, port 8004
./openknxviewer stop [--public|--all]        # stop server(s)
./openknxviewer status                       # show server + gateway status
./openknxviewer logs [--lines N] [--follow]  # show bus log
./openknxviewer gateway [--ip X --port Y]    # show/set gateway config
./openknxviewer update                       # upgrade all packages
./openknxviewer autostart [--public]         # install macOS LaunchAgent
./openknxviewer autostart --remove [--public]# remove macOS LaunchAgent
```

Both servers can run simultaneously and share the same `index.html`. The frontend fetches `/api/mode` on startup to activate or deactivate bus features.

> **Important:** Do not use `--reload` — it spawns multiple worker processes that each try to open a KNX tunnel, competing for the single tunnel slot on the gateway and causing connection failures.

Logs are written to `logs/stdout.log`, `logs/stderr.log`, and `logs/knx_bus.log`.

Run tests with:
```bash
.venv/bin/python3 -m pytest          # all tests
.venv/bin/python3 -m pytest -v       # verbose
.venv/bin/python3 -m pytest tests/test_helpers.py   # one file
```
Test files live in `tests/`. Dev dependencies: `requirements-dev.txt` (pytest, pytest-asyncio, ruff). Lint with `.venv/bin/python3 -m ruff check .`. CI (GitHub Actions, `.github/workflows/ci.yml`) runs ruff + pytest on every push/PR; tests needing `.knxproj` fixtures skip themselves when the sibling `xknxproject` repo is missing.

Test `.knxproj` files are available at `../xknxproject/test/resources/*.knxproj`.

## Architecture

Two server entry points sharing one `index.html` frontend SPA.

### Backend module layout

- **`server.py`** — private server (port 8002): app, lifespan, KNX connection loop, telegram processing, WebSocket endpoints, gateway/annotations/log/parse routes. Includes the routers below.
- **`server_public.py`** — public server (port 8004): read-only (`GET /`, `/api/mode`, `/api/demo*`, `POST /api/parse`, `POST /api/export/xlsx`); no KNX connection, no WebSocket, no state; slowapi rate limiting.
- **`core.py`** — shared state dict, file-path constants, config load/save/update (thread-safe via RLock), recent-projects helpers, `set_project_data()` (builds `ga_dpt_map` + `ga_name_map`), `broadcast()`, `spawn()` (create_task with held reference), bus logger.
- **`common.py`** — stateless helpers shared by both servers: `extract_security_data`, `parse_ets_certificate`, `build_project_xlsx`, `dpt_str`, `flag_str`.
- **`models.py`** — Pydantic request models for all POST bodies.
- **`routers/`** — APIRouter modules included by `server.py`: `ga_ops` (write/read/read-all), `scan` (GA-/PA-Scan, programming mode, device properties), `snapshots`, `recent_projects`, `llm` (KI-Analyse), `wireguard`.

Conventions:
- Routers access paths as `core.CONFIG_PATH` etc. (attribute access at call time) so tests can monkeypatch `core`.
- Background tasks always via `core.spawn()` — never bare `asyncio.create_task()` (GC kann sonst laufende Tasks einsammeln).
- Read-modify-write on `config.json` via `core.update_config({...})`, nie load→mutate→save.
- `recent_projects._validate_slug()` rejects anything `project_slug()` wouldn't produce (path-traversal defence) — neue `{slug}`-Endpoints müssen es aufrufen.
- `.knxproj`-Parsing läuft per `asyncio.to_thread` — nie synchron im Event-Loop.

#### Global state (`core.state` dict)
Created by `core.initial_state()` (single source of truth — auch für den Test-Reset).
Key fields: `xknx`, `connected`, `gateway_ip/port`, `language`, `project_data`,
`ga_dpt_map` (registered with xknx), `ga_name_map` (O(1) GA-name lookup),
`current_values`, `telegram_buffer` (deque maxlen=500), `ws_clients`, `connect_task`,
`connection_type`, `remote_gateway_*`, `ga_scan_*`/`pa_scan_*`, `wireguard_*`.

#### API routes
| Method | Path | Description |
|--------|------|-------------|
| `GET` | `/` | Serves `index.html` |
| `GET` | `/api/mode` | Returns `{public: false}` — signals full-feature mode to frontend |
| `GET` | `/api/gateway` | Returns `{ip, port, connected, language}` |
| `POST` | `/api/gateway` | Saves `{ip, port, language}` to `config.json`, restarts KNX connection |
| `POST` | `/api/parse` | Parses uploaded `.knxproj` file; saves result to `last_project.json`; registers DPT map with xknx |
| `GET` | `/api/last-project/info` | Returns `{filename}` of last parsed project, or 404 |
| `GET` | `/api/last-project/data` | Returns full parsed project JSON from state, or 404 |
| `GET` | `/api/current-values` | Returns `current_values` dict |
| `GET` | `/api/log?lines=N` | Returns last N entries from `logs/knx_bus.log` as JSON |
| `GET` | `/api/annotations` | Returns `annotations.json` |
| `POST` | `/api/annotations` | Saves annotations dict to `annotations.json` |
| `WS` | `/ws` | WebSocket: sends `status`, `snapshot`, `history` on connect; streams `telegram` messages live |
| `GET` | `/.well-known/appspecific/com.chrome.devtools.json` | Returns `{}` (suppresses Chrome DevTools 404 noise) |

#### KNX connection (`knx_connect_loop`)
- Runs as a background `asyncio.Task` started in the lifespan
- Reads gateway config from `config.json` on each (re)start
- Connects via `xknx` tunneling; registers `telegram_received_cb`
- Registers current `ga_dpt_map` with `xknx.group_address_dpt` so xknx decodes telegrams automatically
- On disconnect: exponential backoff retry (10 → 20 → 40 → 60 s max)
- `start_connect_task()` cleanly cancels the old task before starting a new one (called on gateway config change)

#### DPT-aware decoding
When a `.knxproj` file is parsed, the GA→DPT mapping is registered with the live xknx instance:
```python
xknx.group_address_dpt.set(state["ga_dpt_map"])
```
xknx then sets `telegram.decoded_data` on each incoming telegram. `_process_telegram` uses this:
- `decoded_data.value` → typed Python value (float, int, bool, enum)
- `decoded_data.transcoder.unit` → unit string (e.g. `"°C"`, `"%"`, `"V"`)
- Booleans displayed as `"Ein"` / `"Aus"`, floats formatted to 2 decimal places
- Falls back to raw `telegram.payload.value` string if no DPT known
- `raw` field always contains the undecoced payload string; `dpt` field contains e.g. `"9.001"` (from `transcoder.dpt_main_number` / `dpt_sub_number`), empty string if unknown
- Bus-Monitor "Wert" cell tooltip: `"DPT: 9.001 | Raw: DPTArray((0x0c, 0x1a))"` — only shown when DPT or raw differs from displayed value

#### Telegram callback
`telegram_received_cb` is synchronous (required by xknx); it spawns `_process_telegram` as an `asyncio.Task`. The async function looks up device name and GA name from `project_data`, formats the value, logs to `knx_bus.log`, updates `current_values`, appends to `telegram_buffer`, and broadcasts to all WebSocket clients.

#### Log file
`logs/knx_bus.log` — pipe-separated format:
```
2024-01-15 14:32:01.234 | 1.1.5 | Taster EG | 1/2/3 | Licht Küche | Ein
```
Rotates daily, keeps 30 days. Pre-loaded into `telegram_buffer` on startup (last 500 lines).

#### Persistent files
- `config.json` — `{"gateway_ip": "...", "gateway_port": 3671, "language": "de-DE", "last_project_filename": "mein.knxproj"}`
- `annotations.json` — `{"devices": {"1.1.5": {"name": "...", "description": "..."}}, "group_addresses": {"1/2/3": {...}}}`
- `last_project.json` — full parsed project JSON, written after each successful parse; loaded into `state["project_data"]` on startup (avoids re-upload after restart; also pre-populates `ga_dpt_map` for DPT decoding)

---

### Frontend (`index.html` + `static/app.js`)

Vanilla HTML with Alpine.js v3 (state management) and Tailwind CSS (styling). All JS lives in `static/app.js` (the `app()` Alpine component); `index.html` contains only markup. Libraries are vendored locally in `static/vendor/` (alpine.min.js, marked.min.js, vis-network.min.js) — no CDN, works offline. Tailwind is built locally (see memory: Build-Prozess Tailwind). No other build step.

#### Startup (`init()`)
Fetches `/api/mode` first. If `public: true`, sets `publicMode = true` and skips WebSocket, annotations, and last-project check. If `public: false` (default), connects WebSocket, loads annotations, and calls `loadLastProjectInfo()` to check for a previously parsed project.

#### Two phases

1. **Upload phase** — drag-and-drop or file picker, optional password input; language from gateway config used automatically; "Zuletzt: &lt;filename&gt;" button loads last project without re-upload (private mode only); "Ohne Projektdatei → Nur Bus-Monitor" button (private mode only)
2. **Result phase** — eight tabs (see below)

#### Alpine.js state (key additions for live features)
```javascript
publicMode,                          // true when served by server_public.py — disables all bus features
lastProjectFilename,                 // filename of last parsed project (shown as quick-load button)
ws, wsStatus,                        // WebSocket instance and status ('connected'/'disconnected')
gatewayIP, gatewayPort,              // current gateway config
gatewayLanguage,                     // 'de-DE' (default) or 'en-US' — persisted in config.json
showGatewayConfig,                   // modal visibility
currentValues,                       // {ga_address: {value, ts}} — updated live
liveLog,                             // array of telegram entries, newest first (max 1000)
liveLogFilter, liveLogPaused,        // bus monitor controls
annotations,                         // loaded from /api/annotations
editingKey, editValue,               // inline edit state ('type|key|field' format)
```

#### WebSocket message types
| Type | Direction | Payload |
|------|-----------|---------|
| `status` | server→client | `{connected, ip, port, language}` — sent on connect and on connection change |
| `snapshot` | server→client | `{values: current_values}` — sent on WebSocket connect |
| `history` | server→client | `{entries: [...]}` — last 500 telegrams, newest first, sent on connect |
| `telegram` | server→client | `{ts, src, device, ga, ga_name, value, raw, dpt}` — live stream |

Alpine.js uses array spread (`[msg, ...liveLog].slice(0, 1000)`) for live updates — **not** `unshift()` — to ensure Alpine's reactivity proxy detects the change.

#### Tab features

**With project file loaded:**
- **Info**: project metadata
- **Geräte**: searchable device table; `▸/▾` to expand KOs inline; "N KOs" link navigates to KO tab
- **Gruppenadressen**: searchable; "Letzter Wert" column shows live value from `currentValues`; linked KO badges navigate to KO tab
- **Topologie**: collapsible area → line → device tree
- **Kommunikationsobjekte**: COs grouped by device, collapsible; search auto-expands sections; row click navigates to GA tab
- **Funktionen**: function groups with linked GAs — tab only shown when project contains ≥1 function (via `visibleTabs`)
- **Bus-Monitor**: hidden entirely in public mode (via `visibleTabs`)
- **DPT/Flags tooltips**: hover on DPT or Flags cell for human-readable description

**Without project file (bus-only mode):**
- **Geräte** tab shows bus-derived devices (`busDevices` getter — unique `src` addresses from `liveLog`); names/descriptions editable inline
- **Gruppenadressen** tab shows bus-derived GAs (`busGAs` getter — unique `ga` addresses from `liveLog`); names/descriptions editable inline

#### Inline editing (bus-only tabs)
- `startEdit(type, key, field, current)` sets `editingKey = 'type|key|field'`
- `saveEdit()` parses the key, updates `annotations`, triggers reactivity via object spread, POSTs to `/api/annotations`

#### Bus-Monitor tab
- Real-time telegram table (Zeit, PA, Gerät, GA, GA-Name, Wert)
- Gerät column: `min-w-[180px]`; GA-Name column: `min-w-[220px]` (both truncate with title tooltip)
- Wert cell tooltip: `"DPT: x.xxx | Raw: ..."` (only when DPT known or raw ≠ decoded value)
- Filter input searches across all fields
- Pause/Resume button, Clear button, entry count
- Clicking a GA address navigates to Gruppenadressen tab

#### Export
- **With project**: `exportMarkdown()` / `exportPDF()` — full project data
- **Bus-only**: `_exportBusMarkdown()` / `_exportBusPDF()` — bus-derived devices + GAs with annotations

#### Cross-tab navigation
- CO tab row → `navigateToGA(co)`: switches to GA tab, sets `gaSearch`
- GA tab KO badge → `navigateToCO(coId)`: switches to KO tab, expands device section, highlights row yellow (`highlightedCO`)
- Devices tab "N KOs" link → `navigateToDeviceCOs(addr)`: switches to KO tab, expands device section
- Bus-Monitor GA click → switches to GA tab
- Devices tab KO row → `navigateToCO` via `$el.dataset.coKey` (data-attribute pattern to avoid Alpine.js nested x-for scope issues)

#### Gateway config modal
- ⚙ button in header opens modal; fields: IP address, port, language (select: de-DE / en-US)
- Saves all three via `POST /api/gateway`; language is used automatically on next `.knxproj` parse
- Closes with ESC or Cancel; language field on the upload form was removed in favour of this persistent setting

---

### Data flow

```
Upload .knxproj
  → POST /api/parse
  → xknxproject parses file
  → state["project_data"] + state["ga_dpt_map"] updated
  → xknx.group_address_dpt.set(ga_dpt_map)   ← DPT decoder registered
  → JSON returned to frontend → Alpine.js renders tabs

KNX telegram received
  → xknx decodes via group_address_dpt (if DPT known)
  → telegram_received_cb → _process_telegram
  → logs to knx_bus.log
  → current_values[ga] updated
  → telegram_buffer.append(entry)
  → broadcast to all WebSocket clients
  → frontend: currentValues updated, liveLog prepended
```

---

### xknxproject output structure (key field names)
The frontend is tightly coupled to these field names — mismatches were the source of most bugs:
- `project.devices` — flat dict keyed by `individual_address`; fields: `name`, `manufacturer_name`, `application`, `order_number`, `communication_object_ids`
- `project.topology` — dict keyed by area address string; `Area` has `name`, `lines` (dict keyed by line address string); `Line` has `name`, `devices` (list of address strings, **not** device objects)
- `project.communication_objects` — flat dict; fields: `name`, `number`, `device_address`, `dpts` (list), `flags` (nested: `read`, `write`, `transmit`, `update`, `communication`, `read_on_init`), `group_address_links`
- `project.group_addresses` — flat dict; fields: `address`, `name`, `dpt` (single object or null), `description`, `communication_object_ids`
- `project.functions` — dict; `group_addresses` field is a **dict** of `{id: {address, name, role}}`, not a list
- `project.info` — fields: `name` (not `project_name`), `tool_version` (not `project_version`)

### Key dependencies
- `xknxproject` — installed in editable mode from sibling directory `../xknxproject/`; handles all `.knxproj` parsing
- `xknx` — installed from PyPI; handles KNX/IP tunneling, telegram routing, and DPT decoding via `group_address_dpt`
- `websockets` — required by FastAPI for WebSocket support
