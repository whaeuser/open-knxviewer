"""
Public read-only Open-KNXViewer — no bus monitor, no gateway connection.
Safe to expose to the internet.

Run with:
  .venv/bin/uvicorn server_public:app --host 0.0.0.0 --port 8004
"""
import os
import tempfile
from pathlib import Path

from fastapi import FastAPI, File, Form, HTTPException, Request, UploadFile
from fastapi.responses import FileResponse, JSONResponse
from slowapi import Limiter, _rate_limit_exceeded_handler
from slowapi.errors import RateLimitExceeded
from slowapi.util import get_remote_address
from starlette.middleware.base import BaseHTTPMiddleware

from xknxproject import XKNXProj
from xknxproject.exceptions import InvalidPasswordException, XknxProjectException
from xknxproject.zip.extractor import extract as knxproj_extract

INDEX_HTML = Path(__file__).parent / "index.html"
DEMO_PATH = Path(__file__).parent / "demo.knxproj"

MAX_UPLOAD_BYTES = 50 * 1024 * 1024  # 50 MB

limiter = Limiter(key_func=get_remote_address, default_limits=[])
app = FastAPI(title="Open-KNXViewer (Public)", docs_url=None, redoc_url=None)
app.state.limiter = limiter
app.add_exception_handler(RateLimitExceeded, _rate_limit_exceeded_handler)


class SecurityHeadersMiddleware(BaseHTTPMiddleware):
    async def dispatch(self, request: Request, call_next):
        response = await call_next(request)
        response.headers["X-Frame-Options"] = "DENY"
        response.headers["X-Content-Type-Options"] = "nosniff"
        response.headers["Referrer-Policy"] = "strict-origin-when-cross-origin"
        response.headers["Content-Security-Policy"] = (
            "default-src 'self'; "
            "script-src 'self' 'unsafe-inline' 'unsafe-eval' https://cdn.jsdelivr.net https://unpkg.com https://cdn.tailwindcss.com; "
            "style-src 'self' 'unsafe-inline' https://cdn.jsdelivr.net https://unpkg.com https://cdn.tailwindcss.com; "
            "img-src 'self' data:; "
            "connect-src 'self' https://cdn.tailwindcss.com; "
            "font-src 'self' data:; "
            "frame-ancestors 'none';"
        )
        return response


app.add_middleware(SecurityHeadersMiddleware)

_demo_cache = None


def _parse_ets_certificate(raw: str) -> dict:
    import re
    fields = {}
    for m in re.finditer(r'(\w+)=(?:"([^"]*)"|([\w+/=]+))', raw):
        fields[m.group(1)] = m.group(2) if m.group(2) is not None else m.group(3)
    return fields


def _extract_security_data(tmp_path: str, password: str, project: dict) -> dict:
    import re
    import xml.etree.ElementTree as ET
    import zipfile
    result: dict = {"devices": [], "ga_keys": {}, "ets_certificates": []}
    try:
        with knxproj_extract(tmp_path, password or None) as content:
            f = content.open_project_0()
            xml_str = f.read().decode("utf-8")

        ns_match = re.search(r'xmlns="([^"]+)"', xml_str)
        ns = ns_match.group(1) if ns_match else "http://knx.org/xml/project/21"
        root = ET.fromstring(xml_str)

        raw_to_addr: dict[int, str] = {
            ga["raw_address"]: ga["address"]
            for ga in project.get("group_addresses", {}).values()
        }

        for area in root.iter(f"{{{ns}}}Area"):
            area_addr = area.get("Address", "0")
            for line in area.iter(f"{{{ns}}}Line"):
                line_addr = line.get("Address", "0")
                for dev in line.iter(f"{{{ns}}}DeviceInstance"):
                    sec = dev.find(f"{{{ns}}}Security")
                    if sec is None:
                        continue
                    dev_addr = dev.get("Address", "0")
                    ia = f"{area_addr}.{line_addr}.{dev_addr}"
                    dev_info = project.get("devices", {}).get(ia, {})
                    ip_cfg = dev.find(f"{{{ns}}}IPConfig")
                    bus_ifaces = []
                    for bi in dev.iter(f"{{{ns}}}BusInterface"):
                        pwd = bi.get("Password")
                        if pwd:
                            bus_ifaces.append({"ref_id": bi.get("RefId", ""), "password": pwd})
                    result["devices"].append({
                        "address": ia,
                        "name": dev_info.get("name") or dev.get("Name") or "",
                        "ip_address": ip_cfg.get("IPAddress") if ip_cfg is not None else None,
                        "mac_address": ip_cfg.get("MACAddress") if ip_cfg is not None else None,
                        "tool_key": sec.get("ToolKey"),
                        "device_auth_code": sec.get("DeviceAuthenticationCode"),
                        "device_mgmt_password": sec.get("DeviceManagementPassword"),
                        "sequence_number": sec.get("SequenceNumber"),
                        "bus_interfaces": bus_ifaces or None,
                    })

        for ga_el in root.iter(f"{{{ns}}}GroupAddress"):
            key = ga_el.get("Key")
            if not key:
                continue
            raw = ga_el.get("Address")
            try:
                raw_int = int(raw) if raw is not None else None
            except ValueError:
                raw_int = None
            formatted = raw_to_addr.get(raw_int, raw or "")
            result["ga_keys"][formatted] = key

        with zipfile.ZipFile(tmp_path) as zf:
            for name in zf.namelist():
                if name.endswith(".certificate"):
                    raw = zf.read(name).decode("utf-8", errors="replace")
                    cert = _parse_ets_certificate(raw)
                    if cert:
                        result["ets_certificates"].append(cert)

    except Exception:
        pass
    return result


@app.get("/.well-known/appspecific/com.chrome.devtools.json", include_in_schema=False)
async def chrome_devtools():
    return {}


@app.get("/api/mode")
def get_mode():
    return {"public": True}


@app.get("/")
async def root():
    return FileResponse(INDEX_HTML)


@app.get("/api/demo/available")
def demo_available():
    return {"available": DEMO_PATH.exists()}


@app.get("/api/demo")
async def get_demo():
    global _demo_cache
    if not DEMO_PATH.exists():
        raise HTTPException(status_code=404, detail="Demo nicht verfügbar")
    if _demo_cache is None:
        try:
            _demo_cache = XKNXProj(path=str(DEMO_PATH)).parse()
        except Exception as exc:
            raise HTTPException(status_code=500, detail=f"Demo konnte nicht geladen werden: {exc}") from exc
    return JSONResponse(content=_demo_cache)


@app.post("/api/parse")
@limiter.limit("5/minute")
async def parse_project(
    request: Request,
    file: UploadFile = File(...),
    password: str = Form(default=""),
    language: str = Form(default="de-DE"),
):
    # 4. Dateiendung validieren
    suffix = Path(file.filename or "project.knxproj").suffix.lower()
    if suffix != ".knxproj":
        raise HTTPException(status_code=400, detail="Nur .knxproj-Dateien sind erlaubt.")

    # 1. Dateigröße begrenzen
    data = await file.read(MAX_UPLOAD_BYTES + 1)
    if len(data) > MAX_UPLOAD_BYTES:
        raise HTTPException(status_code=413, detail="Datei zu groß (max. 50 MB).")

    with tempfile.NamedTemporaryFile(delete=False, suffix=".knxproj", mode="wb") as tmp:
        tmp.write(data)
        tmp_path = tmp.name

    try:
        kwargs: dict = {"path": tmp_path}
        if password:
            kwargs["password"] = password
        if language:
            kwargs["language"] = language

        project = XKNXProj(**kwargs).parse()
        project["_security"] = _extract_security_data(tmp_path, password, project)
        return JSONResponse(content=project)
    except InvalidPasswordException as exc:
        raise HTTPException(status_code=422, detail=f"Invalid password: {exc}") from exc
    except XknxProjectException as exc:
        raise HTTPException(status_code=500, detail=str(exc)) from exc
    except Exception as exc:
        raise HTTPException(status_code=500, detail=f"Parsing failed: {exc}") from exc
    finally:
        os.unlink(tmp_path)
