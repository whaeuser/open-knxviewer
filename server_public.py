"""
Public read-only Open-KNXViewer — no bus monitor, no gateway connection.
Safe to expose to the internet.

Run with:
  .venv/bin/uvicorn server_public:app --host 0.0.0.0 --port 8004
"""
import asyncio
import io
import logging
import os
import tempfile
import time
from datetime import datetime
from logging.handlers import TimedRotatingFileHandler
from pathlib import Path

from fastapi import Body, FastAPI, File, Form, HTTPException, Request, UploadFile
from fastapi.responses import FileResponse, JSONResponse, StreamingResponse
from fastapi.staticfiles import StaticFiles
from slowapi import Limiter, _rate_limit_exceeded_handler
from slowapi.errors import RateLimitExceeded
from slowapi.util import get_remote_address
from starlette.middleware.base import BaseHTTPMiddleware

from xknxproject import XKNXProj
from xknxproject.exceptions import InvalidPasswordException, XknxProjectException

import common

INDEX_HTML = Path(__file__).parent / "index.html"
STATIC_DIR = Path(__file__).parent / "static"
DEMO_PATH = Path(__file__).parent / "demo.knxproj"
ACCESS_LOG = Path(__file__).parent / "logs" / "access_public.log"

MAX_UPLOAD_BYTES = 200 * 1024 * 1024  # 200 MB

# IPs, die nicht ins Access-Log geschrieben werden (z.B. Monitoring)
ACCESS_LOG_SKIP_IPS = {"172.18.0.1"}

# ── Access-Logger ─────────────────────────────────────────────────────────────
ACCESS_LOG.parent.mkdir(exist_ok=True)
_access_handler = TimedRotatingFileHandler(
    ACCESS_LOG, when="midnight", backupCount=30, encoding="utf-8"
)
_access_handler.setFormatter(logging.Formatter("%(message)s"))
access_log = logging.getLogger("access_public")
access_log.setLevel(logging.INFO)
access_log.addHandler(_access_handler)
access_log.propagate = False

limiter = Limiter(key_func=get_remote_address, default_limits=[])
app = FastAPI(title="Open-KNXViewer (Public)", docs_url=None, redoc_url=None)
app.state.limiter = limiter
app.add_exception_handler(RateLimitExceeded, _rate_limit_exceeded_handler)


class SecurityHeadersMiddleware(BaseHTTPMiddleware):
    async def dispatch(self, request: Request, call_next):
        response = await call_next(request)
        response.headers["X-Content-Type-Options"] = "nosniff"
        response.headers["Referrer-Policy"] = "strict-origin-when-cross-origin"
        response.headers["Content-Security-Policy"] = (
            "default-src 'self'; "
            "script-src 'self' 'unsafe-inline' 'unsafe-eval'; "
            "style-src 'self' 'unsafe-inline' https://fonts.googleapis.com; "
            "img-src 'self' data:; "
            "connect-src 'self'; "
            "font-src 'self' data: https://fonts.gstatic.com; "
            "frame-ancestors https://volt-logik.io https://*.volt-logik.io https://portal.nurdaheim.net https://*.nurdaheim.net;"
        )
        return response


class AccessLogMiddleware(BaseHTTPMiddleware):
    async def dispatch(self, request: Request, call_next):
        start = time.monotonic()
        response = await call_next(request)
        duration = time.monotonic() - start
        ip = request.headers.get("x-forwarded-for", request.client.host if request.client else "-").split(",")[0].strip()
        if ip in ACCESS_LOG_SKIP_IPS:
            return response
        ts = datetime.now().strftime("%Y-%m-%d %H:%M:%S")
        access_log.info("%s | %s | %s | %s | %s | %.3fs",
                        ts, ip, request.method, request.url.path,
                        response.status_code, duration)
        return response


app.add_middleware(SecurityHeadersMiddleware)
app.add_middleware(AccessLogMiddleware)

if STATIC_DIR.is_dir():
    app.mount("/static", StaticFiles(directory=str(STATIC_DIR)), name="static")

_demo_cache = None


@app.get("/.well-known/appspecific/com.chrome.devtools.json", include_in_schema=False)
async def chrome_devtools():
    return {}


@app.get("/api/mode")
def get_mode(request: Request):
    host = request.headers.get("x-forwarded-host") or request.headers.get("host", "")
    if "volt-logik" in host:
        theme = "voltlogik"
        branding = "voltlogik"
    else:
        theme = os.environ.get("OPENKNXVIEWER_THEME", "default").strip().lower()
        if theme not in ("default", "voltlogik"):
            theme = "default"
        branding = None
    return {"public": True, "default_theme": theme, "branding": branding}


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
            _demo_cache = await asyncio.to_thread(XKNXProj(path=str(DEMO_PATH)).parse)
        except Exception as exc:
            raise HTTPException(status_code=500, detail=f"Demo konnte nicht geladen werden: {exc}") from exc
    return JSONResponse(content=_demo_cache)


# ── XLSX export (client supplies project) ────────────────────────────────────

@app.post("/api/export/xlsx")
@limiter.limit("10/minute")
async def export_xlsx_public(request: Request, project: dict = Body(...)):
    if not project or not isinstance(project, dict):
        raise HTTPException(status_code=400, detail="Kein Projekt übergeben")
    xlsx_bytes = await asyncio.to_thread(common.build_project_xlsx, project)
    return StreamingResponse(
        io.BytesIO(xlsx_bytes),
        media_type="application/vnd.openxmlformats-officedocument.spreadsheetml.sheet",
        headers={"Content-Disposition": f'attachment; filename="{common.xlsx_filename(project)}"'},
    )


@app.post("/api/parse")
@limiter.limit("5/minute")
async def parse_project(
    request: Request,
    file: UploadFile = File(...),
    password: str = Form(default=""),
    language: str = Form(default="de-DE"),
):
    # 4. Dateiendung validieren
    filename = (file.filename or "").strip()
    if not filename.lower().endswith(".knxproj"):
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

        # Parsing is CPU-bound — run it off the event loop so other
        # requests keep being served.
        project = await asyncio.to_thread(lambda: XKNXProj(**kwargs).parse())
        project["_security"] = await asyncio.to_thread(
            common.extract_security_data, tmp_path, password, project
        )
        return JSONResponse(content=project)
    except InvalidPasswordException as exc:
        raise HTTPException(status_code=422, detail=f"Invalid password: {exc}") from exc
    except XknxProjectException as exc:
        raise HTTPException(status_code=500, detail=str(exc)) from exc
    except Exception as exc:
        raise HTTPException(status_code=500, detail=f"Parsing failed: {exc}") from exc
    finally:
        os.unlink(tmp_path)
