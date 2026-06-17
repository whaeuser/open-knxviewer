"""KI-Analyse: OpenRouter / lokales LLM (LM Studio, mlx-omni-server) streaming endpoints."""
import asyncio
import json

import httpx
from fastapi import APIRouter, HTTPException
from fastapi.responses import StreamingResponse

import core
from core import load_config, state
from models import LLMAnalyzeRequest, LLMCompareRequest, LLMConfigUpdate

router = APIRouter(prefix="/api/llm", tags=["llm"])

LLM_DEFAULT_MODEL = "z-ai/glm-5"
OPENROUTER_URL = "https://openrouter.ai/api/v1/chat/completions"
LOCAL_LLM_DEFAULT_URL = "http://localhost:1234/v1"


def _is_local_model(model: str) -> bool:
    return model == "local-model" or model.startswith("lm:")


def _local_llm_base() -> str:
    """Base URL of the local OpenAI-compatible server, without trailing slash."""
    url = (load_config().get("local_llm_url") or LOCAL_LLM_DEFAULT_URL).strip()
    return url.rstrip("/")


def _local_llm_headers() -> dict:
    """Headers for the local LLM; adds Bearer token if one is configured."""
    headers = {"Content-Type": "application/json"}
    token = (load_config().get("local_llm_token") or "").strip()
    if token:
        headers["Authorization"] = f"Bearer {token}"
    return headers


def _resolve_llm_target(model: str, api_key: str) -> tuple[str, dict, str]:
    """Return (url, headers, actual_model) for the configured model."""
    if _is_local_model(model):
        actual = model[3:] if model.startswith("lm:") else model
        return (
            f"{_local_llm_base()}/chat/completions",
            _local_llm_headers(),
            actual,
        )
    return (
        OPENROUTER_URL,
        {"Authorization": f"Bearer {api_key}", "Content-Type": "application/json"},
        model,
    )


def _build_bus_activity_summary(limit: int = 100) -> str:
    """Compact list of the most recent telegrams for LLM context."""
    buf = list(state.get("telegram_buffer") or [])
    if not buf:
        return "(Keine Bus-Telegramme im Puffer)"
    recent = buf[-limit:]
    lines = [f"Letzte {len(recent)} Bus-Telegramme (älteste zuerst):"]
    for e in recent:
        ts = (e.get("ts") or "").split(" ")[-1]  # just HH:MM:SS(.ms)
        src = e.get("src") or "?"
        ga = e.get("ga") or "?"
        ga_name = e.get("ga_name") or ""
        apci = e.get("apci") or ""
        value = e.get("value") if e.get("value") not in (None, "") else "-"
        ga_part = f"{ga} ({ga_name})" if ga_name else ga
        lines.append(f"  {ts}  {apci:<1}  {src} → {ga_part} = {value}")
    return "\n".join(lines)


def _build_project_summary(project_data: dict) -> str:
    """Build a compact text summary of a KNX project for LLM context."""
    lines = []
    info = project_data.get("info", {})
    lines.append(f"KNX-Projekt: {info.get('name', 'Unbekannt')}")
    lines.append(f"ETS-Version: {info.get('tool_version', '-')}")

    lines.append("\n## Topologie")
    for area_id, area in project_data.get("topology", {}).items():
        lines.append(f"  Bereich {area_id}: {area.get('name', '')}")
        for line_id, line in area.get("lines", {}).items():
            devs = line.get("devices", [])
            lines.append(
                f"    Linie {area_id}.{line_id}: {line.get('name', '')} ({len(devs)} Geräte)"
            )

    lines.append("\n## Geräte")
    for addr, dev in project_data.get("devices", {}).items():
        lines.append(
            f"  {addr}: {dev.get('name', '')} — {dev.get('manufacturer_name', '')} {dev.get('order_number', '')}"
        )

    lines.append("\n## Gruppenadressen")
    for _, ga in project_data.get("group_addresses", {}).items():
        dpt = ga.get("dpt")
        dpt_str = (
            f" [DPT {dpt['main']}.{str(dpt.get('sub') or 0).zfill(3)}]"
            if dpt and dpt.get("main")
            else ""
        )
        lines.append(f"  {ga.get('address', '')}: {ga.get('name', '')}{dpt_str}")

    funcs = project_data.get("functions", {})
    if funcs:
        lines.append("\n## Funktionen")
        for _, func in funcs.items():
            gas = [
                v.get("address", "")
                for v in (func.get("group_addresses") or {}).values()
            ]
            lines.append(f"  {func.get('name', '')}: {', '.join(gas)}")

    return "\n".join(lines)


def _stream_llm(url: str, headers: dict, payload: dict):
    """SSE generator proxying the upstream chat-completions stream."""

    async def stream():
        async with httpx.AsyncClient(timeout=60) as client:
            async with client.stream("POST", url, headers=headers, json=payload) as resp:
                if resp.status_code != 200:
                    body = await resp.aread()
                    yield f"data: {json.dumps({'error': body.decode()})}\n\n"
                    return
                async for line in resp.aiter_lines():
                    if line.startswith("data: "):
                        yield line + "\n\n"

    return StreamingResponse(stream(), media_type="text/event-stream")


@router.get("/lmstudio/models")
async def lmstudio_models():
    """Return models loaded in the local LLM server. 'local-model' is always first."""
    base = _local_llm_base()
    headers = _local_llm_headers()

    def _fetch():
        try:
            resp = httpx.get(f"{base}/models", headers=headers, timeout=3)
            ids = [m["id"] for m in resp.json().get("data", [])
                   if "embedding" not in m["id"].lower()]
            return {"available": True, "models": ["local-model"] + ids}
        except Exception:
            return {"available": False, "models": []}
    return await asyncio.to_thread(_fetch)


@router.get("/config")
def get_llm_config():
    cfg = load_config()
    key = cfg.get("openrouter_api_key", "")
    model = cfg.get("llm_model", LLM_DEFAULT_MODEL)
    return {
        "configured": bool(key) or _is_local_model(model),
        "model": model,
        "local_url": cfg.get("local_llm_url", LOCAL_LLM_DEFAULT_URL),
        "local_token_set": bool(cfg.get("local_llm_token", "")),
    }


@router.post("/config")
async def set_llm_config(data: LLMConfigUpdate):
    updates = {}
    if data.api_key is not None:
        updates["openrouter_api_key"] = data.api_key
    if data.model is not None:
        updates["llm_model"] = data.model or LLM_DEFAULT_MODEL
    if data.local_url is not None:
        updates["local_llm_url"] = data.local_url.strip() or LOCAL_LLM_DEFAULT_URL
    if data.local_token is not None:
        updates["local_llm_token"] = data.local_token.strip()
    core.update_config(updates)
    return {"ok": True}


def _require_llm_config() -> tuple[str, str]:
    cfg = load_config()
    api_key = cfg.get("openrouter_api_key", "")
    model = cfg.get("llm_model", LLM_DEFAULT_MODEL)
    if not api_key and not _is_local_model(model):
        raise HTTPException(
            status_code=400, detail="OpenRouter API-Key nicht konfiguriert"
        )
    return api_key, model


@router.post("/analyze")
async def llm_analyze(data: LLMAnalyzeRequest):
    api_key, model = _require_llm_config()
    question = (
        data.question.strip()
        or "Erkläre das Projekt, seine Topologie und die wichtigsten Gruppenadressen."
    )
    if not state["project_data"]:
        raise HTTPException(status_code=400, detail="Kein Projekt geladen")

    summary = _build_project_summary(state["project_data"])
    bus_section = ""
    if data.include_bus_activity:
        bus_section = "\n\n## Bus-Aktivität\n" + _build_bus_activity_summary(data.bus_limit)
    messages = [
        {
            "role": "system",
            "content": (
                "Du bist ein KNX-Experte. KNX ist ein offener Standard für Gebäudeautomation. "
                "Analysiere das folgende KNX-Projekt und beantworte Fragen dazu. "
                "Antworte auf Deutsch, präzise und strukturiert."
            ),
        },
    ]

    # Add project summary context only for the first message
    if not data.history:
        messages.append(
            {
                "role": "user",
                "content": f"Projektdaten:\n\n{summary}{bus_section}\n\nFrage: {question}",
            }
        )
    else:
        # Add project summary as context, then conversation history
        messages.append(
            {
                "role": "user",
                "content": f"Projektdaten:\n\n{summary}{bus_section}\n\nBeantworte Fragen zu diesem Projekt.",
            }
        )
        for msg in data.history:
            messages.append({"role": msg.role, "content": msg.content})
        messages.append({"role": "user", "content": question})

    url, headers, actual_model = _resolve_llm_target(model, api_key)
    return _stream_llm(url, headers, {"model": actual_model, "messages": messages, "stream": True})


@router.post("/compare")
async def llm_compare(data: LLMCompareRequest):
    api_key, model = _require_llm_config()
    diff_text = data.diff_text.strip()
    if not diff_text:
        raise HTTPException(status_code=400, detail="Kein Diff-Text übergeben")
    messages = [
        {
            "role": "system",
            "content": (
                "Du bist ein KNX-Experte. Analysiere die Unterschiede zwischen zwei KNX-Projekten "
                "und bewerte deren Auswirkungen. Hebe kritische Änderungen (DPT-Wechsel) besonders "
                "hervor. Antworte auf Deutsch, präzise und strukturiert."
            ),
        },
        {
            "role": "user",
            "content": (
                f"Vergleiche: Projekt A: {data.name_a} / Projekt B: {data.name_b}\n\n{diff_text}\n\n"
                "Erkläre die Auswirkungen, hebe kritische Änderungen hervor, nenne nötige Anpassungen."
            ),
        },
    ]

    url, headers, actual_model = _resolve_llm_target(model, api_key)
    return _stream_llm(url, headers, {"model": actual_model, "messages": messages, "stream": True})
