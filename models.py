"""Pydantic request models for the private server API."""
from pydantic import BaseModel, ConfigDict, Field


class GatewayUpdate(BaseModel):
    ip: str | None = None
    port: int | None = Field(default=None, ge=1, le=65535)
    language: str | None = None
    connection_type: str | None = Field(default=None, pattern="^(local|remote_gateway)$")


class NotesUpdate(BaseModel):
    text: str = ""


class SnapshotCreate(BaseModel):
    name: str = ""


class GAWrite(BaseModel):
    ga: str
    value: str | float | int | bool = ""


class GARead(BaseModel):
    ga: str


class GAScanRequest(BaseModel):
    start: str = "0/0/1"
    end: str = "5/7/255"
    delay_ms: int = 100


class BusScanRequest(BaseModel):
    area: int | None = Field(default=None, ge=0, le=15)
    line: int | None = Field(default=None, ge=0, le=15)
    device: int | None = Field(default=None, ge=0, le=255)
    timeout_ms: int = 1500


class WGSetup(BaseModel):
    model_config = ConfigDict(extra="ignore")

    server_ip: str | None = None
    peer_ip: str | None = None
    listen_port: int | None = None
    ets_port: int | None = None
    knx_ip: str | None = None
    knx_port: int | None = None


class WGPeer(BaseModel):
    public_key: str = ""


class WGEtsAccess(BaseModel):
    enable: bool = False


class LLMConfigUpdate(BaseModel):
    api_key: str | None = None
    model: str | None = None
    local_url: str | None = None
    local_token: str | None = None


class LLMMessage(BaseModel):
    role: str = Field(pattern="^(user|assistant)$")
    content: str


class LLMAnalyzeRequest(BaseModel):
    question: str = ""
    history: list[LLMMessage] = []
    include_bus_activity: bool = False
    bus_limit: int = Field(default=100, ge=1, le=500)


class LLMCompareRequest(BaseModel):
    diff_text: str = ""
    name_a: str = "Projekt A"
    name_b: str = "Projekt B"
