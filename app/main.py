import base64
import hashlib
import hmac
import json
import logging
import os
import secrets
import time
import uuid
from contextlib import asynccontextmanager
from datetime import datetime, timezone

from dotenv import load_dotenv
from fastapi import Cookie, FastAPI, Header, HTTPException, Request, Response
from fastapi.exceptions import RequestValidationError
from fastapi.responses import JSONResponse
from pydantic import BaseModel, ConfigDict, Field, IPvAnyAddress, field_validator, model_validator

load_dotenv()

from app.core_engine import (
    APP_ENV,
    INDEX_NAME,
    bootstrap_database,
    build_graph,
    execute_agent_query,
    ingest_log_events,
)

INGEST_API_KEY = os.getenv("ELASTICOPS_INGEST_API_KEY")
QUERY_API_KEY = os.getenv("ELASTICOPS_QUERY_API_KEY")
QUERY_USERNAME = os.getenv("ELASTICOPS_QUERY_USERNAME")
QUERY_PASSWORD = os.getenv("ELASTICOPS_QUERY_PASSWORD")
QUERY_SESSION_SECRET = os.getenv("ELASTICOPS_QUERY_SESSION_SECRET")
logger = logging.getLogger(__name__)


def _session_token() -> str:
    payload = {
        "issued_at": int(time.time()),
        "expires_at": int(time.time()) + 8 * 60 * 60,
        "session_id": secrets.token_urlsafe(32),
    }
    encoded_payload = base64.urlsafe_b64encode(json.dumps(payload).encode()).decode().rstrip("=")
    signature = hmac.new(
        (QUERY_SESSION_SECRET or "").encode(),
        encoded_payload.encode(),
        hashlib.sha256,
    ).digest()
    return f"{encoded_payload}.{base64.urlsafe_b64encode(signature).decode().rstrip('=')}"


def _valid_session(token: str | None) -> bool:
    if not token or not QUERY_SESSION_SECRET:
        return False
    try:
        encoded_payload, encoded_signature = token.split(".", 1)
        signature = base64.urlsafe_b64decode(encoded_signature + "=" * (-len(encoded_signature) % 4))
        expected_signature = hmac.new(
            QUERY_SESSION_SECRET.encode(),
            encoded_payload.encode(),
            hashlib.sha256,
        ).digest()
        if not hmac.compare_digest(signature, expected_signature):
            return False
        payload = json.loads(base64.urlsafe_b64decode(encoded_payload + "=" * (-len(encoded_payload) % 4)))
        return payload.get("expires_at", 0) > int(time.time())
    except (ValueError, TypeError, json.JSONDecodeError):
        return False


@asynccontextmanager
async def lifespan(app: FastAPI):
    bootstrap_database()
    app.state.graph = build_graph()
    yield


app = FastAPI(
    title="ElasticOps-Agent",
    description="Corporate security log audit, hybrid threat search, and compliance analytics",
    version="1.0.0",
    lifespan=lifespan,
)


@app.exception_handler(RequestValidationError)
async def validation_exception_handler(request: Request, exc: RequestValidationError) -> JSONResponse:
    request_id = str(uuid.uuid4())
    logger.warning("Invalid request %s: %s", request_id, exc.errors())
    return JSONResponse(
        status_code=422,
        content={
            "error": "validation_failed",
            "message": "The request data is invalid.",
            "request_id": request_id,
        },
    )


@app.exception_handler(Exception)
async def unexpected_exception_handler(request: Request, exc: Exception) -> JSONResponse:
    request_id = str(uuid.uuid4())
    logger.exception("Unhandled application error %s", request_id, exc_info=exc)
    return JSONResponse(
        status_code=500,
        content={
            "error": "internal_error",
            "message": "The request could not be completed.",
            "request_id": request_id,
        },
    )


class AgentQueryRequest(BaseModel):
    model_config = ConfigDict(extra="forbid")

    user_query: str = Field(..., min_length=3, max_length=5000)
    context: dict[str, str] = Field(default_factory=dict)


class LoginRequest(BaseModel):
    model_config = ConfigDict(extra="forbid")

    username: str = Field(..., min_length=1, max_length=128)
    password: str = Field(..., min_length=8, max_length=256)


class LogEventRequest(BaseModel):
    model_config = ConfigDict(extra="forbid")

    timestamp: datetime = Field(default_factory=lambda: datetime.now(timezone.utc))
    level: str | None = Field(default=None, max_length=20)
    severity: str | None = Field(default=None, max_length=20)
    service: str = Field(..., min_length=1, max_length=128)
    message: str | None = Field(default=None, max_length=20_000)
    log_message: str | None = Field(default=None, max_length=20_000)
    node: str | None = Field(default=None, max_length=128)
    host: str | None = Field(default=None, max_length=128)
    source_ip: IPvAnyAddress | None = None
    user_id: str | None = Field(default=None, max_length=256)
    target_resource: str | None = Field(default=None, max_length=512)
    environment: str | None = Field(default=None, max_length=64)
    status_code: int | None = Field(default=None, ge=100, le=599)
    latency_ms: float | None = Field(default=None, ge=0)
    trace_id: str | None = Field(default=None, max_length=256)

    @field_validator("timestamp")
    @classmethod
    def normalize_timestamp(cls, value: datetime) -> datetime:
        if value.tzinfo is None:
            return value.replace(tzinfo=timezone.utc)
        return value.astimezone(timezone.utc)

    @field_validator("level", "severity")
    @classmethod
    def normalize_level(cls, value: str | None) -> str | None:
        return value.strip().upper() if value else value

    @field_validator("service")
    @classmethod
    def trim_required_text(cls, value: str) -> str:
        normalized = value.strip()
        if not normalized:
            raise ValueError("value must not be blank")
        return normalized

    @model_validator(mode="after")
    def normalize_security_fields(self):
        severity = self.severity or self.level
        if not severity:
            raise ValueError("severity or level is required")
        message = (self.log_message or self.message or "").strip()
        if not message:
            raise ValueError("log_message or message is required")
        self.severity = severity
        self.level = severity
        self.log_message = message
        self.message = message
        return self


class LogIngestionRequest(BaseModel):
    model_config = ConfigDict(extra="forbid")

    events: list[LogEventRequest] = Field(..., min_length=1, max_length=100)


@app.get("/health")
async def health_check() -> dict:
    return {"status": "ok", "service": "elasticops-agent"}


@app.get("/api/v1/auth/status")
async def auth_status(
    elasticops_session: str | None = Cookie(default=None, alias="elasticops_session"),
) -> dict:
    is_production = APP_ENV in {"prod", "production"}
    configured = bool(QUERY_USERNAME and QUERY_PASSWORD and QUERY_SESSION_SECRET)
    requires_session = is_production and configured
    authenticated = not requires_session or _valid_session(elasticops_session)
    return {
        "authenticated": authenticated,
        "requires_session": requires_session,
        "configured": configured,
    }


@app.post("/api/v1/auth/login")
async def login(request: LoginRequest, response: Response) -> dict:
    is_production = APP_ENV in {"prod", "production"}
    if not is_production or not QUERY_USERNAME or not QUERY_PASSWORD or not QUERY_SESSION_SECRET:
        return {"authenticated": True, "message": "Development authentication is disabled"}
    if request.username != QUERY_USERNAME or not secrets.compare_digest(request.password, QUERY_PASSWORD):
        raise HTTPException(status_code=401, detail="Invalid username or password")
    response.set_cookie(
        "elasticops_session",
        _session_token(),
        httponly=True,
        secure=is_production,
        samesite="lax",
        max_age=8 * 60 * 60,
    )
    return {"authenticated": True, "message": "Session created"}


@app.post("/api/v1/agent/query")
async def agent_query(
    request: AgentQueryRequest,
    x_api_key: str | None = Header(default=None, alias="X-API-Key"),
    elasticops_session: str | None = Cookie(default=None, alias="elasticops_session"),
) -> dict:
    is_production = APP_ENV in {"prod", "production"}
    if is_production and not QUERY_API_KEY and not QUERY_USERNAME:
        raise HTTPException(status_code=503, detail="Production agent query requires an authentication configuration")

    if is_production:
        if QUERY_API_KEY and not secrets.compare_digest(x_api_key or "", QUERY_API_KEY):
            if not _valid_session(elasticops_session):
                raise HTTPException(status_code=401, detail="Invalid or missing query authentication")
        elif not QUERY_API_KEY and not _valid_session(elasticops_session):
            raise HTTPException(status_code=401, detail="Invalid or missing query session")

    graph = getattr(app.state, "graph", None)
    if graph is None:
        graph = build_graph()
    request_id = str(uuid.uuid4())

    try:
        result = execute_agent_query(
            request.user_query,
            graph=graph,
            context=request.context,
            request_id=request_id,
        )
    except Exception as exc:
        logger.exception("Agent query failed %s", request_id, exc_info=exc)
        return JSONResponse(
            status_code=502,
            content={
                "error": "agent_query_failed",
                "message": "The agent query could not be completed.",
                "request_id": request_id,
            },
        )

    result["trace"] = list(result.get("trace", []))
    result["trace"].insert(0, f"request_id={request_id}")
    logger.info(
        "Agent query completed request_id=%s route=%s intent=%s agent_execution=%s",
        request_id,
        result["route"],
        result["intent"],
        len(result.get("agent_execution", [])),
    )

    return {
        "request_id": request_id,
        "request": {"user_query": request.user_query, "context": request.context},
        "intent": result["intent"],
        "route": result["route"],
        "final_output": result["final_report"],
        "trace": result["trace"],
        "agent_execution": result.get("agent_execution", []),
        "payloads": {
            "supervisor": result["supervisor_payload"],
            "search": result["search_payload"],
            "analytics": result["analytics_payload"],
            "writer": result["writer_payload"],
        },
        "search_results": result["search_results"],
        "analytics": result["analytics"],
        "cluster_health": result["cluster_health"],
    }


@app.post("/api/v1/logs/ingest", status_code=202)
def ingest_logs(
    request: LogIngestionRequest,
    x_api_key: str | None = Header(default=None, alias="X-API-Key"),
) -> dict:
    is_production = APP_ENV in {"prod", "production"}
    if is_production and not INGEST_API_KEY:
        raise HTTPException(status_code=503, detail="Log ingestion requires ELASTICOPS_INGEST_API_KEY in production")
    if INGEST_API_KEY and not secrets.compare_digest(x_api_key or "", INGEST_API_KEY):
        raise HTTPException(status_code=401, detail="Invalid or missing ingestion API key")

    events = [event.model_dump(mode="json") for event in request.events]
    accepted = ingest_log_events(events)
    return {"accepted": accepted, "index": INDEX_NAME}
