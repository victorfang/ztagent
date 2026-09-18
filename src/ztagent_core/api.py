# ZTAgent.ai : Zero Trust Security for AI Agents
# Author: VictorFang.com

"""FastAPI API gateway and protected administration API."""

from __future__ import annotations

from collections.abc import Awaitable, Callable
from typing import Any, Literal

from fastapi import Depends, FastAPI, HTTPException, Request
from fastapi.responses import HTMLResponse, JSONResponse
from pydantic import BaseModel, Field
from starlette.types import ASGIApp, Receive, Scope, Send
from starlette.types import Message as ASGIMessage

from .anomaly import AnomalyDetector
from .audit import AuditLog
from .auth import JWTAuthenticator
from .config import AppConfig, load_config
from .containment import ContainmentService
from .gateway import SecureAgentGateway, SecurityDenied
from .guardrails import SignatureScanner
from .models import AgentRequest, Message, Principal, SecurityEvent
from .policy import OPAClient
from .portal import ADMIN_HTML
from .providers import HTTPModelProvider, ProviderError
from .tools import ToolRegistry


class ToolCallRequest(BaseModel):
    arguments: dict[str, Any] = Field(default_factory=dict)


class PublicMessage(BaseModel):
    role: Literal["user"] = "user"
    content: str = Field(min_length=1, max_length=100_000)


class PublicAgentRequest(BaseModel):
    messages: list[PublicMessage] = Field(min_length=1, max_length=100)
    model: str | None = None
    tools: list[str] = Field(default_factory=list, max_length=32)
    metadata: dict[str, str] = Field(default_factory=dict)

    def trusted_request(self) -> AgentRequest:
        return AgentRequest(
            messages=[Message(role="user", content=item.content) for item in self.messages],
            model=self.model,
            tools=self.tools,
            metadata=self.metadata,
        )


class BodyLimitMiddleware:
    def __init__(self, app: ASGIApp, max_bytes: int) -> None:
        self.app = app
        self.max_bytes = max_bytes

    async def __call__(self, scope: Scope, receive: Receive, send: Send) -> None:
        if scope["type"] != "http":
            await self.app(scope, receive, send)
            return
        chunks: list[bytes] = []
        size = 0
        more_body = True
        while more_body:
            message = await receive()
            if message["type"] != "http.request":
                continue
            chunk = message.get("body", b"")
            size += len(chunk)
            if size > self.max_bytes:
                response = JSONResponse(
                    status_code=413,
                    content={"detail": "Request body too large"},
                )
                await response(scope, receive, send)
                return
            chunks.append(chunk)
            more_body = message.get("more_body", False)

        delivered = False

        async def replay_receive() -> ASGIMessage:
            nonlocal delivered
            if delivered:
                return {"type": "http.disconnect"}
            delivered = True
            return {"type": "http.request", "body": b"".join(chunks), "more_body": False}

        await self.app(scope, replay_receive, send)


def create_gateway(config: AppConfig, tools: ToolRegistry | None = None) -> SecureAgentGateway:
    config.validate_security()
    return SecureAgentGateway(
        config=config,
        provider=HTTPModelProvider(config.provider),
        scanner=SignatureScanner.from_file(
            config.guardrails.signatures_file, config.guardrails.regex_timeout_ms
        ),
        policy=OPAClient(config.policy),
        audit=AuditLog.from_env(
            config.audit.path, config.audit.hmac_key_env, config.audit.log_prompt_content
        ),
        anomaly=AnomalyDetector(config.anomaly),
        containment=ContainmentService(config.containment),
        tools=tools,
    )


def create_app(
    config: AppConfig | None = None, gateway: SecureAgentGateway | None = None
) -> FastAPI:
    cfg = config or load_config()
    cfg.validate_security()
    secured = gateway or create_gateway(cfg)
    authenticator = JWTAuthenticator(cfg.auth)
    app = FastAPI(
        title="ZTAgent",
        summary=(
            "Zero Trust Security for AI Agents. "
            "Never trust an agent action. Verify before execution."
        ),
        version="0.1.1",
        docs_url="/docs" if cfg.server.environment != "production" else None,
        redoc_url=None,
    )
    app.add_middleware(BodyLimitMiddleware, max_bytes=cfg.server.max_body_bytes)
    app.state.config = cfg
    app.state.gateway = secured

    async def principal(request: Request) -> Principal:
        return await authenticator(request)

    def require_admin(user: Principal = Depends(principal)) -> Principal:
        if not user.roles.intersection(cfg.server.admin_roles):
            raise HTTPException(status_code=403, detail="Administrator role required")
        return user

    @app.middleware("http")
    async def security_headers(
        request: Request, call_next: Callable[[Request], Awaitable[Any]]
    ) -> Any:
        response = await call_next(request)
        response.headers["X-Content-Type-Options"] = "nosniff"
        response.headers["X-Frame-Options"] = "DENY"
        response.headers["Referrer-Policy"] = "no-referrer"
        response.headers["Cache-Control"] = "no-store"
        response.headers["Content-Security-Policy"] = (
            "default-src 'self'; style-src 'unsafe-inline'; script-src 'unsafe-inline'"
        )
        return response

    @app.exception_handler(SecurityDenied)
    async def denied_handler(_: Request, exc: SecurityDenied) -> JSONResponse:
        return JSONResponse(
            status_code=403, content={"detail": exc.reason, "request_id": exc.request_id}
        )

    @app.exception_handler(ProviderError)
    async def provider_handler(_: Request, __: ProviderError) -> JSONResponse:
        return JSONResponse(status_code=502, content={"detail": "Model provider unavailable"})

    @app.get("/health")
    async def health() -> dict[str, str]:
        return {"status": "ok"}

    @app.post("/v1/agent/run")
    async def run_agent(
        body: PublicAgentRequest, request: Request, user: Principal = Depends(principal)
    ) -> Any:
        return await secured.run(body.trusted_request(), user, _source_ip(request))

    @app.post("/v1/tools/{tool_name}")
    async def execute_tool(
        tool_name: str,
        body: ToolCallRequest,
        request: Request,
        user: Principal = Depends(principal),
    ) -> Any:
        try:
            return await secured.execute_tool(tool_name, body.arguments, user, _source_ip(request))
        except ValueError as exc:
            raise HTTPException(status_code=404, detail=str(exc)) from exc

    @app.get("/admin", response_class=HTMLResponse)
    async def admin_portal() -> str:
        return ADMIN_HTML

    @app.get("/admin/api/summary")
    async def admin_summary(_: Principal = Depends(require_admin)) -> dict[str, Any]:
        events = secured.audit.read(500)
        return {
            "events": len(events),
            "blocked_events": sum(
                1 for item in events if item.get("event", {}).get("outcome") == "blocked"
            ),
            "contained_identities": len(secured.containment.blocklist.list()),
            "audit_chain_valid": secured.audit.verify()[0],
            "provider": cfg.provider.kind,
            "model": cfg.provider.model,
            "environment": cfg.server.environment,
        }

    @app.get("/admin/api/events")
    async def admin_events(
        limit: int = 100, _: Principal = Depends(require_admin)
    ) -> list[dict[str, Any]]:
        return secured.audit.read(max(1, min(limit, 500)))

    @app.get("/admin/api/identities")
    async def admin_identities(_: Principal = Depends(require_admin)) -> dict[str, Any]:
        return secured.containment.blocklist.list()

    @app.delete("/admin/api/identities/{subject}")
    async def unblock_identity(
        subject: str, user: Principal = Depends(require_admin)
    ) -> dict[str, Any]:
        intent = SecurityEvent(
            event_type="admin_identity_unblock",
            outcome="authorized",
            subject=user.subject,
            details={"target_subject": subject},
        )
        secured.audit.append(intent)
        unblocked = secured.containment.blocklist.unblock(subject)
        secured.audit.append(
            SecurityEvent(
                event_type="admin_identity_unblock",
                outcome="completed",
                subject=user.subject,
                details={"target_subject": subject, "unblocked": unblocked},
            )
        )
        return {"unblocked": unblocked}

    return app


def _source_ip(request: Request) -> str | None:
    # Only trust request.client. A deployment proxy must sanitize/translate forwarded headers.
    return request.client.host if request.client else None
