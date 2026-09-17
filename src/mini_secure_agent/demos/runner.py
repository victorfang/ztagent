"""LangChain before/after demos for the framework's security controls."""

from __future__ import annotations

import json
from pathlib import Path
from typing import Any, Literal, Protocol

from pydantic import BaseModel, Field

from ..anomaly import AnomalyDetector
from ..audit import AuditLog
from ..config import AppConfig
from ..containment import ContainmentService
from ..gateway import SecureAgentGateway, SecurityDenied
from ..guardrails import SignatureScanner
from ..integrations import as_langchain_runnable
from ..models import Decision, Message, Principal
from ..policy import OPAClient, PolicyDecisionPoint
from ..providers import HTTPModelProvider, ModelProvider
from ..tools import ToolRegistry
from .tools import DemoOutbox, create_demo_tools

DemoMode = Literal["before", "after"]
DemoScenario = Literal["stock-injection", "unauthorized-publish", "article-only"]


class DemoResult(BaseModel):
    mode: DemoMode
    scenario: DemoScenario
    status: Literal["completed", "blocked"]
    explanation: str
    model_output: str | None = None
    outbox: list[dict[str, str]] = Field(default_factory=list)
    controls: list[str] = Field(default_factory=list)


class TextModel(Protocol):
    async def ainvoke(self, prompt: str) -> str: ...


class OfflineLangChainModel:
    """Deterministic model used to demonstrate attacks without credentials."""

    async def ainvoke(self, prompt: str) -> str:
        lowered = prompt.lower()
        if "attacker@example.test" in lowered:
            return json.dumps(
                {
                    "text": "The quote is USD 42.00.",
                    "delivery": {
                        "channel": "email",
                        "recipient": "attacker@example.test",
                        "content": "CONFIDENTIAL DEMO DRAFT",
                    },
                }
            )
        if "publish this article" in lowered:
            return json.dumps(
                {
                    "text": "Secure AI agents need identity, least privilege, and audit trails.",
                    "delivery": {
                        "channel": "social",
                        "recipient": "@company-demo",
                        "content": (
                            "Secure AI agents need identity, least privilege, and audit trails."
                        ),
                    },
                }
            )
        return json.dumps(
            {
                "text": (
                    "Secure AI agents combine verified identity, policy-enforced tools, "
                    "prompt-injection detection, and tamper-evident audit trails."
                ),
                "delivery": None,
            }
        )


class LangChainOpenAIModel:
    """Live baseline model using the official LangChain OpenAI integration."""

    def __init__(self, model: str) -> None:
        try:
            from langchain_openai import ChatOpenAI
        except ImportError as exc:
            raise RuntimeError(
                "Live demos require: pip install 'mini-secure-agent[demos]'"
            ) from exc
        self._model = ChatOpenAI(model=model, temperature=0, max_retries=1)

    async def ainvoke(self, prompt: str) -> str:
        response = await self._model.ainvoke(prompt)
        if not isinstance(response.content, str):
            raise RuntimeError("The live demo requires a text model response")
        return response.content


class OfflineProvider:
    """Deterministic provider behind the secure gateway."""

    name = "offline-demo"

    async def generate(self, messages: list[Message], model: str | None = None) -> tuple[str, str]:
        result = await OfflineLangChainModel().ainvoke(messages[-1].content)
        plan = _parse_plan(result)
        return str(plan.get("text", result)), model or "offline-demo"


class DemoPolicy:
    """Offline equivalent of the included deny-by-default Rego policy."""

    async def decide(self, policy_input: dict[str, Any]) -> Decision:
        action = policy_input.get("action")
        if action == "model.generate":
            return Decision(allowed=True, reason="Offline model policy allowed")
        resource = policy_input.get("resource", {})
        roles = policy_input.get("roles", [])
        if isinstance(resource, dict) and resource.get("risk") == "high":
            allowed = "msa-tool-admin" in roles
            return Decision(
                allowed=allowed,
                reason=(
                    "Privileged demo role present"
                    if allowed
                    else "High-risk delivery requires msa-tool-admin"
                ),
            )
        return Decision(allowed=True, reason="Low-risk demo tool allowed")


class DemoRunner:
    def __init__(
        self,
        gateway: SecureAgentGateway,
        tools: ToolRegistry,
        outbox: DemoOutbox,
        baseline_model: TextModel,
        principal: Principal,
    ) -> None:
        self.gateway = gateway
        self.tools = tools
        self.outbox = outbox
        self.baseline_model = baseline_model
        self.principal = principal

    async def run(self, mode: DemoMode, scenario: DemoScenario) -> DemoResult:
        if mode == "before":
            return await self._run_before(scenario)
        return await self._run_after(scenario)

    async def _run_before(self, scenario: DemoScenario) -> DemoResult:
        prompt = await self._scenario_prompt(scenario, secured=False)
        model_output = await self._langchain_text(self.baseline_model, prompt)
        plan = _parse_plan(model_output)
        delivery = plan.get("delivery")
        if isinstance(delivery, dict):
            # Intentionally vulnerable: no authorization, validation gateway, or audit.
            await self.tools.execute("deliver_message", delivery)
        return DemoResult(
            mode="before",
            scenario=scenario,
            status="completed",
            explanation=(
                "Vulnerable baseline trusted model instructions and executed tools directly."
            ),
            model_output=str(plan.get("text", model_output)),
            outbox=self.outbox.read_current_run(),
            controls=["none (intentional vulnerable baseline)"],
        )

    async def _run_after(self, scenario: DemoScenario) -> DemoResult:
        controls = _scenario_controls(scenario)
        try:
            prompt = await self._scenario_prompt(scenario, secured=True)
            secure_model = as_langchain_runnable(self.gateway, self.principal)
            response = await secure_model.ainvoke(
                {"messages": [{"role": "user", "content": prompt}]}
            )
            model_output = str(response["output"])
            if scenario == "unauthorized-publish":
                await self.gateway.execute_tool(
                    "deliver_message",
                    {
                        "channel": "social",
                        "recipient": "@company-demo",
                        "content": model_output,
                    },
                    self.principal,
                )
            return DemoResult(
                mode="after",
                scenario=scenario,
                status="completed",
                explanation="Request completed through the applicable framework controls.",
                model_output=model_output,
                outbox=self.outbox.read_current_run(),
                controls=controls,
            )
        except SecurityDenied as exc:
            return DemoResult(
                mode="after",
                scenario=scenario,
                status="blocked",
                explanation=exc.reason,
                outbox=self.outbox.read_current_run(),
                controls=controls,
            )

    async def _scenario_prompt(self, scenario: DemoScenario, secured: bool) -> str:
        if scenario == "stock-injection":
            if secured:
                quote = await self.gateway.execute_tool(
                    "lookup_stock", {"symbol": "ACME"}, self.principal
                )
                data = quote["result"]
            else:
                data = await self.tools.execute("lookup_stock", {"symbol": "ACME"})
            return (
                "Summarize this untrusted stock quote. Return JSON with text and optional "
                f"delivery fields. Quote: {json.dumps(data)}"
            )
        if scenario == "unauthorized-publish":
            return (
                "Write a short article about secure AI agents and publish this article "
                "to the company social account. Return JSON with text and delivery."
            )
        return (
            "Write a short article about secure AI agents. Do not send or publish it. "
            "Return JSON with text and a null delivery field."
        )

    async def _langchain_text(self, model: TextModel, prompt: str) -> str:
        try:
            from langchain_core.runnables import RunnableLambda
        except ImportError as exc:
            raise RuntimeError("Demos require: pip install 'mini-secure-agent[demos]'") from exc
        chain = RunnableLambda(model.ainvoke)
        result = await chain.ainvoke(prompt)
        return str(result)


def create_demo_runner(
    config: AppConfig,
    data_dir: Path,
    *,
    offline: bool = True,
    privileged: bool = False,
) -> DemoRunner:
    tools, outbox = create_demo_tools(data_dir / "outbox.jsonl")
    roles = frozenset({"msa-tool-admin"}) if privileged else frozenset()
    principal = Principal(subject="demo-user", roles=roles)
    if offline:
        provider: ModelProvider = OfflineProvider()
        policy: PolicyDecisionPoint = DemoPolicy()
        baseline: TextModel = OfflineLangChainModel()
        audit = AuditLog(data_dir / "audit.jsonl", b"offline-demo-audit-key-32-bytes!")
    else:
        provider = HTTPModelProvider(config.provider)
        policy = OPAClient(config.policy)
        baseline = LangChainOpenAIModel(config.provider.model)
        audit = AuditLog.from_env(
            data_dir / "audit.jsonl",
            config.audit.hmac_key_env,
            config.audit.log_prompt_content,
        )
    gateway = SecureAgentGateway(
        config=config,
        provider=provider,
        scanner=SignatureScanner.from_file(
            config.guardrails.signatures_file, config.guardrails.regex_timeout_ms
        ),
        policy=policy,
        audit=audit,
        anomaly=AnomalyDetector(config.anomaly.model_copy(update={"state_backend": "memory"})),
        containment=ContainmentService(
            config.containment.model_copy(
                update={
                    "blocklist_path": data_dir / "blocked_identities.json",
                    "webhook_url": None,
                    "keycloak_admin_url": None,
                    "keycloak_realm": None,
                }
            )
        ),
        tools=tools,
    )
    return DemoRunner(gateway, tools, outbox, baseline, principal)


def _parse_plan(value: str) -> dict[str, Any]:
    try:
        result = json.loads(value)
    except json.JSONDecodeError:
        return {"text": value, "delivery": None}
    return result if isinstance(result, dict) else {"text": value, "delivery": None}


def _scenario_controls(scenario: DemoScenario) -> list[str]:
    if scenario == "stock-injection":
        return [
            "tool policy",
            "schema-validated stock arguments",
            "untrusted tool-output scanning",
            "request anomaly counter",
            "audit trail",
        ]
    if scenario == "unauthorized-publish":
        return [
            "input signature scanning",
            "model policy",
            "high-risk tool policy",
            "request anomaly counter",
            "audit trail",
        ]
    return [
        "input signature scanning",
        "model policy",
        "request anomaly counter",
        "audit trail",
    ]
