# Author: Victor Fang
# Website: https://VictorFang.com
# X: https://X.com/vicfcs
# LinkedIn: https://www.linkedin.com/in/drvictorfang

"""Central policy-enforcement pipeline for model and tool calls."""

from __future__ import annotations

import json
from typing import Any
from uuid import uuid4

from .anomaly import AnomalyDetector
from .audit import AuditLog
from .config import AppConfig
from .containment import ContainmentService
from .guardrails import SignatureScanner
from .models import AgentRequest, AgentResponse, Detection, Principal, SecurityEvent
from .policy import PolicyDecisionPoint
from .providers import ModelProvider
from .tools import ToolRegistry


class SecurityDenied(RuntimeError):
    def __init__(self, reason: str, request_id: str) -> None:
        super().__init__(reason)
        self.reason = reason
        self.request_id = request_id


class SecureAgentGateway:
    def __init__(
        self,
        config: AppConfig,
        provider: ModelProvider,
        scanner: SignatureScanner,
        policy: PolicyDecisionPoint,
        audit: AuditLog,
        anomaly: AnomalyDetector,
        containment: ContainmentService,
        tools: ToolRegistry | None = None,
    ) -> None:
        self.config = config
        self.provider = provider
        self.scanner = scanner
        self.policy = policy
        self.audit = audit
        self.anomaly = anomaly
        self.containment = containment
        self.tools = tools or ToolRegistry()

    async def run(
        self, request: AgentRequest, principal: Principal, source_ip: str | None = None
    ) -> AgentResponse:
        request_id = str(uuid4())
        self._ensure_not_contained(principal, request_id)
        prompt = "\n".join(message.content for message in request.messages)
        if len(prompt) > self.config.guardrails.max_prompt_chars:
            await self._deny(
                principal,
                request_id,
                source_ip,
                [
                    Detection(
                        rule_id="gateway.prompt-size",
                        category="resource-abuse",
                        severity="high",
                        action="block",
                        score=100,
                        detail="Combined prompt exceeds configured size limit",
                    )
                ],
            )
        findings = self.scanner.inspect(
            "model_input",
            prompt,
            request_id=request_id,
            subject=principal.subject,
            resource={
                "provider": self.provider.name,
                "model": request.model or self.config.provider.model,
            },
        )
        findings.extend(
            self.anomaly.observe_request(principal.subject, len(request.messages), len(prompt))
        )
        if self._must_block(findings):
            await self._deny(principal, request_id, source_ip, findings)

        decision = await self.policy.decide(
            {
                "action": "model.generate",
                "subject": principal.subject,
                "roles": sorted(principal.roles),
                "resource": {
                    "provider": self.provider.name,
                    "model": request.model or self.config.provider.model,
                    "tools": request.tools,
                },
                "context": {"source_ip": source_ip, "request_id": request_id},
            }
        )
        if not decision.allowed:
            await self._deny_reason(principal, request_id, source_ip, decision.reason, "policy")

        try:
            output, model = await self.provider.generate(request.messages, request.model)
        except Exception as exc:
            self._audit(
                "model_call",
                "error",
                principal,
                request_id,
                source_ip,
                {"error_type": type(exc).__name__},
            )
            raise
        output_findings = self.scanner.inspect(
            "model_output",
            output,
            request_id=request_id,
            subject=principal.subject,
            resource={"provider": self.provider.name, "model": model},
        )
        if self._must_block(output_findings):
            self._audit(
                "model_output_detection",
                "blocked",
                principal,
                request_id,
                source_ip,
                {"detections": [item.model_dump() for item in output_findings]},
            )
            raise SecurityDenied("Model output blocked by security controls", request_id)
        self._audit(
            "model_call",
            "allowed",
            principal,
            request_id,
            source_ip,
            {
                "provider": self.provider.name,
                "model": model,
                "input_chars": len(prompt),
                "output_chars": len(output),
                "detections_logged": [
                    item.rule_id for item in [*findings, *output_findings]
                ],
                "policy_decision_id": decision.decision_id,
            },
        )
        return AgentResponse(
            request_id=request_id, output=output, model=model, provider=self.provider.name
        )

    async def execute_tool(
        self,
        name: str,
        arguments: dict[str, Any],
        principal: Principal,
        source_ip: str | None = None,
    ) -> Any:
        request_id = str(uuid4())
        self._ensure_not_contained(principal, request_id)
        spec = self.tools.get(name)
        argument_text = json.dumps(arguments, default=str)
        findings = self.scanner.inspect(
            "tool_input",
            argument_text,
            request_id=request_id,
            subject=principal.subject,
            resource={"tool": name, "risk": spec.risk},
        )
        findings.extend(self.anomaly.observe_request(principal.subject, 1, len(argument_text)))
        if self._must_block(findings):
            await self._deny(principal, request_id, source_ip, findings)
        decision = await self.policy.decide(
            {
                "action": "tool.execute",
                "subject": principal.subject,
                "roles": sorted(principal.roles),
                "resource": {"tool": name, "risk": spec.risk},
                "context": {"source_ip": source_ip, "request_id": request_id},
            }
        )
        if not decision.allowed:
            await self._deny_reason(principal, request_id, source_ip, decision.reason, "policy")
        self._audit(
            "tool_call_intent",
            "authorized",
            principal,
            request_id,
            source_ip,
            {"tool": name, "risk": spec.risk},
        )
        try:
            result = await self.tools.execute(name, arguments)
        except Exception as exc:
            self._audit(
                "tool_call",
                "error",
                principal,
                request_id,
                source_ip,
                {"tool": name, "error_type": type(exc).__name__},
            )
            raise
        output_findings = self.scanner.inspect(
            "tool_output",
            json.dumps(result, default=str),
            request_id=request_id,
            subject=principal.subject,
            resource={"tool": name, "risk": spec.risk},
        )
        if self._must_block(output_findings):
            self._audit(
                "tool_output_detection",
                "blocked",
                principal,
                request_id,
                source_ip,
                {
                    "tool": name,
                    "detections": [item.model_dump() for item in output_findings],
                },
            )
            raise SecurityDenied("Untrusted tool output blocked by security controls", request_id)
        self._audit(
            "tool_call",
            "allowed",
            principal,
            request_id,
            source_ip,
            {"tool": name, "risk": spec.risk},
        )
        return {"request_id": request_id, "result": result}

    def _must_block(self, findings: list[Detection]) -> bool:
        return (
            any(item.action in {"block", "contain"} for item in findings)
            or sum(item.score for item in findings) >= self.config.guardrails.block_score
        )

    def _ensure_not_contained(self, principal: Principal, request_id: str) -> None:
        if self.containment.blocklist.contains(principal.subject):
            raise SecurityDenied("Identity is contained", request_id)

    async def _deny(
        self,
        principal: Principal,
        request_id: str,
        source_ip: str | None,
        findings: list[Detection],
    ) -> None:
        repeated = self.anomaly.observe_block(principal.subject)
        all_findings = findings + repeated
        should_contain = any(item.action == "contain" for item in all_findings)
        details: dict[str, Any] = {
            "detections": [item.model_dump() for item in all_findings],
            "contained": should_contain,
        }
        event = SecurityEvent(
            event_type="security_detection",
            outcome="blocked",
            subject=principal.subject,
            request_id=request_id,
            source_ip=source_ip,
            details=details,
        )
        if should_contain:
            details["containment_actions"] = await self.containment.contain(
                principal.subject,
                ", ".join(item.rule_id for item in all_findings),
                event.event_id,
            )
        self.audit.append(event)
        raise SecurityDenied("Request blocked by security controls", request_id)

    async def _deny_reason(
        self,
        principal: Principal,
        request_id: str,
        source_ip: str | None,
        reason: str,
        category: str,
    ) -> None:
        self._audit(
            "access_decision",
            "denied",
            principal,
            request_id,
            source_ip,
            {"category": category, "reason": reason},
        )
        raise SecurityDenied(reason, request_id)

    def _audit(
        self,
        event_type: str,
        outcome: str,
        principal: Principal,
        request_id: str,
        source_ip: str | None,
        details: dict[str, Any],
    ) -> SecurityEvent:
        event = SecurityEvent(
            event_type=event_type,
            outcome=outcome,
            subject=principal.subject,
            request_id=request_id,
            source_ip=source_ip,
            details=details,
        )
        self.audit.append(event)
        return event
