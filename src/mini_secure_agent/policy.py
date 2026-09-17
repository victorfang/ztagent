"""OPA policy decision point client; the gateway acts as enforcement point."""

from __future__ import annotations

from typing import Any

import httpx

from .config import PolicyConfig
from .models import Decision


class OPAClient:
    def __init__(self, config: PolicyConfig) -> None:
        self.config = config
        path = config.decision_path.strip("/")
        self.url = f"{config.opa_url.rstrip('/')}/v1/data/{path}"

    async def decide(self, policy_input: dict[str, Any]) -> Decision:
        try:
            async with httpx.AsyncClient(timeout=self.config.timeout_seconds) as client:
                response = await client.post(self.url, json={"input": policy_input})
                response.raise_for_status()
                payload = response.json()
            result = payload.get("result")
            if isinstance(result, bool):
                return Decision(
                    allowed=result,
                    reason="OPA allowed request" if result else "OPA denied request",
                    decision_id=payload.get("decision_id"),
                )
            if isinstance(result, dict) and isinstance(result.get("allow"), bool):
                return Decision(
                    allowed=result["allow"],
                    reason=str(result.get("reason", "OPA decision")),
                    decision_id=payload.get("decision_id"),
                )
            return Decision(allowed=False, reason="OPA returned an undefined decision")
        except (httpx.HTTPError, ValueError, TypeError) as exc:
            if self.config.development_allow_without_opa:
                return Decision(allowed=True, reason=f"Development OPA bypass: {type(exc).__name__}")
            return Decision(
                allowed=self.config.fail_open,
                reason=f"OPA unavailable ({type(exc).__name__}); "
                + ("fail-open" if self.config.fail_open else "fail-closed"),
            )
