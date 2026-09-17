# Author: Victor Fang
# Website: https://VictorFang.com
# X: https://X.com/vicfcs
# LinkedIn: https://www.linkedin.com/in/drvictorfang

"""Optional LangChain runnable adapter.

The gateway stays orchestrator-neutral. This adapter puts the complete security
pipeline around a LangChain graph edge without allowing the graph to bypass it.
"""

from __future__ import annotations

from typing import Any

from ..gateway import SecureAgentGateway
from ..models import AgentRequest, Principal


def as_langchain_runnable(
    gateway: SecureAgentGateway, principal: Principal, source_ip: str | None = None
) -> Any:
    """Return a Runnable accepting an AgentRequest or its dictionary form."""
    try:
        from langchain_core.runnables import RunnableLambda
    except ImportError as exc:
        raise RuntimeError(
            "LangChain integration requires: pip install 'mini-secure-agent[langchain]'"
        ) from exc

    async def secure_call(value: AgentRequest | dict[str, Any]) -> dict[str, Any]:
        request = value if isinstance(value, AgentRequest) else AgentRequest.model_validate(value)
        response = await gateway.run(request, principal, source_ip)
        return response.model_dump()

    return RunnableLambda(secure_call)
