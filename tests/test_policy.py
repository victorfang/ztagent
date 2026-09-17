import pytest

from mini_secure_agent.config import PolicyConfig
from mini_secure_agent.policy import OPAClient


@pytest.mark.asyncio
async def test_opa_failure_is_closed_by_default() -> None:
    client = OPAClient(PolicyConfig(opa_url="http://127.0.0.1:1", timeout_seconds=0.01))

    decision = await client.decide({"action": "model.generate"})

    assert decision.allowed is False
    assert "fail-closed" in decision.reason
