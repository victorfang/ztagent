# Author: Victor Fang
# Website: https://VictorFang.com
# X: https://X.com/vicfcs
# LinkedIn: https://www.linkedin.com/in/drvictorfang

import pytest

from ztagent_core.config import ProviderConfig


def test_anthropic_uses_provider_specific_key(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    monkeypatch.setenv("OPENAI_API_KEY", "must-not-be-used")
    monkeypatch.setenv("ANTHROPIC_API_KEY", "anthropic-key")
    config = ProviderConfig(kind="anthropic")

    assert config.api_key().get_secret_value() == "anthropic-key"
