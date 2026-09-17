# Author: Victor Fang
# Website: https://VictorFang.com
# X: https://X.com/vicfcs
# LinkedIn: https://www.linkedin.com/in/drvictorfang

from pathlib import Path

from ztagent_core.anomaly import AnomalyDetector
from ztagent_core.config import AnomalyConfig


def test_rolling_request_limit_blocks_after_threshold(tmp_path: Path) -> None:
    detector = AnomalyDetector(
        AnomalyConfig(
            state_backend="sqlite",
            sqlite_path=tmp_path / "state.db",
            requests_per_24h=2,
        )
    )

    assert detector.observe_request("victor", 1, 10) == []
    assert detector.observe_request("victor", 1, 10) == []
    findings = detector.observe_request("victor", 1, 10)

    assert findings[0].rule_id == "anomaly.request-rate-24h"
    assert findings[0].action == "block"


def test_repeated_blocks_trigger_containment() -> None:
    detector = AnomalyDetector(AnomalyConfig(state_backend="memory", blocked_events_per_24h=2))

    assert detector.observe_block("victor") == []
    findings = detector.observe_block("victor")

    assert findings[0].action == "contain"
