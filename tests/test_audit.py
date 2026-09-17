# Author: Victor Fang
# Website: https://VictorFang.com
# X: https://X.com/vicfcs
# LinkedIn: https://www.linkedin.com/in/drvictorfang

import json
from pathlib import Path

from mini_secure_agent.audit import AuditLog
from mini_secure_agent.models import SecurityEvent


def test_audit_chain_verifies_and_redacts(tmp_path: Path) -> None:
    path = tmp_path / "audit.jsonl"
    audit = AuditLog(path, b"x" * 32)
    audit.append(
        SecurityEvent(
            event_type="request",
            outcome="allowed",
            details={"token": "secret", "nested": {"api_key": "also-secret"}},
        )
    )
    audit.append(SecurityEvent(event_type="response", outcome="allowed"))

    valid, count = audit.verify()
    records = audit.read()

    assert (valid, count) == (True, 2)
    assert records[0]["event"]["details"]["token"] == "[REDACTED]"
    assert records[0]["event"]["details"]["nested"]["api_key"] == "[REDACTED]"


def test_audit_chain_detects_tampering(tmp_path: Path) -> None:
    path = tmp_path / "audit.jsonl"
    audit = AuditLog(path, b"x" * 32)
    audit.append(SecurityEvent(event_type="request", outcome="allowed"))
    envelope = json.loads(path.read_text())
    envelope["event"]["outcome"] = "blocked"
    path.write_text(json.dumps(envelope) + "\n")

    assert audit.verify() == (False, 0)
