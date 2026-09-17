"""Threat containment with an immediate local block and optional external actions."""

from __future__ import annotations

import json
import os
import threading
from datetime import UTC, datetime
from pathlib import Path
from typing import Any
from urllib.parse import quote

import httpx

from .config import ContainmentConfig


class IdentityBlocklist:
    def __init__(self, path: Path) -> None:
        self.path = path
        self._lock = threading.Lock()
        path.parent.mkdir(parents=True, exist_ok=True)

    def contains(self, subject: str) -> bool:
        return subject in self._read()

    def block(self, subject: str, reason: str) -> None:
        with self._lock:
            entries = self._read()
            entries[subject] = {"reason": reason, "blocked_at": datetime.now(UTC).isoformat()}
            temporary = self.path.with_suffix(".tmp")
            temporary.write_text(json.dumps(entries, indent=2), encoding="utf-8")
            temporary.replace(self.path)

    def unblock(self, subject: str) -> bool:
        with self._lock:
            entries = self._read()
            removed = entries.pop(subject, None) is not None
            if removed:
                temporary = self.path.with_suffix(".tmp")
                temporary.write_text(json.dumps(entries, indent=2), encoding="utf-8")
                temporary.replace(self.path)
            return removed

    def list(self) -> dict[str, Any]:
        return self._read()

    def _read(self) -> dict[str, Any]:
        if not self.path.exists():
            return {}
        try:
            value = json.loads(self.path.read_text(encoding="utf-8"))
            return value if isinstance(value, dict) else {}
        except (OSError, json.JSONDecodeError):
            # A corrupt blocklist must not silently restore access.
            raise RuntimeError(f"Cannot safely read identity blocklist {self.path}") from None


class ContainmentService:
    def __init__(self, config: ContainmentConfig) -> None:
        self.config = config
        self.blocklist = IdentityBlocklist(config.blocklist_path)

    async def contain(self, subject: str, reason: str, event_id: str) -> list[str]:
        if not self.config.enabled:
            return ["containment-disabled"]
        self.blocklist.block(subject, reason)
        actions = ["local-identity-block"]
        async with httpx.AsyncClient(timeout=5) as client:
            if self.config.webhook_url:
                try:
                    response = await client.post(
                        self.config.webhook_url,
                        json={"subject": subject, "reason": reason, "event_id": event_id},
                    )
                    response.raise_for_status()
                    actions.append("webhook-notified")
                except httpx.HTTPError:
                    actions.append("webhook-failed")
            if self.config.keycloak_admin_url and self.config.keycloak_realm:
                token = os.getenv(self.config.keycloak_token_env)
                if token:
                    url = (
                        f"{self.config.keycloak_admin_url.rstrip('/')}/admin/realms/"
                        f"{quote(self.config.keycloak_realm, safe='')}/users/"
                        f"{quote(subject, safe='')}/logout"
                    )
                    try:
                        response = await client.post(
                            url, headers={"Authorization": f"Bearer {token}"}
                        )
                        response.raise_for_status()
                        actions.append("keycloak-sessions-revoked")
                    except httpx.HTTPError:
                        actions.append("keycloak-revoke-failed")
                else:
                    actions.append("keycloak-token-missing")
        return actions
