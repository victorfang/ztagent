"""Lightweight stateless scoring plus optional rolling-window counters."""

from __future__ import annotations

import sqlite3
import threading
import time
from collections import defaultdict, deque
from pathlib import Path
from typing import Protocol

from .config import AnomalyConfig
from .models import Detection


class CounterStore(Protocol):
    def increment(self, subject: str, event_type: str, window_seconds: int) -> int: ...


class MemoryCounterStore:
    def __init__(self) -> None:
        self._events: dict[tuple[str, str], deque[float]] = defaultdict(deque)
        self._lock = threading.Lock()

    def increment(self, subject: str, event_type: str, window_seconds: int) -> int:
        now = time.time()
        cutoff = now - window_seconds
        with self._lock:
            bucket = self._events[(subject, event_type)]
            while bucket and bucket[0] < cutoff:
                bucket.popleft()
            bucket.append(now)
            return len(bucket)


class SQLiteCounterStore:
    def __init__(self, path: Path) -> None:
        path.parent.mkdir(parents=True, exist_ok=True)
        self.path = path
        self._lock = threading.Lock()
        with self._connect() as conn:
            conn.execute(
                "CREATE TABLE IF NOT EXISTS events "
                "(subject TEXT NOT NULL, event_type TEXT NOT NULL, occurred REAL NOT NULL)"
            )
            conn.execute(
                "CREATE INDEX IF NOT EXISTS events_lookup ON events(subject, event_type, occurred)"
            )

    def increment(self, subject: str, event_type: str, window_seconds: int) -> int:
        now = time.time()
        cutoff = now - window_seconds
        with self._lock, self._connect() as conn:
            conn.execute("DELETE FROM events WHERE occurred < ?", (cutoff,))
            conn.execute(
                "INSERT INTO events(subject, event_type, occurred) VALUES (?, ?, ?)",
                (subject, event_type, now),
            )
            row = conn.execute(
                "SELECT COUNT(*) FROM events "
                "WHERE subject = ? AND event_type = ? AND occurred >= ?",
                (subject, event_type, cutoff),
            ).fetchone()
        return int(row[0]) if row else 0

    def _connect(self) -> sqlite3.Connection:
        return sqlite3.connect(self.path, timeout=5)


class AnomalyDetector:
    WINDOW_SECONDS = 86_400

    def __init__(self, config: AnomalyConfig) -> None:
        self.config = config
        self.store: CounterStore = (
            SQLiteCounterStore(config.sqlite_path)
            if config.state_backend == "sqlite"
            else MemoryCounterStore()
        )

    def observe_request(
        self, subject: str, message_count: int, prompt_chars: int
    ) -> list[Detection]:
        if not self.config.enabled:
            return []
        findings: list[Detection] = []
        # Per-request, stateless heuristics catch unusual payload shape.
        if message_count > 50 or prompt_chars > 75_000:
            findings.append(
                Detection(
                    rule_id="anomaly.large-context",
                    category="resource-abuse",
                    severity="medium",
                    action="log",
                    score=30,
                    detail="Unusually large message context",
                )
            )
        count = self.store.increment(subject, "request", self.WINDOW_SECONDS)
        if count > self.config.requests_per_24h:
            findings.append(
                Detection(
                    rule_id="anomaly.request-rate-24h",
                    category="rate-limit",
                    severity="high",
                    action="block",
                    score=90,
                    detail=f"Identity exceeded {self.config.requests_per_24h} requests in 24 hours",
                )
            )
        return findings

    def observe_block(self, subject: str) -> list[Detection]:
        if not self.config.enabled:
            return []
        count = self.store.increment(subject, "blocked", self.WINDOW_SECONDS)
        if count >= self.config.blocked_events_per_24h:
            return [
                Detection(
                    rule_id="anomaly.repeated-blocks-24h",
                    category="repeat-offender",
                    severity="critical",
                    action="contain",
                    score=100,
                    detail="Identity repeatedly triggered blocking controls",
                )
            ]
        return []
