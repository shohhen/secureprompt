"""Reusable in-memory async task store (enqueue + poll). Strong references keep
tasks alive (asyncio holds only weak refs); TTL prune never evicts a running
task; a running-count cap bounds concurrency. Mirrors the async scan-file
plumbing so new endpoints stay consistent."""
from __future__ import annotations

import asyncio
import time
import uuid
from typing import Any, Awaitable, Callable


class TaskStore:
    def __init__(self, ttl_s: int = 900, max_running: int = 4):
        self._tasks: dict[str, dict] = {}
        self._refs: set = set()
        self._ttl_s = ttl_s
        self._max_running = max_running

    def _prune(self) -> None:
        cutoff = time.monotonic() - self._ttl_s
        for tid in [t for t, v in self._tasks.items()
                    if v["status"] != "running" and v["created"] < cutoff]:
            self._tasks.pop(tid, None)

    def running_count(self) -> int:
        return sum(1 for v in self._tasks.values() if v["status"] == "running")

    def at_capacity(self) -> bool:
        self._prune()
        return self.running_count() >= self._max_running

    def start(self, coro_factory: Callable[[], Awaitable[Any]]) -> str:
        tid = uuid.uuid4().hex
        self._tasks[tid] = {"status": "running", "result": None,
                            "error": None, "created": time.monotonic()}

        async def _run():
            try:
                res = await coro_factory()
                entry = self._tasks.get(tid)
                if entry is not None:
                    entry["result"] = res
                    entry["status"] = "done"
            except Exception as e:  # noqa: BLE001
                entry = self._tasks.get(tid)
                if entry is not None:
                    entry["status"] = "error"
                    entry["error"] = str(e)

        t = asyncio.create_task(_run())
        self._refs.add(t)
        t.add_done_callback(self._refs.discard)
        return tid

    def get(self, tid: str) -> dict | None:
        return self._tasks.get(tid)
