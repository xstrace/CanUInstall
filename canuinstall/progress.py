from __future__ import annotations

import contextvars
import threading
import time
import uuid
from dataclasses import dataclass, field
from datetime import UTC, datetime
from typing import Callable


Reporter = Callable[[str, str, str], None]
_reporter: contextvars.ContextVar[Reporter | None] = contextvars.ContextVar(
    "canuinstall_reporter", default=None
)


def emit(message: str, level: str = "info", kind: str = "step") -> None:
    reporter = _reporter.get()
    if reporter:
        reporter(message, level, kind)


def set_reporter(reporter: Reporter):
    return _reporter.set(reporter)


def reset_reporter(token) -> None:
    _reporter.reset(token)


@dataclass
class Job:
    id: str = field(default_factory=lambda: uuid.uuid4().hex)
    status: str = "queued"
    events: list[dict[str, object]] = field(default_factory=list)
    report: dict[str, object] | None = None
    error: str | None = None
    created_at: float = field(default_factory=time.time)
    updated_at: float = field(default_factory=time.time)
    lock: threading.Lock = field(default_factory=threading.Lock, repr=False)

    def log(self, message: str, level: str = "info", kind: str = "step") -> None:
        with self.lock:
            self.events.append(
                {
                    "seq": len(self.events),
                    "time": datetime.now(UTC).isoformat(),
                    "level": level,
                    "kind": kind,
                    "message": message[:8000],
                }
            )
            self.updated_at = time.time()

    def snapshot(self, since: int = 0) -> dict[str, object]:
        with self.lock:
            return {
                "id": self.id,
                "status": self.status,
                "events": self.events[max(0, since) :],
                "next": len(self.events),
                "report": self.report if self.status == "completed" else None,
                "error": self.error,
            }


class JobStore:
    def __init__(self) -> None:
        self.jobs: dict[str, Job] = {}
        self.lock = threading.Lock()

    def create(self) -> Job:
        job = Job()
        with self.lock:
            self.jobs[job.id] = job
            self._prune()
        return job

    def get(self, job_id: str) -> Job | None:
        with self.lock:
            return self.jobs.get(job_id)

    def _prune(self) -> None:
        cutoff = time.time() - 6 * 60 * 60
        stale = [key for key, job in self.jobs.items() if job.updated_at < cutoff]
        for key in stale:
            self.jobs.pop(key, None)


JOBS = JobStore()
