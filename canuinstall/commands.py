from __future__ import annotations

import subprocess
import shlex
import time
from dataclasses import dataclass
from pathlib import Path

from .progress import emit


@dataclass
class CommandResult:
    args: list[str]
    returncode: int
    stdout: str
    stderr: str

    @property
    def output(self) -> str:
        return "\n".join(v for v in (self.stdout, self.stderr) if v).strip()


def run(
    args: list[str],
    *,
    timeout: int = 90,
    cwd: Path | None = None,
) -> CommandResult:
    display = " ".join(shlex.quote(str(arg)) for arg in args)
    emit(f"$ {display}", "command", "command")
    started = time.monotonic()
    try:
        process = subprocess.run(
            args,
            cwd=cwd,
            capture_output=True,
            text=True,
            timeout=timeout,
            check=False,
            env={"PATH": "/usr/bin:/bin:/usr/sbin:/sbin"},
        )
        result = CommandResult(args, process.returncode, process.stdout, process.stderr)
        elapsed = time.monotonic() - started
        emit(
            f"exit {result.returncode} · {elapsed:.2f}s"
            + (f"\n{truncate_output(result.output)}" if result.output else ""),
            "success" if result.returncode == 0 else "warning",
            "output",
        )
        return result
    except subprocess.TimeoutExpired as exc:
        stdout = exc.stdout.decode(errors="replace") if isinstance(exc.stdout, bytes) else exc.stdout
        stderr = exc.stderr.decode(errors="replace") if isinstance(exc.stderr, bytes) else exc.stderr
        result = CommandResult(args, 124, stdout or "", (stderr or "") + "\nTimed out")
        emit(
            f"timeout · {time.monotonic() - started:.2f}s\n{truncate_output(result.output)}",
            "error",
            "output",
        )
        return result


def truncate_output(value: str, limit: int = 4000) -> str:
    value = value.strip()
    if len(value) <= limit:
        return value
    return value[:limit] + f"\n… output truncated ({len(value) - limit} chars omitted)"
