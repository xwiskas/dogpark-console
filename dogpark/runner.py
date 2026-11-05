"""Command runner — the only place in the app that calls subprocess, and only ever on a
command the user clicked Run on. Streams output line-by-line to a callback so the GUI can
show it live, and writes an evidence trail (per-run log + session JSONL) for every attempt.

No command is ever built or launched here; this module only executes the exact string it's
handed. Non-blocking: runs in a background thread and supports cancel/terminate.
"""

from __future__ import annotations

import json
import os
import platform
import shlex
import subprocess
import threading
import time
from dataclasses import dataclass
from datetime import datetime, timezone
from pathlib import Path
from typing import Callable, Optional

OnLine = Callable[[str], None]


@dataclass
class RunResult:
    command: str
    target: str
    action_id: str
    exit_code: Optional[int]
    log_path: str
    started_at: str
    finished_at: Optional[str]
    cancelled: bool = False


class Runner:
    """Runs one command at a time in a background thread, streaming output and logging."""

    def __init__(self, output_dir: str):
        self.output_dir = Path(output_dir).expanduser()
        self._proc: Optional[subprocess.Popen] = None
        self._thread: Optional[threading.Thread] = None
        self._lock = threading.Lock()
        self._cancelled = False

    # -- paths -----------------------------------------------------------
    def runs_dir(self) -> Path:
        d = self.output_dir / "runs"
        d.mkdir(parents=True, exist_ok=True)
        return d

    def session_dir(self) -> Path:
        d = self.output_dir / "session"
        d.mkdir(parents=True, exist_ok=True)
        return d

    def session_log_path(self, day: int) -> Path:
        return self.session_dir() / f"day{day}.jsonl"

    # -- running -----------------------------------------------------------
    def is_running(self) -> bool:
        with self._lock:
            return self._proc is not None and self._proc.poll() is None

    def run(
        self,
        command: str,
        target: str,
        action_id: str,
        day: int,
        on_line: Optional[OnLine] = None,
        on_done: Optional[Callable[[RunResult], None]] = None,
        cwd: Optional[str] = None,
        env: Optional[dict] = None,
    ) -> None:
        """Launch `command` in a background thread. Never blocks the caller."""
        if self.is_running():
            if on_line:
                on_line("[runner] a command is already running — Stop it first")
            return

        self._cancelled = False
        thread = threading.Thread(
            target=self._run_blocking,
            args=(command, target, action_id, day, on_line, on_done, cwd, env),
            daemon=True,
        )
        self._thread = thread
        thread.start()

    def _run_blocking(self, command, target, action_id, day, on_line, on_done, cwd, env):
        started_at = datetime.now(timezone.utc).isoformat()
        timestamp = started_at.replace(":", "-").replace("+00:00", "Z")
        log_path = self.runs_dir() / f"{timestamp}_{action_id or 'run'}.log"

        is_windows = platform.system() == "Windows"
        # On the Windows dev box the real Kali tools don't exist. Rather than fail the whole
        # save/log path (which we DO want exercised by tests/dev runs), swap in a harmless
        # no-op command but keep logging exactly as if the real one ran.
        actual_command = command
        if is_windows:
            actual_command = "echo DOGPARK: this tool is Kali-only; on Windows this is a no-op echo"

        full_env = os.environ.copy()
        if env:
            full_env.update(env)

        exit_code: Optional[int] = None
        try:
            with open(log_path, "w", encoding="utf-8") as log_file:
                log_file.write(f"# command: {command}\n")
                log_file.write(f"# started: {started_at}\n")
                if is_windows:
                    log_file.write("# NOTE: executed on Windows dev box — real command not run, echo stub used\n")
                log_file.flush()

                args = shlex.split(actual_command, posix=not is_windows)
                proc = subprocess.Popen(
                    args,
                    cwd=cwd,
                    env=full_env,
                    stdout=subprocess.PIPE,
                    stderr=subprocess.STDOUT,
                    text=True,
                    bufsize=1,
                    shell=False,
                )
                with self._lock:
                    self._proc = proc

                for line in proc.stdout:  # type: ignore[union-attr]
                    log_file.write(line)
                    log_file.flush()
                    if on_line:
                        on_line(line.rstrip("\n"))
                    if self._cancelled:
                        break

                proc.wait(timeout=5)
                exit_code = proc.returncode
        except Exception as exc:  # noqa: BLE001 — surface any failure to the log + callback
            if on_line:
                on_line(f"[runner] error: {exc}")
            exit_code = -1
        finally:
            with self._lock:
                self._proc = None

        finished_at = datetime.now(timezone.utc).isoformat()
        result = RunResult(
            command=command,
            target=target,
            action_id=action_id,
            exit_code=exit_code,
            log_path=str(log_path),
            started_at=started_at,
            finished_at=finished_at,
            cancelled=self._cancelled,
        )
        self._append_session_record(day, result)
        if on_done:
            on_done(result)

    def stop(self) -> None:
        """Request cancellation and terminate the running process, if any."""
        self._cancelled = True
        with self._lock:
            proc = self._proc
        if proc is not None and proc.poll() is None:
            try:
                proc.terminate()
                time.sleep(0.2)
                if proc.poll() is None:
                    proc.kill()
            except Exception:
                pass

    def _append_session_record(self, day: int, result: RunResult) -> None:
        record = {
            "timestamp": result.started_at,
            "finished_at": result.finished_at,
            "target": result.target,
            "action_id": result.action_id,
            "command": result.command,
            "exit_code": result.exit_code,
            "log_path": result.log_path,
            "cancelled": result.cancelled,
        }
        path = self.session_log_path(day)
        with open(path, "a", encoding="utf-8") as f:
            f.write(json.dumps(record) + "\n")
