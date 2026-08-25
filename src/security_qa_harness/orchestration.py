from __future__ import annotations

from contextlib import contextmanager
from pathlib import Path
import subprocess
import time
from urllib.error import URLError
from urllib.request import urlopen

from .models import AdapterConfig, CaseDefinition


@contextmanager
def managed_target(case: CaseDefinition):
    if case.target.setup:
        run_commands(case.target.setup, case.target.root)
    try:
        processes = start_services(case.adapter, case.target.root)
        wait_for_healthcheck(case.adapter)
        yield
    finally:
        stop_services(case.adapter, case.target.root, processes)
        if case.target.cleanup:
            run_commands(case.target.cleanup, case.target.root)


def run_commands(commands: list[str], cwd: Path) -> None:
    for command in commands:
        subprocess.run(command, cwd=cwd, shell=True, check=True, text=True, capture_output=True)


def start_services(adapter: AdapterConfig, cwd: Path) -> list[subprocess.Popen]:
    processes: list[subprocess.Popen] = []
    for command in adapter.start_commands:
        processes.append(
            subprocess.Popen(
                command,
                cwd=cwd,
                shell=True,
                text=True,
                stdout=subprocess.DEVNULL,
                stderr=subprocess.DEVNULL,
            )
        )
    return processes


def wait_for_healthcheck(adapter: AdapterConfig) -> None:
    if not adapter.healthcheck:
        return
    deadline = time.time() + adapter.startup_timeout_seconds
    last_error: Exception | None = None
    while time.time() < deadline:
        try:
            with urlopen(adapter.healthcheck, timeout=2) as response:
                if 200 <= response.status < 500:
                    return
        except URLError as exc:
            last_error = exc
        time.sleep(adapter.healthcheck_interval_seconds)
    if last_error:
        raise RuntimeError(f"Healthcheck failed for {adapter.healthcheck}: {last_error}")
    raise RuntimeError(f"Healthcheck timed out for {adapter.healthcheck}")


def stop_services(adapter: AdapterConfig, cwd: Path, processes: list[subprocess.Popen]) -> None:
    for command in adapter.stop_commands:
        subprocess.run(command, cwd=cwd, shell=True, check=False, text=True, capture_output=True)
    for process in processes:
        if process.poll() is None:
            process.terminate()
            try:
                process.wait(timeout=5)
            except subprocess.TimeoutExpired:
                process.kill()
