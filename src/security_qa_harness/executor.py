from __future__ import annotations

from dataclasses import replace
from pathlib import Path
import os
import subprocess
import time

from .models import CaseDefinition, ExecutionStep, StepResult
from .replay import generate_command


REDACTED = "[REDACTED]"


def prepare_steps(
    case: CaseDefinition,
    variable_overrides: dict[str, str] | None = None,
    step_env_overrides: dict[str, dict[str, str]] | None = None,
) -> list[ExecutionStep]:
    variables = {
        "TARGET_ROOT": str(case.target.root),
        "REPORT_ID": case.metadata.report_id,
        "ATTACK_SURFACE": case.metadata.attack_surface,
        "AUTH_HTTP_HEADERS": _auth_http_headers(case),
        "GRPC_AUTH_METADATA": _grpc_auth_metadata(case),
        **case.variables,
        **(variable_overrides or {}),
    }
    env_overrides = step_env_overrides or {}
    prepared: list[ExecutionStep] = []
    for step in case.steps:
        command = generate_command(step.command, case.replay, variables)
        env = {key: value.format(**variables) for key, value in step.env.items()}
        env.update(env_overrides.get(step.name, {}))
        collect_paths = [Path(str(item).format(**variables)).resolve() for item in step.collect_paths]
        prepared.append(replace(step, command=command, env=env, collect_paths=collect_paths))
    return prepared


def run_steps(
    steps: list[ExecutionStep],
    output_dir: Path,
    redactions: list[str] | None = None,
) -> list[StepResult]:
    results: list[StepResult] = []
    sensitive_values = normalize_redactions(redactions or [])
    for index, step in enumerate(steps, start=1):
        step_dir = output_dir / f"{index:02d}-{slugify(step.name)}"
        step_dir.mkdir(parents=True, exist_ok=True)
        env = os.environ.copy()
        env.update(step.env)
        started = time.perf_counter()
        try:
            completed = subprocess.run(step.command, cwd=step.cwd, env=env, shell=True, text=True, capture_output=True, timeout=step.timeout_seconds)
            exit_code, stdout, stderr = completed.returncode, completed.stdout, completed.stderr
        except subprocess.TimeoutExpired as exc:
            exit_code = 124
            stdout = exc.stdout or ""
            stderr = (exc.stderr or "") + "\n[timeout] exceeded %s second(s)" % step.timeout_seconds
        duration = time.perf_counter() - started
        stored_command = redact_text(step.command, sensitive_values)
        stored_stdout = redact_text(stdout, sensitive_values)
        stored_stderr = redact_text(stderr, sensitive_values)
        (step_dir / "stdout.txt").write_text(stored_stdout, encoding="utf-8")
        (step_dir / "stderr.txt").write_text(stored_stderr, encoding="utf-8")
        collected = [str(artifact) for artifact in step.collect_paths if artifact.exists()]
        results.append(StepResult(step.name, step.objective, step.tags, stored_command, str(step.cwd), exit_code, exit_code in step.expected_exit_codes, round(duration, 3), stored_stdout, stored_stderr, collected))
    return results


def auth_redaction_values(case: CaseDefinition) -> list[str]:
    """Return authentication material that must never enter reports or step logs."""

    return normalize_redactions(
        [
            case.auth.bearer_token,
            case.auth.cookie,
            *case.auth.headers.values(),
        ]
    )


def normalize_redactions(values: list[str]) -> list[str]:
    return sorted({value for value in values if value}, key=len, reverse=True)


def redact_text(text: str, redactions: list[str]) -> str:
    for value in normalize_redactions(redactions):
        text = text.replace(value, REDACTED)
    return text


def _auth_http_headers(case: CaseDefinition) -> str:
    headers: list[str] = []
    if case.auth.bearer_token:
        headers.append("-H 'Authorization: Bearer %s'" % case.auth.bearer_token)
    if case.auth.cookie:
        headers.append("-H 'Cookie: %s'" % case.auth.cookie)
    for key, value in case.auth.headers.items():
        headers.append("-H '%s: %s'" % (key, value))
    return " ".join(headers)


def _grpc_auth_metadata(case: CaseDefinition) -> str:
    headers: list[str] = []
    if case.auth.bearer_token:
        headers.append("-H 'authorization: Bearer %s'" % case.auth.bearer_token)
    if case.auth.cookie:
        headers.append("-H 'cookie: %s'" % case.auth.cookie)
    for key, value in case.auth.headers.items():
        headers.append("-H '%s: %s'" % (key.lower(), value))
    return " ".join(headers)


def slugify(value: str) -> str:
    return "".join(ch.lower() if ch.isalnum() else "-" for ch in value).strip("-")
