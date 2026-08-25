from __future__ import annotations

from pathlib import Path
import re

from .models import AdapterConfig, RuntimeObservation, StepResult


GO_PANIC_RE = re.compile(r"panic: (?P<msg>.+)")
JAVA_HS_RE = re.compile(r"A fatal error has been detected by the Java Runtime Environment", re.IGNORECASE)
PY_TRACEBACK_RE = re.compile(r"Traceback \(most recent call last\):")
NODE_TRACE_RE = re.compile(r"(UnhandledPromiseRejection|TypeError:|ReferenceError:)")
RUST_PANIC_RE = re.compile(r"thread '.*' panicked at")
CORE_RE = re.compile(r"\bcore dumped\b", re.IGNORECASE)


def collect_runtime_observations(adapter: AdapterConfig, steps: list[StepResult], search_root: Path | None = None) -> list[RuntimeObservation]:
    observations: list[RuntimeObservation] = []
    for step in steps:
        merged = "\n".join([step.stdout, step.stderr])
        observations.extend(observations_from_text(adapter.language, merged, f"step:{step.name}"))
        for artifact in step.collected_artifacts:
            observations.extend(observations_from_file(adapter.language, Path(artifact)))
    if search_root is not None:
        observations.extend(observations_from_globs(adapter, search_root))
    return dedupe_observations(observations)


def observations_from_text(language: str, text: str, source: str) -> list[RuntimeObservation]:
    observations: list[RuntimeObservation] = []
    if language == "go":
        for match in GO_PANIC_RE.finditer(text):
            observations.append(RuntimeObservation("go-panic", source, match.group("msg").strip()))
    if language == "java" and JAVA_HS_RE.search(text):
        observations.append(RuntimeObservation("jvm-fatal", source, "JVM fatal error banner observed"))
    if language == "python" and PY_TRACEBACK_RE.search(text):
        observations.append(RuntimeObservation("python-traceback", source, "Python traceback observed"))
    if language == "node" and NODE_TRACE_RE.search(text):
        observations.append(RuntimeObservation("node-exception", source, "Node exception trace observed"))
    if language == "rust" and RUST_PANIC_RE.search(text):
        observations.append(RuntimeObservation("rust-panic", source, "Rust panic observed"))
    if CORE_RE.search(text):
        observations.append(RuntimeObservation("core-dump", source, "Core dump message observed"))
    return observations


def observations_from_globs(adapter: AdapterConfig, root: Path) -> list[RuntimeObservation]:
    observations: list[RuntimeObservation] = []
    for pattern in adapter.dump_globs:
        for path in sorted(root.glob(pattern)):
            observations.extend(observations_from_file(adapter.language, path))
            if path.is_file() and not observations_from_file(adapter.language, path):
                observations.append(RuntimeObservation("dump-artifact", "glob", f"Collected artifact matching {pattern}", str(path)))
    return observations


def observations_from_file(language: str, path: Path) -> list[RuntimeObservation]:
    if not path.exists() or path.is_dir():
        return []
    name = path.name
    observations: list[RuntimeObservation] = []
    text = read_text_safely(path)
    if name.startswith("hs_err_pid"):
        observations.append(RuntimeObservation("jvm-crash-log", "artifact", "HotSpot fatal error log collected", str(path)))
    if name.endswith(".hprof"):
        observations.append(RuntimeObservation("jvm-heap-dump", "artifact", "JVM heap dump collected", str(path)))
    if name.startswith("core") or name.endswith(".core"):
        observations.append(RuntimeObservation("native-core", "artifact", "Native core dump collected", str(path)))
    if "panic:" in text and language == "go":
        observations.append(RuntimeObservation("go-panic-log", "artifact", "Go panic log collected", str(path)))
    if "Traceback (most recent call last):" in text and language == "python":
        observations.append(RuntimeObservation("python-traceback-log", "artifact", "Python traceback log collected", str(path)))
    if "UnhandledPromiseRejection" in text and language == "node":
        observations.append(RuntimeObservation("node-crash-log", "artifact", "Node crash log collected", str(path)))
    return observations


def read_text_safely(path: Path) -> str:
    try:
        return path.read_text(encoding="utf-8", errors="ignore")
    except OSError:
        return ""


def dedupe_observations(items: list[RuntimeObservation]) -> list[RuntimeObservation]:
    seen: set[tuple[str, str, str, str | None]] = set()
    ordered: list[RuntimeObservation] = []
    for item in items:
        key = (item.kind, item.source, item.summary, item.path)
        if key not in seen:
            seen.add(key)
            ordered.append(item)
    return ordered
