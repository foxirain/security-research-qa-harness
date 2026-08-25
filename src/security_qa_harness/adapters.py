from __future__ import annotations

from dataclasses import replace

from .models import AdapterConfig, CaseDefinition, ExecutionStep


class TargetAdapter:
    name = "generic"

    def plan(self, case: CaseDefinition) -> CaseDefinition:
        return case


class GenericAdapter(TargetAdapter):
    name = "generic"

    def plan(self, case: CaseDefinition) -> CaseDefinition:
        return _apply_adapter_defaults(case)


class FileParserAdapter(TargetAdapter):
    name = "file-parser"

    def plan(self, case: CaseDefinition) -> CaseDefinition:
        return _append_tags(_apply_adapter_defaults(case), ["input-driven", "parser"])


class ServiceAdapter(TargetAdapter):
    name = "service"

    def plan(self, case: CaseDefinition) -> CaseDefinition:
        planned = _append_tags(_apply_adapter_defaults(case), ["service"])
        if planned.adapter.ports and not planned.adapter.healthcheck:
            planned = replace(planned, adapter=replace(planned.adapter, notes=list(planned.adapter.notes) + [f"Service ports declared: {', '.join(str(port) for port in planned.adapter.ports)}"]))
        return planned


class WebAppAdapter(TargetAdapter):
    name = "web-app"

    def plan(self, case: CaseDefinition) -> CaseDefinition:
        planned = _append_tags(_apply_adapter_defaults(case), ["service", "web", "http"])
        adapter = planned.adapter
        if adapter.ports and not adapter.healthcheck:
            adapter = replace(adapter, healthcheck=f"http://127.0.0.1:{adapter.ports[0]}/")
        return replace(planned, adapter=adapter)


class OpenAPIAdapter(TargetAdapter):
    name = "openapi"

    def plan(self, case: CaseDefinition) -> CaseDefinition:
        planned = _append_tags(_apply_adapter_defaults(case), ["service", "web", "http", "openapi"])
        return replace(planned, adapter=replace(planned.adapter, notes=dedupe_strings(list(planned.adapter.notes) + ["OpenAPI targets should keep path, method, content type, and auth state explicit per step."])))


class GrpcAdapter(TargetAdapter):
    name = "grpc"

    def plan(self, case: CaseDefinition) -> CaseDefinition:
        planned = _append_tags(_apply_adapter_defaults(case), ["service", "grpc", "rpc"])
        return replace(planned, adapter=replace(planned.adapter, notes=dedupe_strings(list(planned.adapter.notes) + ["gRPC targets should preserve method name, metadata, compression, and serialized body shape."])))


class LibraryAdapter(TargetAdapter):
    name = "library"

    def plan(self, case: CaseDefinition) -> CaseDefinition:
        return _append_tags(_apply_adapter_defaults(case), ["library"])


class JniLibraryAdapter(TargetAdapter):
    name = "jni-library"

    def plan(self, case: CaseDefinition) -> CaseDefinition:
        planned = _append_tags(_apply_adapter_defaults(case), ["library", "jni", "java-native-boundary"])
        return replace(planned, adapter=replace(planned.adapter, notes=dedupe_strings(list(planned.adapter.notes) + ["JNI targets should preserve both Java-side exception state and native crash evidence."])))


class NativeHarnessAdapter(TargetAdapter):
    name = "native-harness"

    def plan(self, case: CaseDefinition) -> CaseDefinition:
        planned = _append_tags(_apply_adapter_defaults(case), ["library", "native-harness"])
        return replace(planned, adapter=replace(planned.adapter, notes=dedupe_strings(list(planned.adapter.notes) + ["Native harness targets should keep argv, env, symbols, and dump collection deterministic."])))


class CliToolAdapter(TargetAdapter):
    name = "cli-tool"

    def plan(self, case: CaseDefinition) -> CaseDefinition:
        return _append_tags(_apply_adapter_defaults(case), ["cli"])


def resolve_adapter(config: AdapterConfig) -> TargetAdapter:
    registry = {
        "generic": GenericAdapter(),
        "file-parser": FileParserAdapter(),
        "service": ServiceAdapter(),
        "local-server": ServiceAdapter(),
        "web-app": WebAppAdapter(),
        "openapi": OpenAPIAdapter(),
        "grpc": GrpcAdapter(),
        "library": LibraryAdapter(),
        "jni-library": JniLibraryAdapter(),
        "native-harness": NativeHarnessAdapter(),
        "cli-tool": CliToolAdapter(),
    }
    return registry.get(config.product_type or config.kind, registry.get(config.kind, GenericAdapter()))


def _apply_adapter_defaults(case: CaseDefinition) -> CaseDefinition:
    env_defaults = sanitizer_defaults(case.adapter.sanitizer_profile)
    env_defaults.update(language_defaults(case.adapter.language))
    auth_env = auth_defaults(case)
    merged_steps: list[ExecutionStep] = []
    for step in case.steps:
        env = {**env_defaults, **auth_env, **case.adapter.runtime_env, **step.env}
        collect_paths = dedupe_paths(list(step.collect_paths) + list(case.adapter.extra_artifacts))
        tags = dedupe_strings(list(step.tags) + [case.adapter.language, case.adapter.product_type, case.auth.mode])
        merged_steps.append(replace(step, env=env, collect_paths=collect_paths, tags=tags))
    setup = dedupe_strings(list(case.target.setup) + maybe_auth_login(case) + list(language_build_hints(case.adapter.language)) + list(case.adapter.build_commands))
    adapter = replace(case.adapter, notes=dedupe_strings(language_notes(case.adapter.language) + product_notes(case.adapter.product_type) + auth_notes(case) + case.adapter.notes), dump_globs=dedupe_strings(default_dump_globs(case.adapter.language) + case.adapter.dump_globs))
    target = replace(case.target, setup=setup)
    return replace(case, target=target, adapter=adapter, steps=merged_steps)


def _append_tags(case: CaseDefinition, tags: list[str]) -> CaseDefinition:
    updated = [replace(step, tags=dedupe_strings(list(step.tags) + tags)) for step in case.steps]
    return replace(case, steps=updated)


def auth_defaults(case: CaseDefinition) -> dict[str, str]:
    auth = case.auth
    headers = []
    if auth.bearer_token:
        headers.append(f"-H 'Authorization: Bearer {auth.bearer_token}'")
    if auth.cookie:
        headers.append(f"-H 'Cookie: {auth.cookie}'")
    for key, value in auth.headers.items():
        headers.append(f"-H '{key}: {value}'")
    return {
        "AUTH_MODE": auth.mode,
        "AUTH_HTTP_HEADERS": " ".join(headers),
        "AUTH_BEARER_TOKEN": auth.bearer_token,
        "AUTH_COOKIE": auth.cookie,
    }


def maybe_auth_login(case: CaseDefinition) -> list[str]:
    return [case.auth.login_command] if case.auth.login_command else []


def auth_notes(case: CaseDefinition) -> list[str]:
    if case.auth.mode == "none":
        return []
    notes = [f"Authentication mode is `{case.auth.mode}` and should remain stable across replay and boundary variants."]
    if case.auth.headers:
        notes.append("Custom auth headers are configured for replay.")
    if case.auth.login_command:
        notes.append("A pre-run login command is configured to establish session state.")
    return notes


def sanitizer_defaults(profile: str) -> dict[str, str]:
    profiles = {
        "none": {},
        "asan-ubsan": {"ASAN_OPTIONS": "halt_on_error=1:abort_on_error=1:detect_stack_use_after_return=1", "UBSAN_OPTIONS": "print_stacktrace=1:halt_on_error=1"},
        "asan": {"ASAN_OPTIONS": "halt_on_error=1:abort_on_error=1"},
        "go-race": {"GORACE": "halt_on_error=1"},
        "jvm": {"JAVA_TOOL_OPTIONS": "-XX:+HeapDumpOnOutOfMemoryError -XX:ErrorFile=hs_err_pid%p.log"},
    }
    return dict(profiles.get(profile, {}))


def language_defaults(language: str) -> dict[str, str]:
    profiles = {
        "c": {"HARNESS_LANGUAGE": "c", "MALLOC_CHECK_": "3"},
        "c++": {"HARNESS_LANGUAGE": "c++", "MALLOC_CHECK_": "3"},
        "go": {"HARNESS_LANGUAGE": "go", "GOTRACEBACK": "all"},
        "java": {"HARNESS_LANGUAGE": "java"},
        "python": {"HARNESS_LANGUAGE": "python", "PYTHONFAULTHANDLER": "1"},
        "node": {"HARNESS_LANGUAGE": "node", "NODE_OPTIONS": "--trace-uncaught"},
        "rust": {"HARNESS_LANGUAGE": "rust", "RUST_BACKTRACE": "full"},
    }
    return dict(profiles.get(language, {"HARNESS_LANGUAGE": language or "generic"}))


def language_build_hints(language: str) -> list[str]:
    return []


def default_dump_globs(language: str) -> list[str]:
    globs = {
        "c": ["core*", "*.core"],
        "c++": ["core*", "*.core"],
        "go": ["*.panic", "panic.log", "core*"],
        "java": ["hs_err_pid*.log", "*.hprof"],
        "python": ["*.traceback", "traceback*.log"],
        "node": ["*.node-crash.log"],
        "rust": ["core*", "panic*.log"],
    }
    return list(globs.get(language, []))


def language_notes(language: str) -> list[str]:
    notes = {
        "c": ["Native C targets benefit from ASan/UBSan or valgrind-backed replay in isolated builds."],
        "c++": ["C++ targets often need symbolized sanitizer builds and allocator-aware review of adjacent objects."],
        "go": ["Go services benefit from panic traces, race-enabled variants, and explicit goroutine context capture."],
        "java": ["JVM targets benefit from hs_err logs, heap dumps, and explicit framework-specific request replay."],
        "python": ["Python targets often require traceback preservation, faulthandler output, and dependency pinning for replay fidelity."],
        "node": ["Node targets benefit from uncaught exception traces and explicit event-loop state capture."],
        "rust": ["Rust targets benefit from full backtraces and panic strategy awareness when replaying crash paths."],
    }
    return list(notes.get(language, []))


def product_notes(product_type: str) -> list[str]:
    notes = {
        "file-parser": ["Prefer PoC-preserving file variants over blind fuzz-like expansion when validating parser reports."],
        "service": ["Service targets should declare ports, startup sequencing, and health checks to keep replay deterministic."],
        "web-app": ["Web targets should encode authentication state, route, method, and body shape explicitly in replay steps."],
        "openapi": ["OpenAPI targets should keep path parameter, query, header, and schema version changes explicit in variants."],
        "grpc": ["gRPC targets should preserve method name, metadata, and serialized message fields explicitly."],
        "library": ["Library targets should include the smallest deterministic harness binary or script that reproduces the call path."],
        "jni-library": ["JNI targets should preserve Java-side exception state and native-side crash artifacts together."],
        "native-harness": ["Native harness targets should keep argv, env, symbols, and dump collection deterministic."],
        "cli-tool": ["CLI targets should preserve exact argv, cwd, stdin shape, and filesystem preconditions."],
    }
    return list(notes.get(product_type, []))


def dedupe_strings(items: list[str]) -> list[str]:
    seen: set[str] = set()
    ordered: list[str] = []
    for item in items:
        if item and item not in seen:
            seen.add(item)
            ordered.append(item)
    return ordered


def dedupe_paths(items: list) -> list:
    seen: set[str] = set()
    ordered = []
    for item in items:
        key = str(item)
        if key not in seen:
            seen.add(key)
            ordered.append(item)
    return ordered
