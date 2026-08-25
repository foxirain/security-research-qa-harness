from __future__ import annotations

from pathlib import Path
import tomllib

from .models import (
    AdapterConfig,
    AuthenticationConfig,
    BoundaryAxis,
    BoundaryConfig,
    CaseDefinition,
    ExecutionStep,
    GrpcReplay,
    OpenAPIReplay,
    ReplayConfig,
    ReportMetadata,
    Target,
)


def load_case(path: Path) -> CaseDefinition:
    data = tomllib.loads(path.read_text(encoding="utf-8"))
    target_root = _resolve_path(path.parent, data["target"]["root"])

    metadata = ReportMetadata(
        report_id=data["report"]["id"],
        title=data["report"]["title"],
        reporter=data["report"].get("reporter", "unknown"),
        category=data["report"]["category"],
        claim=data["report"]["claim"],
        attack_surface=data["report"]["attack_surface"],
        exposure=data["report"].get("exposure", "unknown"),
        privileges_required=data["report"].get("privileges_required", "unknown"),
        user_interaction=data["report"].get("user_interaction", "unknown"),
        input_origin=data["report"].get("input_origin", "unknown"),
        repeatability=data["report"].get("repeatability", "unknown"),
        assets=list(data["report"].get("assets", [])),
        notes=data["report"].get("notes", ""),
    )

    target = Target(
        name=data["target"]["name"],
        root=target_root,
        adapter=data["target"].get("adapter", data.get("adapter", {}).get("kind", "generic")),
        setup=list(data["target"].get("setup", [])),
        cleanup=list(data["target"].get("cleanup", [])),
    )

    auth_data = data.get("auth", {})
    auth = AuthenticationConfig(
        mode=auth_data.get("mode", "none"),
        bearer_token=str(auth_data.get("bearer_token", "")),
        cookie=str(auth_data.get("cookie", "")),
        headers={key: str(value) for key, value in auth_data.get("headers", {}).items()},
        login_command=str(auth_data.get("login_command", "")),
        notes=list(auth_data.get("notes", [])),
    )

    adapter_data = data.get("adapter", {})
    adapter = AdapterConfig(
        kind=adapter_data.get("kind", target.adapter),
        product_type=adapter_data.get("product_type", adapter_data.get("kind", target.adapter)),
        language=adapter_data.get("language", "generic"),
        framework=adapter_data.get("framework", "unknown"),
        sanitizer_profile=adapter_data.get("sanitizer_profile", "none"),
        build_commands=list(adapter_data.get("build_commands", [])),
        start_commands=list(adapter_data.get("start_commands", [])),
        stop_commands=list(adapter_data.get("stop_commands", [])),
        runtime_env={key: str(value) for key, value in adapter_data.get("runtime_env", {}).items()},
        extra_artifacts=[_resolve_path(target_root, item) for item in adapter_data.get("extra_artifacts", [])],
        dump_globs=[str(item) for item in adapter_data.get("dump_globs", [])],
        ports=[int(item) for item in adapter_data.get("ports", [])],
        healthcheck=str(adapter_data.get("healthcheck", "")),
        startup_timeout_seconds=int(adapter_data.get("startup_timeout_seconds", 30)),
        healthcheck_interval_seconds=float(adapter_data.get("healthcheck_interval_seconds", 1.0)),
        notes=list(adapter_data.get("notes", [])),
    )

    replay = _load_replay(data.get("replay", {}))
    boundary = _load_boundary(data.get("boundary", {}))
    variables = {key: str(value) for key, value in data.get("variables", {}).items()}
    steps: list[ExecutionStep] = []
    for step_data in data["steps"]:
        cwd = _resolve_path(target_root, step_data.get("cwd", "."))
        steps.append(
            ExecutionStep(
                name=step_data["name"],
                command=step_data.get("command", ""),
                objective=step_data.get("objective", ""),
                cwd=cwd,
                timeout_seconds=int(step_data.get("timeout_seconds", 120)),
                expected_exit_codes=list(step_data.get("expected_exit_codes", [0])),
                env={key: str(value) for key, value in step_data.get("env", {}).items()},
                collect_paths=[_resolve_path(target_root, item) for item in step_data.get("collect_paths", [])],
                tags=list(step_data.get("tags", [])),
            )
        )

    return CaseDefinition(metadata=metadata, target=target, auth=auth, adapter=adapter, replay=replay, boundary=boundary, variables=variables, steps=steps)


def _load_replay(data: dict) -> ReplayConfig:
    openapi_data = data.get("openapi", {})
    grpc_data = data.get("grpc", {})
    return ReplayConfig(
        mode=str(data.get("mode", "none")),
        openapi=OpenAPIReplay(
            spec=str(openapi_data.get("spec", "")),
            path=str(openapi_data.get("path", "")),
            method=str(openapi_data.get("method", "GET")),
            content_type=str(openapi_data.get("content_type", "application/json")),
            body_variable=str(openapi_data.get("body_variable", "")),
            target_url_variable=str(openapi_data.get("target_url_variable", "TARGET_URL")),
            extra_headers_variable=str(openapi_data.get("extra_headers_variable", "HTTP_EXTRA_HEADERS")),
            query_variable=str(openapi_data.get("query_variable", "HTTP_QUERY")),
            curl_options=[str(item) for item in openapi_data.get("curl_options", [])],
        ),
        grpc=GrpcReplay(
            target=str(grpc_data.get("target", "")),
            target_variable=str(grpc_data.get("target_variable", "GRPC_TARGET")),
            service=str(grpc_data.get("service", "")),
            method=str(grpc_data.get("method", "")),
            request_file=str(grpc_data.get("request_file", "")),
            request_file_variable=str(grpc_data.get("request_file_variable", "")),
            plaintext=bool(grpc_data.get("plaintext", True)),
            use_reflection=bool(grpc_data.get("use_reflection", True)),
            import_paths=[str(item) for item in grpc_data.get("import_paths", [])],
            proto_files=[str(item) for item in grpc_data.get("proto_files", [])],
            extra_metadata_variable=str(grpc_data.get("extra_metadata_variable", "GRPC_METADATA")),
            grpcurl_options=[str(item) for item in grpc_data.get("grpcurl_options", [])],
        ),
    )


def _load_boundary(data: dict) -> BoundaryConfig:
    axes: list[BoundaryAxis] = []
    for axis_data in data.get("axes", []):
        axes.append(
            BoundaryAxis(
                name=axis_data["name"],
                kind=axis_data["kind"],
                variable=axis_data.get("variable"),
                env_key=axis_data.get("env_key"),
                target_file_variable=axis_data.get("target_file_variable"),
                values=[str(item) for item in axis_data.get("values", [])],
                sizes=[int(item) for item in axis_data.get("sizes", [])],
                character=str(axis_data.get("character", "A")),
                token=axis_data.get("token"),
                content=str(axis_data.get("content", "A")),
                counts=[int(item) for item in axis_data.get("counts", [])],
                step_name=axis_data.get("step_name"),
                description=axis_data.get("description", ""),
                header_name=axis_data.get("header_name"),
                query_name=axis_data.get("query_name"),
            )
        )
    return BoundaryConfig(bool(data.get("enabled", False)), int(data.get("max_variants", 12)), int(data.get("combine_depth", 1)), axes)


def _resolve_path(base: Path, raw: str | None) -> Path:
    if raw is None:
        return base.resolve()
    candidate = Path(raw)
    if candidate.is_absolute():
        return candidate.resolve()
    return (base / candidate).resolve()
