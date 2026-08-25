from __future__ import annotations

import shlex

from .models import ReplayConfig


def generate_command(command_template: str, replay: ReplayConfig, variables: dict[str, str]) -> str:
    if command_template:
        return command_template.format(**variables)
    if replay.mode == "openapi":
        return generate_openapi_command(replay, variables)
    if replay.mode == "grpc":
        return generate_grpc_command(replay, variables)
    raise ValueError("Step has no command and no supported replay mode is configured")


def generate_openapi_command(replay: ReplayConfig, variables: dict[str, str]) -> str:
    config = replay.openapi
    base_url = _lookup(variables, config.target_url_variable, required=True)
    path = config.path.format(**variables)
    method = variables.get("HTTP_METHOD", config.method).upper()
    query = variables.get(config.query_variable, "") if config.query_variable else ""
    extra_headers = []
    auth_headers = variables.get("AUTH_HTTP_HEADERS", "").strip()
    if auth_headers:
        extra_headers.append(auth_headers)
    if config.extra_headers_variable:
        extra = variables.get(config.extra_headers_variable, "").strip()
        if extra:
            extra_headers.append(extra)
    options = ["curl", "-sS", "-X", shlex.quote(method)]
    for item in config.curl_options:
        options.append(item.format(**variables))
    options.extend(extra_headers)
    if config.content_type:
        options.extend(["-H", shlex.quote(f"content-type: {config.content_type}")])
    if config.body_variable:
        body_path = _lookup(variables, config.body_variable, required=True)
        options.append(f"--data-binary @{shlex.quote(body_path)}")
    options.append(shlex.quote(f"{base_url}{path}{query}"))
    return " ".join(options)


def generate_grpc_command(replay: ReplayConfig, variables: dict[str, str]) -> str:
    config = replay.grpc
    target = variables.get(config.target_variable, config.target).strip()
    if not target:
        raise ValueError("gRPC replay requires a target or target_variable")
    fq_method = f"{config.service}/{config.method}".strip("/")
    if "/" not in fq_method:
        raise ValueError("gRPC replay requires both service and method")
    request_file = config.request_file
    if config.request_file_variable:
        request_file = _lookup(variables, config.request_file_variable, required=True)
    command = ["grpcurl"]
    if config.plaintext:
        command.append("-plaintext")
    for item in config.grpcurl_options:
        command.append(item.format(**variables))
    metadata = variables.get("GRPC_AUTH_METADATA", "").strip()
    if metadata:
        command.append(metadata)
    if config.extra_metadata_variable:
        extra_metadata = variables.get(config.extra_metadata_variable, "").strip()
        if extra_metadata:
            command.append(extra_metadata)
    if not config.use_reflection:
        for path in config.import_paths:
            command.extend(["-import-path", shlex.quote(path.format(**variables))])
        for proto in config.proto_files:
            command.extend(["-proto", shlex.quote(proto.format(**variables))])
    if request_file:
        command.append(f"-d @ < {shlex.quote(request_file)}")
    command.extend([shlex.quote(target), shlex.quote(fq_method)])
    return " ".join(command)


def _lookup(variables: dict[str, str], key: str, required: bool = False) -> str:
    value = variables.get(key, "").strip()
    if required and not value:
        raise ValueError(f"Required replay variable `{key}` is missing")
    return value
