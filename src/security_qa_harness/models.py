from __future__ import annotations

from dataclasses import asdict, dataclass, field
from pathlib import Path
from typing import Any


@dataclass(slots=True)
class Target:
    name: str
    root: Path
    adapter: str = "generic"
    setup: list[str] = field(default_factory=list)
    cleanup: list[str] = field(default_factory=list)


@dataclass(slots=True)
class ExecutionStep:
    name: str
    command: str = ""
    objective: str = ""
    cwd: Path | None = None
    timeout_seconds: int = 120
    expected_exit_codes: list[int] = field(default_factory=lambda: [0])
    env: dict[str, str] = field(default_factory=dict)
    collect_paths: list[Path] = field(default_factory=list)
    tags: list[str] = field(default_factory=list)


@dataclass(slots=True)
class AuthenticationConfig:
    mode: str = "none"
    bearer_token: str = ""
    cookie: str = ""
    headers: dict[str, str] = field(default_factory=dict)
    login_command: str = ""
    notes: list[str] = field(default_factory=list)


@dataclass(slots=True)
class AdapterConfig:
    kind: str = "generic"
    product_type: str = "generic"
    language: str = "generic"
    framework: str = "unknown"
    sanitizer_profile: str = "none"
    build_commands: list[str] = field(default_factory=list)
    start_commands: list[str] = field(default_factory=list)
    stop_commands: list[str] = field(default_factory=list)
    runtime_env: dict[str, str] = field(default_factory=dict)
    extra_artifacts: list[Path] = field(default_factory=list)
    dump_globs: list[str] = field(default_factory=list)
    ports: list[int] = field(default_factory=list)
    healthcheck: str = ""
    startup_timeout_seconds: int = 30
    healthcheck_interval_seconds: float = 1.0
    notes: list[str] = field(default_factory=list)


@dataclass(slots=True)
class OpenAPIReplay:
    spec: str = ""
    path: str = ""
    method: str = "GET"
    content_type: str = "application/json"
    body_variable: str = ""
    target_url_variable: str = "TARGET_URL"
    extra_headers_variable: str = "HTTP_EXTRA_HEADERS"
    query_variable: str = "HTTP_QUERY"
    curl_options: list[str] = field(default_factory=list)


@dataclass(slots=True)
class GrpcReplay:
    target: str = ""
    target_variable: str = "GRPC_TARGET"
    service: str = ""
    method: str = ""
    request_file: str = ""
    request_file_variable: str = ""
    plaintext: bool = True
    use_reflection: bool = True
    import_paths: list[str] = field(default_factory=list)
    proto_files: list[str] = field(default_factory=list)
    extra_metadata_variable: str = "GRPC_METADATA"
    grpcurl_options: list[str] = field(default_factory=list)


@dataclass(slots=True)
class ReplayConfig:
    mode: str = "none"
    openapi: OpenAPIReplay = field(default_factory=OpenAPIReplay)
    grpc: GrpcReplay = field(default_factory=GrpcReplay)


@dataclass(slots=True)
class BoundaryAxis:
    name: str
    kind: str
    variable: str | None = None
    env_key: str | None = None
    target_file_variable: str | None = None
    values: list[str] = field(default_factory=list)
    sizes: list[int] = field(default_factory=list)
    character: str = "A"
    token: str | None = None
    content: str = "A"
    counts: list[int] = field(default_factory=list)
    step_name: str | None = None
    description: str = ""
    header_name: str | None = None
    query_name: str | None = None


@dataclass(slots=True)
class BoundaryConfig:
    enabled: bool = False
    max_variants: int = 12
    combine_depth: int = 1
    axes: list[BoundaryAxis] = field(default_factory=list)


@dataclass(slots=True)
class ReportMetadata:
    report_id: str
    title: str
    reporter: str
    category: str
    claim: str
    attack_surface: str
    exposure: str = "unknown"
    privileges_required: str = "unknown"
    user_interaction: str = "unknown"
    input_origin: str = "unknown"
    repeatability: str = "unknown"
    assets: list[str] = field(default_factory=list)
    notes: str = ""


@dataclass(slots=True)
class CaseDefinition:
    metadata: ReportMetadata
    target: Target
    auth: AuthenticationConfig
    adapter: AdapterConfig
    replay: ReplayConfig
    boundary: BoundaryConfig
    variables: dict[str, str]
    steps: list[ExecutionStep]


@dataclass(slots=True)
class StepResult:
    name: str
    objective: str
    tags: list[str]
    command: str
    cwd: str
    exit_code: int
    expected: bool
    duration_seconds: float
    stdout: str
    stderr: str
    collected_artifacts: list[str]


@dataclass(slots=True)
class CrashSignal:
    kind: str
    summary: str
    access_type: str | None = None
    memory_region: str | None = None
    fault_address: str | None = None
    pc: str | None = None
    allocator_state: str | None = None
    adjacency: str | None = None
    stack_excerpt: list[str] = field(default_factory=list)


@dataclass(slots=True)
class MemoryRiskLens:
    exploitability_review_needed: bool
    corruption_class: str
    allocator_state: str
    adjacency: str
    control_data_proximity: str
    likely_impacted_asset: str
    review_cues: list[str]
    analyst_boundaries: list[str]


@dataclass(slots=True)
class RuntimeObservation:
    kind: str
    source: str
    summary: str
    path: str | None = None


@dataclass(slots=True)
class ArtifactDiff:
    added_artifacts: list[str] = field(default_factory=list)
    removed_artifacts: list[str] = field(default_factory=list)
    added_runtime_observations: list[str] = field(default_factory=list)
    removed_runtime_observations: list[str] = field(default_factory=list)
    changed_step_outputs: list[str] = field(default_factory=list)
    summary: list[str] = field(default_factory=list)


@dataclass(slots=True)
class ImpactAssessment:
    verdict: str
    confidence: str
    priority: str
    exploitability_review_needed: bool
    availability_risk: str
    integrity_risk: str
    confidentiality_risk: str
    reasoning: list[str]
    boundaries: list[str]
    next_actions: list[str]


@dataclass(slots=True)
class BoundaryVariant:
    name: str
    description: str
    variable_overrides: dict[str, str] = field(default_factory=dict)
    step_env_overrides: dict[str, dict[str, str]] = field(default_factory=dict)
    staged_files: dict[str, str] = field(default_factory=dict)


@dataclass(slots=True)
class BoundaryVariantResult:
    name: str
    description: str
    changes: list[str]
    impact: ImpactAssessment
    memory_lens: MemoryRiskLens
    crash_signals: list[CrashSignal]
    runtime_observations: list[RuntimeObservation]
    artifact_diff: ArtifactDiff
    steps: list[StepResult]
    output_dir: Path


@dataclass(slots=True)
class BoundaryExplorationSummary:
    enabled: bool
    attempted_variants: int
    interesting_variants: int
    highest_risk_variant: str | None
    findings: list[str]
    variants: list[BoundaryVariantResult]


@dataclass(slots=True)
class ExecutiveSummary:
    headline: str
    confirmed_impact: list[str]
    unproven_claims: list[str]
    immediate_actions: list[str]
    business_context: list[str]


@dataclass(slots=True)
class AnalysisResult:
    report: ReportMetadata
    auth: AuthenticationConfig
    adapter: AdapterConfig
    replay: ReplayConfig
    steps: list[StepResult]
    crash_signals: list[CrashSignal]
    runtime_observations: list[RuntimeObservation]
    memory_lens: MemoryRiskLens
    impact: ImpactAssessment
    boundary: BoundaryExplorationSummary
    executive: ExecutiveSummary
    output_dir: Path

    def to_dict(self) -> dict[str, Any]:
        payload = asdict(self)
        auth = payload["auth"]
        auth["bearer_token"] = "[REDACTED]" if auth["bearer_token"] else ""
        auth["cookie"] = "[REDACTED]" if auth["cookie"] else ""
        auth["headers"] = {
            key: "[REDACTED]" if value else ""
            for key, value in auth["headers"].items()
        }
        auth["login_command"] = "[REDACTED]" if auth["login_command"] else ""
        return normalize(payload)


def normalize(value: Any) -> Any:
    if isinstance(value, Path):
        return str(value)
    if isinstance(value, dict):
        return {key: normalize(item) for key, item in value.items()}
    if isinstance(value, list):
        return [normalize(item) for item in value]
    return value
