from __future__ import annotations

from dataclasses import dataclass
from datetime import UTC, datetime
from pathlib import Path
import json
import os
import re

from .adapters import resolve_adapter
from .analyzer import analyze
from .boundary import explore_boundaries
from .collectors import collect_runtime_observations
from .config import load_case
from .executor import auth_redaction_values, prepare_steps, run_steps
from .intake import IntakeFinding, build_selected_findings, parse_findings, render_summary
from .models import AnalysisResult, BoundaryExplorationSummary, ExecutiveSummary, ImpactAssessment, RuntimeObservation, StepResult
from .orchestration import managed_target
from .reporting import write_outputs


@dataclass(slots=True)
class RepoProfile:
    root: Path
    languages: list[str]
    build_systems: list[str]
    openapi_specs: list[str]
    proto_files: int
    likely_test_command: str
    command_confidence: str
    notes: list[str]


@dataclass(slots=True)
class CommandCandidate:
    command: str
    confidence: str
    rationale: str
    matched_paths: list[str]


IGNORED_REPO_DIRS = {
    ".git",
    ".hg",
    ".cache",
    ".mypy_cache",
    ".next",
    ".pytest_cache",
    ".svn",
    ".tox",
    ".venv",
    "__pycache__",
    "build",
    "dist",
    "intake-runs",
    "htmlcov",
    "node_modules",
    "oss-runs",
    "out",
    "runs",
    "target",
    "venv",
}

OPERATIONAL_FAILURE_PATTERNS = (
    (re.compile(r"no module named (?:pytest|unittest|tox)\b", re.IGNORECASE), "required test runner is unavailable"),
    (re.compile(r"(?:command not found|not recognized as an internal or external command)", re.IGNORECASE), "command is unavailable"),
    (re.compile(r"(?:cannot|can't) open file .+\[errno 2\]", re.IGNORECASE), "entrypoint file is missing"),
    (re.compile(r"(?:no tests (?:ran|collected)|collected 0 items)", re.IGNORECASE), "the selected command collected no tests"),
)

TRAVERSAL_ENTRY_RE = re.compile(r"(?:^|[\s=:\"'])\.\.[\\/](?:\.\.[\\/])*[^\s\"']+", re.MULTILINE)
STACK_RUNTIME_RE = re.compile(
    r"(?:addresssanitizer:\s*(?:stack|stack-buffer)-overflow|recursionerror)",
    re.IGNORECASE,
)


def triage_ranked_report_against_repo(
    report_path: Path,
    repo_path: Path,
    output_root: Path,
    allowed_tiers: tuple[str, ...] = ("S", "A", "B"),
    top_n: int = 5,
    execute: bool = False,
) -> Path:
    report_path = report_path.resolve()
    repo_path = repo_path.resolve()
    timestamp = datetime.now(UTC).strftime("%Y%m%dT%H%M%SZ")
    output_dir = output_root.resolve() / (report_path.stem.lower().replace(" ", "-") + "-" + timestamp)
    output_dir.mkdir(parents=True, exist_ok=True)

    findings = parse_findings(report_path.read_text(encoding="utf-8"))
    selected = build_selected_findings(findings, allowed_tiers, top_n)
    profile = discover_repo(repo_path)

    drafts_dir = output_dir / "drafts"
    drafts_dir.mkdir(parents=True, exist_ok=True)
    runs_dir = output_dir / "runs"
    if execute:
        runs_dir.mkdir(parents=True, exist_ok=True)

    executions: list[dict[str, object]] = []
    selected_payload: list[dict[str, object]] = []
    for finding in selected:
        finding_artifacts_dir = output_dir / "artifacts" / finding.finding_id
        repro_assets = synthesize_inputs_for_finding(finding, finding_artifacts_dir)
        generated_inputs = generated_input_paths(repro_assets)
        command_candidate = select_command_for_finding(finding, profile)
        case_path = drafts_dir / (finding.finding_id + ".toml")
        case_path.write_text(render_repo_toml_draft(finding, report_path, profile, command_candidate, repro_assets), encoding="utf-8")
        if execute and command_candidate.command.strip():
            status = execute_generated_case(case_path, runs_dir)
        elif execute:
            status = {
                "case": str(case_path),
                "status": "operational-failure",
                "claim_assessment": "operational-failure",
                "operational_failures": ["No runnable repository command was inferred; review and complete the draft manually."],
            }
        else:
            status = {"case": str(case_path), "status": "not-executed"}
        status["selected_command"] = command_candidate.command
        status["command_confidence"] = command_candidate.confidence
        status["command_rationale"] = command_candidate.rationale
        status["matched_paths"] = command_candidate.matched_paths
        status["generated_inputs"] = generated_inputs
        status["generated_input_provenance"] = "harness-generated-input-not-observed-evidence"
        executions.append(status)
        selected_payload.append(
            {
                "finding_id": finding.finding_id,
                "title": finding.title,
                "tier": finding.tier,
                "draft": str(case_path),
                "selected_command": command_candidate.command,
                "command_confidence": command_candidate.confidence,
                "generated_inputs": generated_inputs,
                "generated_input_provenance": "harness-generated-input-not-observed-evidence",
                "run_status": status["status"],
                "claim_assessment": status.get("claim_assessment", ""),
                "result_dir": status.get("result_dir", ""),
            }
        )

    (output_dir / "repo_profile.json").write_text(json.dumps(repo_profile_to_dict(profile), indent=2), encoding="utf-8")
    (output_dir / "triage_summary.json").write_text(
        json.dumps(
            {
                "report": str(report_path),
                "repo": str(repo_path),
                "allowed_tiers": list(allowed_tiers),
                "top_n": top_n,
                "execution_requested": execute,
                "selected_findings": selected_payload,
                "executions": executions,
                "repo_profile": repo_profile_to_dict(profile),
            },
            indent=2,
        ),
        encoding="utf-8",
    )
    (output_dir / "intake_summary.md").write_text(render_summary(report_path, findings, selected, allowed_tiers, top_n), encoding="utf-8")
    (output_dir / "triage_summary.md").write_text(render_triage_summary(report_path, repo_path, profile, selected, executions), encoding="utf-8")
    return output_dir


def discover_repo(root: Path) -> RepoProfile:
    languages: list[str] = []
    build_systems: list[str] = []
    notes: list[str] = []
    openapi_specs: list[str] = []
    proto_files = 0

    if (root / "go.mod").exists():
        languages.append("go")
        build_systems.append("go-mod")
    if (root / "Cargo.toml").exists():
        languages.append("rust")
        build_systems.append("cargo")
    if (root / "pyproject.toml").exists() or (root / "setup.py").exists():
        languages.append("python")
        build_systems.append("python-build")
    if (root / "package.json").exists():
        languages.append("node")
        build_systems.append("npm")
    if (root / "pom.xml").exists():
        languages.append("java")
        build_systems.append("maven")
    if (root / "build.gradle").exists() or (root / "build.gradle.kts").exists() or (root / "gradlew").exists():
        languages.append("java")
        build_systems.append("gradle")
    if (root / "CMakeLists.txt").exists():
        languages.extend(["c", "c++"])
        build_systems.append("cmake")
    if (root / "Makefile").exists():
        build_systems.append("make")

    api_spec_names = {"openapi.yaml", "openapi.yml", "swagger.yaml", "swagger.yml"}
    for path in iter_repo_files(root):
        if path.suffix == ".proto" and proto_files <= 2000:
            proto_files += 1
        if path.name in api_spec_names and len(openapi_specs) < 10:
            openapi_specs.append(str(path.relative_to(root)))

    languages = dedupe(languages)
    build_systems = dedupe(build_systems)
    openapi_specs = dedupe(openapi_specs)
    command, confidence = infer_test_command(root, languages, build_systems)
    if proto_files:
        notes.append("Repository contains %s .proto file(s)." % proto_files)
    if openapi_specs:
        notes.append("OpenAPI or Swagger specs were found and can drive declarative HTTP replay.")
    if not command:
        notes.append("No reliable repository-wide test command was inferred.")
    else:
        notes.append("Auto-selected repository test command: %s" % command)
    return RepoProfile(
        root=root,
        languages=languages,
        build_systems=build_systems,
        openapi_specs=openapi_specs,
        proto_files=proto_files,
        likely_test_command=command,
        command_confidence=confidence,
        notes=notes,
    )


def infer_test_command(root: Path, languages: list[str], build_systems: list[str]) -> tuple[str, str]:
    if "python-build" in build_systems:
        scope = "python" if (root / "python").exists() else "."
        return "python3 -m pytest -q %s" % scope, "medium"
    if "cargo" in build_systems:
        return "cargo test -- --nocapture", "medium"
    if "go-mod" in build_systems:
        return "go test ./...", "medium"
    if "gradle" in build_systems and (root / "gradlew").exists():
        return "./gradlew test", "medium"
    if "maven" in build_systems:
        return "mvn -q test", "medium"
    if "npm" in build_systems:
        return "npm test -- --runInBand", "low"
    if "cmake" in build_systems:
        return "ctest --output-on-failure", "low"
    if "make" in build_systems:
        return "make test", "low"
    if "java" in languages:
        return "./gradlew test", "low"
    return "", "none"


def choose_adapter(finding: IntakeFinding, profile: RepoProfile) -> str:
    if finding.attack_surface == "archive-output" and profile.proto_files:
        return "file-parser"
    if finding.attack_surface == "protobuf-text-format" and "python" in profile.languages:
        return "cli-tool"
    if profile.openapi_specs:
        return "openapi"
    if profile.proto_files:
        return "file-parser"
    if any(item in profile.build_systems for item in ["gradle", "maven", "go-mod"]):
        return "service"
    return "generic"


def render_repo_toml_draft(
    finding: IntakeFinding,
    report_path: Path,
    profile: RepoProfile,
    command_candidate: CommandCandidate,
    repro_assets: dict[str, str],
) -> str:
    adapter = choose_adapter(finding, profile)
    language = profile.languages[0] if profile.languages else "generic"
    command = command_candidate.command
    healthcheck = ""
    product_type = adapter
    replay_mode = "none"
    if adapter == "openapi" and profile.openapi_specs:
        product_type = "openapi"
        replay_mode = "openapi"
    claim = finding.summary.replace('"', "'")
    title = finding.title.replace('"', "'")
    notes = [
        "Source report: %s" % report_path,
        "Auto-generated from ranked report plus OSS repo discovery.",
        "Repo languages: %s" % (", ".join(profile.languages) or "unknown"),
        "Build systems: %s" % (", ".join(profile.build_systems) or "unknown"),
        "Command confidence: %s" % command_candidate.confidence,
        "Command rationale: %s" % command_candidate.rationale,
        "POC_FILE, REQUEST_FILE, and PROTO_FILE are harness-generated inputs, not observed target evidence.",
    ] + finding.analyst_notes + profile.notes
    notes_text = "; ".join(item.replace('"', "'") for item in notes)
    variables_block = build_variables_block(repro_assets)
    replay_block = "[replay]\nmode = \"%s\"\n" % replay_mode
    if replay_mode == "openapi":
        replay_block += (
            "\n[replay.openapi]\n"
            "spec = \"%s\"\n"
            "path = \"/\"\n"
            "method = \"GET\"\n"
            "content_type = \"application/json\"\n"
            "body_variable = \"POC_FILE\"\n"
            "target_url_variable = \"TARGET_URL\"\n"
            "extra_headers_variable = \"HTTP_EXTRA_HEADERS\"\n"
            "query_variable = \"HTTP_QUERY\"\n"
        ) % profile.openapi_specs[0]
    if adapter == "service":
        healthcheck = "healthcheck = \"http://127.0.0.1:8080/\"\nports = [8080]\n"
    boundary_block = render_boundary_block(finding)
    return """[report]
id = \"{finding_id}\"
title = \"{title}\"
reporter = \"unknown\"
category = \"{bug_class}\"
claim = \"{claim}\"
attack_surface = \"{attack_surface}\"
exposure = \"unknown\"
privileges_required = \"unknown\"
user_interaction = \"unknown\"
input_origin = \"report-derived\"
repeatability = \"unknown\"
assets = [\"report-derived\"]
notes = \"{notes}\"

[target]
name = \"{repo_name}\"
root = \"{repo_root}\"
adapter = \"{adapter}\"
setup = []
cleanup = []

[adapter]
kind = \"{adapter}\"
product_type = \"{product_type}\"
language = \"{language}\"
framework = \"unknown\"
sanitizer_profile = \"none\"
{healthcheck}notes = [\"Auto-generated OSS repo case. Replace the command only if repo-specific reproduction is known.\"]

{replay_block}[variables]
{variables_block}{boundary_block}
[[steps]]
name = \"Auto-discovered repo replay\"
objective = \"Use repository-wide or finding-targeted entrypoints to validate the top-ranked finding\"
tags = [\"auto-generated\", \"tier-{tier}\", \"repo-discovery\"]
command = \"{command}\"
cwd = \".\"
timeout_seconds = 180
expected_exit_codes = [0]
collect_paths = []
""".format(
        finding_id=finding.finding_id,
        title=title,
        bug_class=finding.bug_class,
        claim=claim,
        attack_surface=finding.attack_surface,
        notes=notes_text,
        repo_name=profile.root.name,
        repo_root=str(profile.root),
        adapter=adapter,
        product_type=product_type,
        language=language,
        healthcheck=healthcheck,
        replay_block=replay_block,
        variables_block=variables_block,
        boundary_block=boundary_block,
        tier=finding.tier.lower(),
        command=command.replace('"', "'"),
    )


def execute_generated_case(case_path: Path, runs_dir: Path) -> dict[str, object]:
    try:
        raw_case = load_case(case_path)
        case = resolve_adapter(raw_case.adapter).plan(raw_case)
        # Auto-generated cases have no trustworthy artifact provenance yet.
        # Restrict observations to this run's stdout/stderr until an analyst
        # adds explicit target-owned collection paths to the reviewed draft.
        case.adapter.dump_globs = []
        case.adapter.extra_artifacts = []
        timestamp = datetime.now(UTC).strftime("%Y%m%dT%H%M%SZ")
        output_dir = runs_dir / (case.metadata.report_id + "-" + timestamp)
        output_dir.mkdir(parents=True, exist_ok=True)
        with managed_target(case):
            steps = prepare_steps(case)
            results = run_steps(steps, output_dir, auth_redaction_values(case))
            crash_signals, memory_lens, impact = analyze(case.metadata, results)
            runtime_observations = collect_runtime_observations(case.adapter, results, case.target.root)
            operational_failures = detect_operational_failures(results)
            if operational_failures:
                impact = operational_failure_impact(operational_failures)
            boundary = (
                BoundaryExplorationSummary(
                    enabled=False,
                    attempted_variants=0,
                    interesting_variants=0,
                    highest_risk_variant=None,
                    findings=["Boundary exploration was skipped because the base command did not run successfully."],
                    variants=[],
                )
                if operational_failures
                else explore_boundaries(case, output_dir, results, runtime_observations)
            )
            executive = build_executive_summary(
                case,
                impact,
                memory_lens,
                runtime_observations,
                boundary,
                operational_failures,
            )
            analysis = AnalysisResult(case.metadata, case.auth, case.adapter, case.replay, results, crash_signals, runtime_observations, memory_lens, impact, boundary, executive, output_dir)
            write_outputs(analysis)
        claim_assessment = assess_claim(
            case.metadata.claim,
            case.metadata.category,
            impact.verdict,
            memory_lens.corruption_class,
            runtime_observations,
            results,
            operational_failures,
        )
        write_claim_assessment(output_dir, claim_assessment)
        append_claim_assessment_to_reports(output_dir, claim_assessment)
        status = "operational-failure" if operational_failures else "completed"
        return {
            "case": str(case_path),
            "status": status,
            "result_dir": str(output_dir),
            "claim_assessment": claim_assessment["verdict"],
            "operational_failures": operational_failures,
        }
    except Exception as exc:
        return {"case": str(case_path), "status": "failed", "error": str(exc)}


def build_executive_summary(
    case,
    impact,
    memory_lens,
    runtime_observations,
    boundary,
    operational_failures: list[str] | None = None,
) -> ExecutiveSummary:
    operational_failures = operational_failures or []
    top_variant = next((item for item in boundary.variants if item.name == boundary.highest_risk_variant), None)
    highest_boundary = top_variant.memory_lens.corruption_class if top_variant else memory_lens.corruption_class
    review_status = "required" if impact.exploitability_review_needed or top_variant else "not yet justified by current evidence"
    headline = (
        f"Report `{case.metadata.report_id}` is `{impact.verdict}` with priority `{impact.priority}`. "
        f"The highest confirmed tested boundary is `{highest_boundary}` and manual exploitability review is `{review_status}`."
    )
    confirmed: list[str] = []
    if operational_failures:
        headline = f"Report `{case.metadata.report_id}` could not be assessed because the base command failed operationally."
        confirmed.append("No vulnerability conclusion was produced from the failed execution.")
    else:
        confirmed.extend(
            [
                f"Recorded impact verdict: `{impact.verdict}`.",
                f"Recorded risks: availability `{impact.availability_risk}`, integrity `{impact.integrity_risk}`, confidentiality `{impact.confidentiality_risk}`.",
                f"Base memory context: `{memory_lens.likely_impacted_asset}` with `{memory_lens.control_data_proximity}`.",
            ]
        )
    if runtime_observations:
        confirmed.append("Additional runtime evidence collected: " + ", ".join(obs.kind for obs in runtime_observations[:3]) + ".")
    if case.replay.mode != "none":
        confirmed.append(f"Replay command generation was driven by declarative `{case.replay.mode}` configuration.")
    if top_variant and top_variant.artifact_diff.summary:
        confirmed.append("Boundary variant changed observable artifacts: " + top_variant.artifact_diff.summary[0])
    unproven = [
        "No remote code execution or weaponized exploit chain was demonstrated by this harness.",
        "Repository-wide or test-targeted execution remains heuristic and may still need a smaller reproducer.",
    ]
    immediate = list(impact.next_actions[:3])
    if operational_failures:
        unproven.insert(0, "The reported behavior was not evaluated because the execution environment was incomplete.")
        immediate = ["Fix the execution environment, then rerun the unchanged base case."]
        immediate.extend(operational_failures)
    immediate.append("Review auto-generated repo commands before using the result for severity sign-off.")
    business = [
        f"Attack surface is `{case.metadata.attack_surface}`.",
        f"Product type is `{case.adapter.product_type}` on language `{case.adapter.language}`.",
        f"Replay mode is `{case.replay.mode}`.",
    ]
    return ExecutiveSummary(headline, confirmed, unproven, immediate, business)


def render_triage_summary(
    report_path: Path,
    repo_path: Path,
    profile: RepoProfile,
    findings: list[IntakeFinding],
    executions: list[dict[str, object]],
) -> str:
    lines = [
        "# OSS Triage Summary",
        "",
        "- Report: `%s`" % report_path,
        "- Repo: `%s`" % repo_path,
        "- Languages: `%s`" % (", ".join(profile.languages) or "unknown"),
        "- Build systems: `%s`" % (", ".join(profile.build_systems) or "unknown"),
        "- Auto test command: `%s`" % (profile.likely_test_command or "none"),
        "- Command confidence: `%s`" % profile.command_confidence,
        "",
        "## Selected Findings",
    ]
    for item in findings:
        lines.append("### %s" % item.finding_id)
        lines.append("- Tier: `%s`" % item.tier)
        lines.append("- Title: %s" % item.title)
        lines.append("- Bug class: `%s`" % item.bug_class)
        lines.append("- Attack surface: `%s`" % item.attack_surface)
        lines.append("")
    lines.append("## Execution Status")
    for item in executions:
        lines.append("- `%s`: `%s`" % (Path(str(item["case"])).name, item["status"]))
        if item.get("claim_assessment"):
            lines.append("- Claim assessment: `%s`" % item["claim_assessment"])
        if item.get("command_confidence"):
            lines.append("- Command confidence: `%s`" % item["command_confidence"])
        if item.get("command_rationale"):
            lines.append("- Command rationale: %s" % item["command_rationale"])
        if item.get("matched_paths"):
            lines.append("- Matched paths: %s" % ", ".join(item["matched_paths"][:5]))
        if item.get("result_dir"):
            lines.append("- Result dir: `%s`" % item["result_dir"])
        for failure in item.get("operational_failures", []):
            lines.append("- Operational failure: %s" % failure)
        if item.get("error"):
            lines.append("- Error: %s" % item["error"])
    return "\n".join(lines) + "\n"


def select_command_for_finding(finding: IntakeFinding, profile: RepoProfile) -> CommandCandidate:
    keywords = extract_keywords(finding)
    matched_paths = rank_repo_paths(profile.root, keywords)
    if "python-build" in profile.build_systems:
        return choose_python_command(profile, keywords, matched_paths)
    if "go-mod" in profile.build_systems:
        return choose_go_command(profile, matched_paths)
    if "gradle" in profile.build_systems and (profile.root / "gradlew").exists():
        return choose_gradle_command(profile, matched_paths)
    if "maven" in profile.build_systems:
        return CommandCandidate("mvn -q test", "medium", "Falling back to Maven test execution because no narrower finding-specific command was inferred.", matched_paths[:5])
    return CommandCandidate(
        profile.likely_test_command,
        profile.command_confidence,
        "Falling back to repository-wide command because no stronger finding-specific target was inferred.",
        matched_paths[:5],
    )


def choose_python_command(profile: RepoProfile, keywords: list[str], matched_paths: list[str]) -> CommandCandidate:
    test_match = next((path for path in matched_paths if path.endswith(".py") and ("test" in path.lower() or "tests/" in path.lower())), "")
    if test_match:
        return CommandCandidate(
            "python3 -m pytest -q %s" % shell_quote(test_match),
            "high",
            "Matched a Python test file to finding-specific keywords.",
            matched_paths[:5],
        )
    if matched_paths and keywords:
        keyword_expr = " or ".join(keywords[:3])
        return CommandCandidate(
            "python3 -m pytest -q . -k %s" % shell_quote(keyword_expr),
            "medium",
            "No direct Python test file match; narrowed repository tests with finding keywords.",
            matched_paths[:5],
        )
    scope = "python" if (profile.root / "python").exists() else "."
    return CommandCandidate(
        "python3 -m pytest -q %s" % scope,
        "medium",
        "Falling back to repository-wide pytest because no finding-specific Python target was inferred.",
        matched_paths[:5],
    )


def choose_go_command(profile: RepoProfile, matched_paths: list[str]) -> CommandCandidate:
    test_match = next((path for path in matched_paths if path.endswith("_test.go")), "")
    if test_match:
        pkg = str(Path(test_match).parent)
        return CommandCandidate(
            "go test ./%s" % pkg,
            "medium",
            "Matched a Go test package to the finding keywords.",
            matched_paths[:5],
        )
    return CommandCandidate("go test ./...", "medium", "Falling back to repository-wide Go tests.", matched_paths[:5])


def choose_gradle_command(profile: RepoProfile, matched_paths: list[str]) -> CommandCandidate:
    class_match = next((Path(path).stem for path in matched_paths if path.endswith(".java") or path.endswith(".kt")), "")
    if class_match:
        return CommandCandidate(
            "./gradlew test --tests %s" % shell_quote(class_match),
            "medium",
            "Matched a JVM test class name to the finding keywords.",
            matched_paths[:5],
        )
    return CommandCandidate("./gradlew test", "medium", "Falling back to repository-wide Gradle tests.", matched_paths[:5])


def synthesize_inputs_for_finding(finding: IntakeFinding, artifacts_dir: Path) -> dict[str, str]:
    artifacts_dir.mkdir(parents=True, exist_ok=True)
    outputs = {
        "POC_FILE": str((artifacts_dir / "poc-input.txt").resolve()),
        "REQUEST_FILE": str((artifacts_dir / "request.json").resolve()),
        "PROTO_FILE": str((artifacts_dir / "repro.proto").resolve()),
        "TARGET_URL": "http://127.0.0.1:8080",
        "HTTP_EXTRA_HEADERS": "",
        "HTTP_QUERY": "",
        "GRPC_TARGET": "127.0.0.1:50051",
        "GRPC_METADATA": "",
    }
    summary = finding.summary.lower()
    if finding.attack_surface == "protobuf-text-format":
        depth = 40 if finding.tier in {"S", "A"} else 20
        payload = build_nested_text_payload(depth)
        Path(outputs["POC_FILE"]).write_text(payload, encoding="utf-8")
        Path(outputs["REQUEST_FILE"]).write_text(json.dumps({"payload_file": outputs["POC_FILE"], "depth": depth}, indent=2), encoding="utf-8")
    elif "group" in summary or finding.attack_surface == "proto-input":
        depth = 60 if finding.tier in {"S", "A"} else 30
        proto = build_group_proto_payload(depth)
        Path(outputs["PROTO_FILE"]).write_text(proto, encoding="utf-8")
        Path(outputs["POC_FILE"]).write_text(proto, encoding="utf-8")
    elif finding.attack_surface == "archive-output":
        proto = 'syntax = "proto2";\npackage attacker;\noption java_package = "..\\\\pwn";\nmessage ZipSlip { optional string value = 1; }\n'
        Path(outputs["PROTO_FILE"]).write_text(proto, encoding="utf-8")
        Path(outputs["POC_FILE"]).write_text(proto, encoding="utf-8")
    else:
        Path(outputs["POC_FILE"]).write_text("AUTO-GENERATED INPUT FOR %s\n" % finding.finding_id, encoding="utf-8")
        Path(outputs["REQUEST_FILE"]).write_text(json.dumps({"finding_id": finding.finding_id, "title": finding.title}, indent=2), encoding="utf-8")
    return outputs


def generated_input_paths(repro_assets: dict[str, str]) -> list[str]:
    """List only files synthesized by the harness, never target observations."""

    paths: list[str] = []
    for key in ("POC_FILE", "REQUEST_FILE", "PROTO_FILE"):
        value = repro_assets.get(key, "")
        if value and Path(value).is_file() and value not in paths:
            paths.append(value)
    return paths


def build_nested_text_payload(depth: int) -> str:
    payload: list[str] = []
    for index in range(depth):
        payload.append("node {")
        payload.append("value: %d" % index)
    payload.extend("}" for _ in range(depth))
    return "\n".join(payload) + "\n"


def build_group_proto_payload(depth: int) -> str:
    lines = ['syntax = "proto2";', 'message Root {']
    for index in range(depth):
        lines.append("  optional group G%d = %d {" % (index, index + 1))
    lines.extend("  }" for _ in range(depth))
    lines.append("}")
    return "\n".join(lines) + "\n"


def build_variables_block(repro_assets: dict[str, str]) -> str:
    ordered = ["POC_FILE", "REQUEST_FILE", "PROTO_FILE", "TARGET_URL", "HTTP_EXTRA_HEADERS", "HTTP_QUERY", "GRPC_TARGET", "GRPC_METADATA"]
    lines: list[str] = []
    for key in ordered:
        value = repro_assets.get(key, "")
        lines.append('%s = "%s"' % (key, value.replace('"', "'")))
    return "\n".join(lines) + "\n"


def render_boundary_block(finding: IntakeFinding) -> str:
    lines = [
        "[boundary]",
        "enabled = true",
        "max_variants = 3",
        "combine_depth = 1",
        "",
        "[[boundary.axes]]",
        'name = "env-mode"',
        'kind = "env-set"',
        'env_key = "HARNESS_VARIANT"',
        'values = ["baseline", "stress"]',
        'step_name = "Auto-discovered repo replay"',
        'description = "Lightweight variant axis for repo-wide replay attempts"',
    ]
    if finding.attack_surface in {"proto-input", "protobuf-text-format", "archive-output"}:
        lines.extend(
            [
                "",
                "[[boundary.axes]]",
                'name = "input-growth"',
                'kind = "file-append"',
                'target_file_variable = "POC_FILE"',
                'content = "A"',
                'counts = [32, 256]',
                'description = "Increase attacker-controlled input size to probe boundary behavior"',
            ]
        )
    return "\n".join(lines) + "\n"


def extract_keywords(finding: IntakeFinding) -> list[str]:
    tokens = re.findall(r"[A-Za-z_][A-Za-z0-9_:+.-]+", "%s %s %s" % (finding.title, finding.summary, finding.target_component))
    stop = {"the", "and", "can", "via", "from", "with", "into", "that", "this", "does", "not", "path", "claim", "input", "output", "uses", "allow", "allows", "reach"}
    ordered: list[str] = []
    for token in tokens:
        lowered = token.lower()
        if len(lowered) < 4 or lowered in stop:
            continue
        if lowered not in ordered:
            ordered.append(lowered)
    return ordered[:8]


def rank_repo_paths(root: Path, keywords: list[str]) -> list[str]:
    scored: list[tuple[int, str]] = []
    for path in iter_repo_files(root):
        rel = str(path.relative_to(root))
        lowered = rel.lower()
        keyword_score = 0
        for keyword in keywords:
            if keyword in lowered:
                keyword_score += 4
        if keyword_score == 0:
            continue
        score = keyword_score
        if "test" in lowered or "tests/" in lowered or "_test." in lowered:
            score += 3
        if lowered.endswith((".py", ".go", ".java", ".kt", ".proto", ".cc", ".cpp")):
            score += 1
        if score > 0:
            scored.append((score, rel))
    scored.sort(key=lambda item: (-item[0], item[1]))
    return [path for _, path in scored[:20]]


def iter_repo_files(root: Path):
    """Yield source-tree files while pruning generated output and dependency trees."""

    for current, dirs, files in os.walk(root, followlinks=False):
        dirs[:] = sorted(
            name
            for name in dirs
            if name not in IGNORED_REPO_DIRS and not name.endswith(".egg-info")
        )
        current_path = Path(current)
        for name in sorted(files):
            if name.endswith((".pyc", ".pyo")):
                continue
            yield current_path / name


def detect_operational_failures(steps: list[StepResult]) -> list[str]:
    """Return infrastructure failures that cannot support a security verdict."""

    failures: list[str] = []
    for step in steps:
        if step.exit_code in {126, 127}:
            failures.append(f"{step.name}: command could not be executed (exit {step.exit_code})")
        text = "\n".join([step.stdout, step.stderr])
        for pattern, description in OPERATIONAL_FAILURE_PATTERNS:
            if pattern.search(text):
                failures.append(f"{step.name}: {description}")
    return dedupe(failures)


def operational_failure_impact(failures: list[str]) -> ImpactAssessment:
    return ImpactAssessment(
        verdict="operational-failure",
        confidence="high",
        priority="P3",
        exploitability_review_needed=False,
        availability_risk="unknown",
        integrity_risk="unknown",
        confidentiality_risk="unknown",
        reasoning=["The execution environment failed before the reported behavior could be evaluated."],
        boundaries=["No vulnerability boundary was assessed."],
        next_actions=["Resolve the operational failure and rerun the unchanged base case.", *failures],
    )


def assess_claim(
    claim: str,
    category: str,
    impact_verdict: str,
    corruption_class: str,
    runtime_observations: list[RuntimeObservation],
    steps: list[StepResult],
    operational_failures: list[str] | None = None,
) -> dict[str, object]:
    operational_failures = operational_failures or []
    observed_chunks = [step.stdout + "\n" + step.stderr for step in steps]
    observed_chunks.extend(obs.summary for obs in runtime_observations)
    text = "\n".join(observed_chunks).lower()
    verdict = "inconclusive"
    reasoning: list[str] = []
    evidence_sources = observed_evidence_sources(steps, runtime_observations)
    if operational_failures:
        verdict = "operational-failure"
        reasoning.append("The base command did not run successfully, so no semantic claim assessment was made.")
    elif category in {"stack-overflow", "unbounded-recursion"}:
        if STACK_RUNTIME_RE.search(text) or "stack" in corruption_class:
            verdict = "substantiated"
            reasoning.append("Observed recursion or stack-related evidence aligned with the reported failure mode.")
        elif impact_verdict == "reproduced":
            verdict = "partially-substantiated"
            reasoning.append("The path reproduced, but the observed signal did not cleanly prove stack exhaustion.")
        else:
            verdict = "not-substantiated"
            reasoning.append("No stack-related runtime evidence was observed.")
    elif category == "archive-path-traversal":
        if TRAVERSAL_ENTRY_RE.search(text):
            verdict = "partially-substantiated" if impact_verdict != "reproduced" else "substantiated"
            reasoning.append("A traversal-style path was present in target runtime output.")
        else:
            verdict = "inconclusive"
            reasoning.append("Target runtime output did not contain a traversal-style archive entry path.")
    elif category == "null-dereference":
        if impact_verdict == "reproduced" and (
            "null dereference" in text or "segmentation fault" in text or "sigsegv" in corruption_class
        ):
            verdict = "substantiated"
            reasoning.append("A null dereference or equivalent fatal signal was observed.")
        elif impact_verdict == "reproduced":
            verdict = "partially-substantiated"
            reasoning.append("Execution failed, but the available signal does not prove a null dereference specifically.")
        else:
            verdict = "not-substantiated"
            reasoning.append("No null-dereference evidence was observed.")
    else:
        if impact_verdict == "reproduced":
            verdict = "partially-substantiated"
            reasoning.append("The reported path reproduced, but the exact claim wording needs manual confirmation.")
        else:
            verdict = "inconclusive"
            reasoning.append("The auto-generated replay did not produce enough signal to confirm or reject the claim.")
    return {
        "verdict": verdict,
        "claim": claim,
        "observed_corruption_class": corruption_class,
        "operational_failures": operational_failures,
        "observed_evidence_sources": evidence_sources,
        "reasoning": reasoning,
    }


def observed_evidence_sources(
    steps: list[StepResult],
    runtime_observations: list[RuntimeObservation],
) -> list[str]:
    sources: list[str] = []
    for step in steps:
        if step.stdout.strip():
            sources.append(f"step:{step.name}:stdout")
        if step.stderr.strip():
            sources.append(f"step:{step.name}:stderr")
    for observation in runtime_observations:
        sources.append(f"runtime:{observation.kind}:{observation.source}")
    return dedupe(sources)


def write_claim_assessment(output_dir: Path, claim_assessment: dict[str, object]) -> None:
    (output_dir / "claim_assessment.json").write_text(json.dumps(claim_assessment, indent=2), encoding="utf-8")
    lines = [
        "# Claim Assessment",
        "",
        "- Verdict: `%s`" % claim_assessment["verdict"],
        "- Observed corruption class: `%s`" % claim_assessment["observed_corruption_class"],
        "- Claim: %s" % claim_assessment["claim"],
    ]
    for item in claim_assessment["reasoning"]:
        lines.append("- Reasoning: %s" % item)
    for item in claim_assessment.get("operational_failures", []):
        lines.append("- Operational failure: %s" % item)
    for item in claim_assessment.get("observed_evidence_sources", []):
        lines.append("- Evidence source: `%s`" % item)
    (output_dir / "claim_assessment.md").write_text("\n".join(lines) + "\n", encoding="utf-8")


def append_claim_assessment_to_reports(output_dir: Path, claim_assessment: dict[str, object]) -> None:
    technical = output_dir / "analysis.md"
    executive = output_dir / "executive_summary.md"
    appendix = "\n## Claim Assessment\n- Verdict: `%s`\n- Observed corruption class: `%s`\n" % (
        claim_assessment["verdict"],
        claim_assessment["observed_corruption_class"],
    )
    for item in claim_assessment["reasoning"]:
        appendix += "- Reasoning: %s\n" % item
    for item in claim_assessment.get("operational_failures", []):
        appendix += "- Operational failure: %s\n" % item
    technical.write_text(technical.read_text(encoding="utf-8") + appendix, encoding="utf-8")
    executive.write_text(executive.read_text(encoding="utf-8") + "\n## Claim Assessment\n- `%s`\n" % claim_assessment["verdict"], encoding="utf-8")


def repo_profile_to_dict(profile: RepoProfile) -> dict[str, object]:
    return {
        "root": str(profile.root),
        "languages": profile.languages,
        "build_systems": profile.build_systems,
        "openapi_specs": profile.openapi_specs,
        "proto_files": profile.proto_files,
        "likely_test_command": profile.likely_test_command,
        "command_confidence": profile.command_confidence,
        "notes": profile.notes,
    }


def dedupe(items: list[str]) -> list[str]:
    seen: set[str] = set()
    ordered: list[str] = []
    for item in items:
        if item and item not in seen:
            seen.add(item)
            ordered.append(item)
    return ordered


def shell_quote(value: str) -> str:
    return "'" + value.replace("'", "'\"'\"'") + "'"
