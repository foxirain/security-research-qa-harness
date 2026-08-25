from __future__ import annotations

import argparse
from datetime import UTC, datetime
from pathlib import Path
import sys

from . import __version__
from .adapters import resolve_adapter
from .analyzer import analyze
from .boundary import explore_boundaries
from .collectors import collect_runtime_observations
from .config import load_case
from .executor import auth_redaction_values, prepare_steps, run_steps
from .intake import normalize_report
from .models import AnalysisResult, ExecutiveSummary
from .orchestration import managed_target
from .oss_workflow import triage_ranked_report_against_repo
from .reporting import write_outputs


def build_parser() -> argparse.ArgumentParser:
    parser = argparse.ArgumentParser(prog="security-qa-harness", description="Evidence-led security research QA harness")
    parser.add_argument("--version", action="version", version=f"%(prog)s {__version__}")
    subparsers = parser.add_subparsers(dest="command", required=True)

    run_parser = subparsers.add_parser("run", help="Execute a case definition")
    run_parser.add_argument("case_file", type=Path, help="Path to the TOML case definition")
    run_parser.add_argument("--output-root", type=Path, default=Path("runs"))
    run_parser.add_argument(
        "--acknowledge-execution-risk",
        action="store_true",
        help="Confirm that the case file and target are trusted enough to execute in an isolated lab",
    )

    validate_parser = subparsers.add_parser("validate", help="Validate a case definition")
    validate_parser.add_argument("case_file", type=Path)

    intake_parser = subparsers.add_parser("intake", help="Normalize a markdown report into prioritized draft cases")
    intake_parser.add_argument("report_file", type=Path, help="Path to the markdown report")
    intake_parser.add_argument("--output-root", type=Path, default=Path("intake-runs"))
    intake_parser.add_argument("--tiers", default="S,A,B", help="Comma-separated tiers to keep, default S,A,B")
    intake_parser.add_argument("--top-n", type=int, default=5, help="Maximum number of highest-priority findings to draft")

    oss_parser = subparsers.add_parser("triage-oss", help="Run ranked markdown intake and OSS repo auto-discovery in one command")
    oss_parser.add_argument("report_file", type=Path, help="Path to the ranked markdown report")
    oss_parser.add_argument("--repo", type=Path, required=True, help="Path to the OSS repository")
    oss_parser.add_argument("--output-root", type=Path, default=Path("oss-runs"))
    oss_parser.add_argument("--tiers", default="S,A,B", help="Comma-separated tiers to keep, default S,A,B")
    oss_parser.add_argument("--top-n", type=int, default=5, help="Maximum number of highest-priority findings to draft")
    oss_parser.add_argument(
        "--execute",
        action="store_true",
        help="Execute generated cases after drafting them; use only in a disposable isolated lab",
    )

    return parser


def main(argv: list[str] | None = None) -> int:
    parser = build_parser()
    args = parser.parse_args(argv)

    if args.command == "intake":
        tiers = tuple(item.strip().upper() for item in args.tiers.split(",") if item.strip())
        report_path = args.report_file.resolve()
        stem = report_path.stem.lower().replace(" ", "-")
        output_dir = args.output_root.resolve() / stem
        normalize_report(report_path, output_dir, tiers, args.top_n)
        print(f"Intake complete. Normalized findings written to {output_dir}.")
        return 0

    if args.command == "triage-oss":
        tiers = tuple(item.strip().upper() for item in args.tiers.split(",") if item.strip())
        output_dir = triage_ranked_report_against_repo(
            args.report_file,
            args.repo,
            args.output_root,
            tiers,
            args.top_n,
            execute=args.execute,
        )
        print(f"OSS triage complete. Results written to {output_dir}.")
        return 0

    raw_case = load_case(args.case_file.resolve())
    case = resolve_adapter(raw_case.adapter).plan(raw_case)
    if args.command == "validate":
        print(f"Case `{case.metadata.report_id}` is valid with adapter `{case.adapter.kind}`, replay mode `{case.replay.mode}`, and {len(case.steps)} step(s).")
        return 0

    if not args.acknowledge_execution_risk:
        parser.error(
            "run executes commands from the case file; pass --acknowledge-execution-risk only after reviewing the case and isolating the target"
        )

    timestamp = datetime.now(UTC).strftime("%Y%m%dT%H%M%SZ")
    output_dir = args.output_root.resolve() / f"{case.metadata.report_id}-{timestamp}"
    output_dir.mkdir(parents=True, exist_ok=True)

    with managed_target(case):
        steps = prepare_steps(case)
        results = run_steps(steps, output_dir, auth_redaction_values(case))
        crash_signals, memory_lens, impact = analyze(case.metadata, results)
        runtime_observations = collect_runtime_observations(case.adapter, results, case.target.root)
        boundary = explore_boundaries(case, output_dir, results, runtime_observations)
        executive = build_executive_summary(case, impact, memory_lens, runtime_observations, boundary)
        analysis = AnalysisResult(case.metadata, case.auth, case.adapter, case.replay, results, crash_signals, runtime_observations, memory_lens, impact, boundary, executive, output_dir)
        write_outputs(analysis)

    print(f"Run complete. Analysis written to {output_dir}.")
    return 0


def build_executive_summary(case, impact, memory_lens, runtime_observations, boundary) -> ExecutiveSummary:
    top_variant = next((item for item in boundary.variants if item.name == boundary.highest_risk_variant), None)
    highest_boundary = top_variant.memory_lens.corruption_class if top_variant else memory_lens.corruption_class
    review_status = "required" if impact.exploitability_review_needed or top_variant else "not yet justified by current evidence"
    headline = (
        f"Report `{case.metadata.report_id}` is `{impact.verdict}` with priority `{impact.priority}`. "
        f"The highest confirmed tested boundary is `{highest_boundary}` and manual exploitability review is `{review_status}`."
    )
    confirmed = [
        f"Runtime evidence confirms `{impact.verdict}` for the reported path.",
        f"Confirmed risks: availability `{impact.availability_risk}`, integrity `{impact.integrity_risk}`, confidentiality `{impact.confidentiality_risk}`.",
        f"Base memory context indicates `{memory_lens.likely_impacted_asset}` with `{memory_lens.control_data_proximity}`.",
    ]
    if runtime_observations:
        confirmed.append("Additional runtime evidence collected: " + ", ".join(obs.kind for obs in runtime_observations[:3]) + ".")
    if case.auth.mode != "none":
        confirmed.append(f"Replay included authentication mode `{case.auth.mode}`.")
    if case.replay.mode != "none":
        confirmed.append(f"Replay command generation was driven by declarative `{case.replay.mode}` configuration.")
    if top_variant:
        confirmed.append(f"Boundary exploration elevated the highest tested boundary to `{top_variant.memory_lens.corruption_class}` via variant `{top_variant.name}`.")
        if top_variant.artifact_diff.summary:
            confirmed.append("That variant also changed observable artifacts: " + top_variant.artifact_diff.summary[0])

    unproven = [
        "No remote code execution or weaponized exploit chain was demonstrated by this harness.",
        "Potential control-data adjacency is treated as an analyst cue, not proof of exploitability.",
    ]
    immediate = list(impact.next_actions[:3])
    if top_variant:
        immediate.append(f"Review the artifacts from variant `{top_variant.name}` before final severity sign-off.")
    if case.adapter.healthcheck:
        immediate.append(f"Keep the service healthcheck `{case.adapter.healthcheck}` wired into future replay runs.")
    if case.auth.login_command:
        immediate.append("Preserve the login or session establishment command with the case so auth-sensitive replay remains reproducible.")
    immediate.append("Use the technical report for engineering remediation and the executive report for leadership communication.")
    business = [
        f"Attack surface is `{case.metadata.attack_surface}` with exposure `{case.metadata.exposure}`.",
        f"Product type is `{case.adapter.product_type}` on language `{case.adapter.language}` and framework `{case.adapter.framework}`.",
        f"Authentication mode is `{case.auth.mode}`.",
        f"Replay mode is `{case.replay.mode}`.",
        "Severity should be communicated from confirmed evidence, not the strongest reporter claim.",
    ]
    return ExecutiveSummary(headline, confirmed, unproven, immediate, business)


if __name__ == "__main__":
    raise SystemExit(main(sys.argv[1:]))
