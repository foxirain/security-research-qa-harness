from __future__ import annotations

import json

from .models import AnalysisResult


def write_outputs(result: AnalysisResult) -> None:
    result.output_dir.mkdir(parents=True, exist_ok=True)
    (result.output_dir / "analysis.json").write_text(json.dumps(result.to_dict(), indent=2), encoding="utf-8")
    (result.output_dir / "analysis.md").write_text(render_technical_markdown(result), encoding="utf-8")
    (result.output_dir / "executive_summary.md").write_text(render_executive_markdown(result), encoding="utf-8")


def render_technical_markdown(result: AnalysisResult) -> str:
    report = result.report
    impact = result.impact
    lens = result.memory_lens
    lines = [
        "# %s" % report.title,
        "",
        "## Intake",
        "- Report ID: `%s`" % report.report_id,
        "- Reporter: `%s`" % report.reporter,
        "- Category: `%s`" % report.category,
        "- Attack surface: `%s`" % report.attack_surface,
        "- Exposure: `%s`" % report.exposure,
        "- Privileges required: `%s`" % report.privileges_required,
        "- User interaction: `%s`" % report.user_interaction,
        "- Input origin: `%s`" % report.input_origin,
        "- Repeatability: `%s`" % report.repeatability,
        "- Claimed issue: %s" % report.claim,
        "- Target adapter: `%s`" % result.adapter.product_type,
        "- Language profile: `%s`" % result.adapter.language,
        "- Framework: `%s`" % result.adapter.framework,
        "- Sanitizer profile: `%s`" % result.adapter.sanitizer_profile,
        "- Authentication mode: `%s`" % result.auth.mode,
        "- Replay mode: `%s`" % result.replay.mode,
    ]
    if result.replay.mode == "openapi":
        lines.append("- Replay path: `%s %s`" % (result.replay.openapi.method, result.replay.openapi.path))
        if result.replay.openapi.spec:
            lines.append("- OpenAPI spec hint: `%s`" % result.replay.openapi.spec)
    if result.replay.mode == "grpc":
        lines.append("- gRPC method: `%s/%s`" % (result.replay.grpc.service, result.replay.grpc.method))
        lines.append("- gRPC reflection: `%s`" % result.replay.grpc.use_reflection)
    if result.adapter.ports:
        lines.append("- Declared ports: %s" % ", ".join(str(port) for port in result.adapter.ports))
    if result.adapter.healthcheck:
        lines.append("- Healthcheck: `%s`" % result.adapter.healthcheck)
    if result.auth.notes:
        lines.append("- Auth notes: %s" % "; ".join(result.auth.notes))
    if report.notes:
        lines.append("- Notes: %s" % report.notes)
    if result.adapter.notes:
        lines.append("- Adapter notes: %s" % "; ".join(result.adapter.notes))

    lines.extend([
        "",
        "## Triage Verdict",
        "- Verdict: `%s`" % impact.verdict,
        "- Confidence: `%s`" % impact.confidence,
        "- Priority: `%s`" % impact.priority,
        "- Manual exploitability review needed: `%s`" % impact.exploitability_review_needed,
        "- Availability risk: `%s`" % impact.availability_risk,
        "- Integrity risk: `%s`" % impact.integrity_risk,
        "- Confidentiality risk: `%s`" % impact.confidentiality_risk,
        "",
        "## Evidence",
    ])

    for step in result.steps:
        lines.extend([
            "### %s" % step.name,
            "- Objective: %s" % (step.objective or "not specified"),
            "- Tags: %s" % (", ".join(step.tags) if step.tags else "none"),
            "- Command: `%s`" % step.command,
            "- Working directory: `%s`" % step.cwd,
            "- Exit code: `%s`" % step.exit_code,
            "- Expected: `%s`" % step.expected,
            "- Duration: `%s` seconds" % step.duration_seconds,
        ])
        if step.collected_artifacts:
            lines.append("- Collected artifacts: " + ", ".join("`%s`" % item for item in step.collected_artifacts))
        lines.append("")

    lines.append("## Crash Signals")
    if result.crash_signals:
        for signal in result.crash_signals:
            lines.append("- `%s`: %s" % (signal.kind, signal.summary))
            if signal.memory_region:
                lines.append("- Memory region: `%s`" % signal.memory_region)
            if signal.access_type:
                lines.append("- Access type: `%s`" % signal.access_type)
            if signal.allocator_state:
                lines.append("- Allocator state: `%s`" % signal.allocator_state)
            if signal.adjacency:
                lines.append("- Adjacency: `%s`" % signal.adjacency)
            if signal.fault_address:
                lines.append("- Fault address: `%s`" % signal.fault_address)
            if signal.pc:
                lines.append("- Program counter: `%s`" % signal.pc)
            for frame in signal.stack_excerpt:
                lines.append("- Stack: `%s`" % frame)
    else:
        lines.append("- No crash signature recognized.")

    lines.extend(["", "## Runtime Observations"])
    if result.runtime_observations:
        for item in result.runtime_observations:
            line = "- `%s` from `%s`: %s" % (item.kind, item.source, item.summary)
            if item.path:
                line += " (`%s`)" % item.path
            lines.append(line)
    else:
        lines.append("- No language-specific runtime observations were collected.")

    lines.extend([
        "",
        "## Memory Risk Lens",
        "- Corruption class: `%s`" % lens.corruption_class,
        "- Allocator state: `%s`" % lens.allocator_state,
        "- Adjacency: `%s`" % lens.adjacency,
        "- Control-data proximity: `%s`" % lens.control_data_proximity,
        "- Likely impacted asset: `%s`" % lens.likely_impacted_asset,
    ])
    for item in lens.review_cues:
        lines.append("- Review cue: %s" % item)

    lines.extend(["", "## Boundary Exploration"])
    lines.append("- Enabled: `%s`" % result.boundary.enabled)
    lines.append("- Attempted variants: `%s`" % result.boundary.attempted_variants)
    lines.append("- Interesting variants: `%s`" % result.boundary.interesting_variants)
    lines.append("- Highest-risk variant: `%s`" % (result.boundary.highest_risk_variant or "none"))
    for finding in result.boundary.findings:
        lines.append("- %s" % finding)
    for variant in result.boundary.variants:
        lines.append("### Variant %s" % variant.name)
        lines.append("- Description: %s" % variant.description)
        lines.append("- Changes: %s" % (", ".join(variant.changes) if variant.changes else "none"))
        lines.append("- Verdict: `%s` / Priority: `%s`" % (variant.impact.verdict, variant.impact.priority))
        lines.append("- Memory lens: `%s` / `%s`" % (variant.memory_lens.corruption_class, variant.memory_lens.control_data_proximity))
        if variant.runtime_observations:
            lines.append("- Runtime observations: %s" % ", ".join(obs.kind for obs in variant.runtime_observations))
        if variant.artifact_diff.summary:
            lines.append("- Artifact diff summary: %s" % " | ".join(variant.artifact_diff.summary))
        if variant.artifact_diff.added_artifacts:
            lines.append("- Added artifacts: " + ", ".join("`%s`" % item for item in variant.artifact_diff.added_artifacts))
        if variant.artifact_diff.removed_artifacts:
            lines.append("- Missing base artifacts: " + ", ".join("`%s`" % item for item in variant.artifact_diff.removed_artifacts))
        if variant.artifact_diff.added_runtime_observations:
            lines.append("- New runtime evidence: %s" % ", ".join(variant.artifact_diff.added_runtime_observations))
        if variant.artifact_diff.changed_step_outputs:
            lines.append("- Changed step outputs: %s" % ", ".join(variant.artifact_diff.changed_step_outputs))

    lines.extend(["", "## Analyst Notes"])
    for item in impact.reasoning:
        lines.append("- %s" % item)
    lines.extend(["", "## Boundary"])
    for item in impact.boundaries:
        lines.append("- %s" % item)
    lines.extend(["", "## Next Actions"])
    for item in impact.next_actions:
        lines.append("- %s" % item)
    lines.extend([
        "",
        "## Safe Use Limits",
        "- This harness is for defensive validation and impact triage.",
        "- For memory corruption, it stops at crash classification, execution evidence, and review cues.",
        "- It does not automate payload crafting, exploitation, or post-compromise activity.",
    ])
    return "\n".join(lines) + "\n"


def render_executive_markdown(result: AnalysisResult) -> str:
    executive = result.executive
    lines = ["# Executive Summary: %s" % result.report.title, "", executive.headline, "", "## Confirmed Impact"]
    for item in executive.confirmed_impact:
        lines.append("- %s" % item)
    lines.extend(["", "## Unproven Claims"])
    for item in executive.unproven_claims:
        lines.append("- %s" % item)
    lines.extend(["", "## Immediate Actions"])
    for item in executive.immediate_actions:
        lines.append("- %s" % item)
    lines.extend(["", "## Business Context"])
    for item in executive.business_context:
        lines.append("- %s" % item)
    return "\n".join(lines) + "\n"
