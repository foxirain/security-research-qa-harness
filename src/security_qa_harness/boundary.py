from __future__ import annotations

from itertools import combinations
from pathlib import Path

from .analyzer import analyze
from .collectors import collect_runtime_observations
from .diffing import diff_variant_against_base
from .executor import auth_redaction_values, prepare_steps, run_steps
from .models import BoundaryConfig, BoundaryExplorationSummary, BoundaryVariant, BoundaryVariantResult, CaseDefinition, RuntimeObservation, StepResult


MEMORY_SEVERITY = {
    "stack-buffer-overflow": 4,
    "use-after-free": 4,
    "double-free": 4,
    "heap-buffer-overflow": 3,
    "global-buffer-overflow": 2,
    "sigsegv": 1,
    "none-observed": 0,
}


def explore_boundaries(
    case: CaseDefinition,
    output_dir: Path,
    base_steps: list[StepResult],
    base_runtime_observations: list[RuntimeObservation],
) -> BoundaryExplorationSummary:
    config = case.boundary
    if not config.enabled or not config.axes:
        return BoundaryExplorationSummary(False, 0, 0, None, ["Boundary exploration is disabled for this case."], [])

    variants = build_variants(case, config, output_dir)
    results_out: list[BoundaryVariantResult] = []
    for variant in variants:
        variant_dir = output_dir / "boundary" / variant.name
        steps = prepare_steps(case, variant.variable_overrides, variant.step_env_overrides)
        step_results = run_steps(steps, variant_dir, auth_redaction_values(case))
        crash_signals, memory_lens, impact = analyze(case.metadata, step_results)
        runtime_observations = collect_runtime_observations(case.adapter, step_results, case.target.root)
        artifact_diff = diff_variant_against_base(base_steps, base_runtime_observations, step_results, runtime_observations)
        results_out.append(
            BoundaryVariantResult(
                name=variant.name,
                description=variant.description,
                changes=describe_changes(variant),
                impact=impact,
                memory_lens=memory_lens,
                crash_signals=crash_signals,
                runtime_observations=runtime_observations,
                artifact_diff=artifact_diff,
                steps=step_results,
                output_dir=variant_dir,
            )
        )

    interesting = [item for item in results_out if item.impact.verdict == "reproduced"]
    highest = max(results_out, key=variant_rank, default=None)
    findings = build_findings(results_out, highest.name if highest else None)
    return BoundaryExplorationSummary(True, len(results_out), len(interesting), highest.name if highest else None, findings, results_out)


def build_variants(case: CaseDefinition, config: BoundaryConfig, output_dir: Path) -> list[BoundaryVariant]:
    atomic: list[BoundaryVariant] = []
    for axis in config.axes:
        atomic.extend(axis_variants(case, axis, output_dir))
    variants = list(atomic)
    if config.combine_depth > 1:
        for left, right in combinations(atomic, 2):
            variants.append(
                BoundaryVariant(
                    name=f"{left.name}__{right.name}",
                    description=f"Combined exploration: {left.description}; {right.description}",
                    variable_overrides={**left.variable_overrides, **right.variable_overrides},
                    step_env_overrides=merge_step_env(left.step_env_overrides, right.step_env_overrides),
                )
            )
    return variants[: config.max_variants]


def axis_variants(case: CaseDefinition, axis, output_dir: Path) -> list[BoundaryVariant]:
    variants: list[BoundaryVariant] = []
    if axis.kind == "variable-set" and axis.variable:
        for value in axis.values:
            variants.append(BoundaryVariant(f"{axis.name}-{slug(value)}", axis.description or f"Set {axis.variable} to {value}", {axis.variable: value}))
    elif axis.kind == "string-length" and axis.variable:
        for size in axis.sizes:
            variants.append(BoundaryVariant(f"{axis.name}-{size}", axis.description or f"Set {axis.variable} length to {size}", {axis.variable: axis.character * size}))
    elif axis.kind == "env-set" and axis.env_key:
        step_name = axis.step_name or case.steps[0].name
        for value in axis.values:
            variants.append(BoundaryVariant(f"{axis.name}-{slug(value)}", axis.description or f"Set env {axis.env_key}={value}", step_env_overrides={step_name: {axis.env_key: value}}))
    elif axis.kind in {"file-append", "file-token-replace"} and axis.target_file_variable:
        source = resolve_case_path(case, case.variables[axis.target_file_variable])
        variants.extend(file_variants(axis, source, output_dir / "boundary-inputs", axis.target_file_variable))
    elif axis.kind == "http-method":
        for value in axis.values:
            variants.append(BoundaryVariant(f"{axis.name}-{slug(value)}", axis.description or f"Set HTTP method to {value}", {"HTTP_METHOD": value}))
    elif axis.kind == "http-header" and axis.header_name:
        for value in axis.values:
            variants.append(BoundaryVariant(f"{axis.name}-{slug(value)}", axis.description or f"Set HTTP header {axis.header_name}", {"HTTP_EXTRA_HEADERS": "-H '%s: %s'" % (axis.header_name, value)}))
    elif axis.kind == "query-param" and axis.query_name:
        for value in axis.values:
            variants.append(BoundaryVariant(f"{axis.name}-{slug(value)}", axis.description or f"Set query parameter {axis.query_name}", {"HTTP_QUERY": "?%s=%s" % (axis.query_name, value)}))
    elif axis.kind == "argv-append" and axis.variable:
        base = case.variables.get(axis.variable, "")
        for value in axis.values:
            joined = f"{base} {value}".strip()
            variants.append(BoundaryVariant(f"{axis.name}-{slug(value)}", axis.description or f"Append argv fragment {value}", {axis.variable: joined}))
    return variants


def file_variants(axis, source: Path, output_dir: Path, variable: str) -> list[BoundaryVariant]:
    output_dir.mkdir(parents=True, exist_ok=True)
    original = source.read_text(encoding="utf-8")
    variants: list[BoundaryVariant] = []
    if axis.kind == "file-append":
        for count in axis.counts:
            mutated = original + (axis.content * count)
            path = output_dir / f"{axis.name}-{count}{source.suffix}"
            path.write_text(mutated, encoding="utf-8")
            variants.append(BoundaryVariant(f"{axis.name}-{count}", axis.description or f"Append {count} unit(s) to {source.name}", {variable: str(path)}, staged_files={variable: str(path)}))
    elif axis.kind == "file-token-replace" and axis.token is not None:
        for value in axis.values:
            mutated = original.replace(axis.token, value)
            path = output_dir / f"{axis.name}-{slug(value)}{source.suffix}"
            path.write_text(mutated, encoding="utf-8")
            variants.append(BoundaryVariant(f"{axis.name}-{slug(value)}", axis.description or f"Replace token {axis.token} with {value}", {variable: str(path)}, staged_files={variable: str(path)}))
    return variants


def resolve_case_path(case: CaseDefinition, raw: str) -> Path:
    candidate = Path(raw)
    if candidate.is_absolute():
        return candidate.resolve()
    return (case.target.root / candidate).resolve()


def describe_changes(variant: BoundaryVariant) -> list[str]:
    changes: list[str] = []
    for key, value in variant.variable_overrides.items():
        changes.append(f"variable {key}={value}")
    for step_name, env in variant.step_env_overrides.items():
        for key, value in env.items():
            changes.append(f"step {step_name} env {key}={value}")
    return changes


def merge_step_env(left: dict[str, dict[str, str]], right: dict[str, dict[str, str]]) -> dict[str, dict[str, str]]:
    merged = {name: dict(values) for name, values in left.items()}
    for name, env in right.items():
        merged.setdefault(name, {}).update(env)
    return merged


def variant_rank(item: BoundaryVariantResult) -> tuple[int, int, int, int, int, int]:
    priority_weight = {"P1": 3, "P2": 2, "P3": 1}
    confidence_weight = {"high": 3, "medium": 2, "low": 1}
    verdict_weight = {"reproduced": 3, "partial-reproduction": 2, "not-reproduced": 1, "insufficient-data": 0}
    memory_weight = MEMORY_SEVERITY.get(item.memory_lens.corruption_class, 0)
    runtime_weight = len(item.runtime_observations)
    diff_weight = len(item.artifact_diff.added_runtime_observations) + len(item.artifact_diff.changed_step_outputs)
    return (priority_weight.get(item.impact.priority, 0), memory_weight, diff_weight, confidence_weight.get(item.impact.confidence, 0), verdict_weight.get(item.impact.verdict, 0), runtime_weight)


def build_findings(variants: list[BoundaryVariantResult], highest_name: str | None) -> list[str]:
    findings: list[str] = []
    for item in variants:
        if item.impact.verdict == "reproduced":
            statement = f"{item.name}: reproduced with priority {item.impact.priority} and memory class {item.memory_lens.corruption_class}."
            if item.runtime_observations:
                statement += f" Runtime observations: {len(item.runtime_observations)}."
            if item.artifact_diff.summary:
                statement += " " + item.artifact_diff.summary[0]
            if item.name == highest_name:
                statement += " This is the highest-risk tested boundary."
            findings.append(statement)
    if not findings:
        findings.append("No boundary variant exceeded the base reproduction evidence.")
    return findings


def slug(value: str) -> str:
    return "".join(ch.lower() if ch.isalnum() else "-" for ch in value).strip("-")[:40] or "value"
