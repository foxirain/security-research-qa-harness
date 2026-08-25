from __future__ import annotations

from hashlib import sha256
from pathlib import Path

from .collectors import read_text_safely
from .models import ArtifactDiff, RuntimeObservation, StepResult


def diff_variant_against_base(
    base_steps: list[StepResult],
    base_runtime_observations: list[RuntimeObservation],
    variant_steps: list[StepResult],
    variant_runtime_observations: list[RuntimeObservation],
) -> ArtifactDiff:
    base_artifacts = sorted(_artifacts(base_steps))
    variant_artifacts = sorted(_artifacts(variant_steps))
    base_runtime = sorted(_runtime_keys(base_runtime_observations))
    variant_runtime = sorted(_runtime_keys(variant_runtime_observations))

    added_artifacts = sorted(set(variant_artifacts) - set(base_artifacts))
    removed_artifacts = sorted(set(base_artifacts) - set(variant_artifacts))
    added_runtime = sorted(set(variant_runtime) - set(base_runtime))
    removed_runtime = sorted(set(base_runtime) - set(variant_runtime))
    changed_outputs = compare_step_outputs(base_steps, variant_steps)

    summary: list[str] = []
    if added_artifacts:
        summary.append("Added artifacts: " + ", ".join(added_artifacts[:4]))
    if removed_artifacts:
        summary.append("Missing base artifacts: " + ", ".join(removed_artifacts[:4]))
    if added_runtime:
        summary.append("New runtime evidence: " + ", ".join(added_runtime[:4]))
    if removed_runtime:
        summary.append("Runtime evidence no longer present: " + ", ".join(removed_runtime[:4]))
    if changed_outputs:
        summary.append("Step output changed for " + ", ".join(changed_outputs[:4]))
    if not summary:
        summary.append("No material artifact or runtime observation differences against the base replay.")

    return ArtifactDiff(
        added_artifacts=added_artifacts,
        removed_artifacts=removed_artifacts,
        added_runtime_observations=added_runtime,
        removed_runtime_observations=removed_runtime,
        changed_step_outputs=changed_outputs,
        summary=summary,
    )


def compare_step_outputs(base_steps: list[StepResult], variant_steps: list[StepResult]) -> list[str]:
    base_by_name = {step.name: step for step in base_steps}
    variant_names = {step.name for step in variant_steps}
    changed: list[str] = []
    for step in variant_steps:
        base = base_by_name.get(step.name)
        if base is None:
            changed.append("%s (new step)" % step.name)
            continue
        if _digest(base.stdout, base.stderr) != _digest(step.stdout, step.stderr) or base.exit_code != step.exit_code:
            changed.append(step.name)
    for step in base_steps:
        if step.name not in variant_names:
            changed.append("%s (missing in variant)" % step.name)
    return changed


def snapshot_artifacts(steps: list[StepResult]) -> dict[str, str]:
    return {path: _artifact_fingerprint(Path(path)) for path in sorted(_artifacts(steps))}


def _artifacts(steps: list[StepResult]) -> set[str]:
    paths: set[str] = set()
    for step in steps:
        paths.update(step.collected_artifacts)
    return paths


def _runtime_keys(items: list[RuntimeObservation]) -> set[str]:
    return {"%s:%s" % (item.kind, item.summary) for item in items}


def _artifact_fingerprint(path: Path) -> str:
    if not path.exists() or path.is_dir():
        return "missing"
    text = read_text_safely(path)
    if text:
        return sha256(text.encode("utf-8", errors="ignore")).hexdigest()
    return "size:%s" % path.stat().st_size


def _digest(stdout: str, stderr: str) -> str:
    return sha256((stdout + "\n---\n" + stderr).encode("utf-8", errors="ignore")).hexdigest()
