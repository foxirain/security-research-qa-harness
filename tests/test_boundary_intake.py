from __future__ import annotations

from pathlib import Path
from tempfile import TemporaryDirectory
import unittest

from security_qa_harness.adapters import resolve_adapter
from security_qa_harness.boundary import build_variants
from security_qa_harness.config import load_case
from security_qa_harness.diffing import diff_variant_against_base
from security_qa_harness.intake import build_selected_findings, parse_findings
from security_qa_harness.models import RuntimeObservation, StepResult
from security_qa_harness.oss_workflow import (
    assess_claim,
    detect_operational_failures,
    discover_repo,
    infer_test_command,
    rank_repo_paths,
)


ROOT = Path(__file__).resolve().parents[1]


def result(name: str, stdout: str, artifact: str = "") -> StepResult:
    return StepResult(
        name=name,
        objective="test",
        tags=[],
        command="demo",
        cwd="/tmp",
        exit_code=0,
        expected=True,
        duration_seconds=0.01,
        stdout=stdout,
        stderr="",
        collected_artifacts=[artifact] if artifact else [],
    )


class BoundaryTests(unittest.TestCase):
    def test_builds_atomic_variants_with_budget(self) -> None:
        raw = load_case(ROOT / "examples" / "report-case.toml")
        case = resolve_adapter(raw.adapter).plan(raw)
        with TemporaryDirectory() as tmp:
            variants = build_variants(case, case.boundary, Path(tmp))
        self.assertEqual(len(variants), 4)
        self.assertEqual(len({variant.name for variant in variants}), 4)
        self.assertTrue(any("PARSER_MODE" in variant.step_env_overrides.get(case.steps[0].name, {}) for variant in variants))

    def test_diff_detects_output_and_runtime_change(self) -> None:
        diff = diff_variant_against_base(
            [result("replay", "base")],
            [],
            [result("replay", "changed")],
            [RuntimeObservation("python-traceback", "stderr", "trace observed")],
        )
        self.assertEqual(diff.changed_step_outputs, ["replay"])
        self.assertEqual(len(diff.added_runtime_observations), 1)

    def test_diff_reports_no_material_change(self) -> None:
        base = [result("replay", "same")]
        diff = diff_variant_against_base(base, [], base, [])
        self.assertIn("No material", diff.summary[0])


class IntakeTests(unittest.TestCase):
    def test_parses_all_ranked_sections(self) -> None:
        findings = parse_findings((ROOT / "examples" / "ranked-report.md").read_text(encoding="utf-8"))
        self.assertEqual(len(findings), 7)
        self.assertEqual({finding.tier for finding in findings}, {"S", "A", "B", "C", "D"})

    def test_selection_prioritizes_s_then_a(self) -> None:
        findings = parse_findings((ROOT / "examples" / "ranked-report.md").read_text(encoding="utf-8"))
        selected = build_selected_findings(findings, ("S", "A", "B"), 3)
        self.assertEqual([finding.tier for finding in selected], ["S", "A", "A"])

    def test_discovers_python_repository(self) -> None:
        with TemporaryDirectory() as tmp:
            root = Path(tmp)
            (root / "pyproject.toml").write_text("[project]\nname='demo'\nversion='0'\n", encoding="utf-8")
            profile = discover_repo(root)
        self.assertIn("python", profile.languages)
        self.assertEqual(profile.likely_test_command, "python3 -m pytest -q .")

    def test_infer_command_has_no_unsupported_fallback(self) -> None:
        command, confidence = infer_test_command(ROOT, [], [])
        self.assertEqual(command, "")
        self.assertEqual(confidence, "none")

    def test_repository_ranking_ignores_generated_and_dependency_trees(self) -> None:
        with TemporaryDirectory() as tmp:
            root = Path(tmp)
            (root / "src").mkdir()
            (root / "src" / "archive_parser.py").write_text("pass\n", encoding="utf-8")
            for directory in ["runs", "oss-runs", "build", "node_modules", ".venv", "package.egg-info"]:
                path = root / directory
                path.mkdir()
                (path / "archive_parser_test.py").write_text("pass\n", encoding="utf-8")
            ranked = rank_repo_paths(root, ["archive", "parser"])
        self.assertEqual(ranked, ["src/archive_parser.py"])

    def test_repository_ranking_does_not_return_unrelated_source_files(self) -> None:
        with TemporaryDirectory() as tmp:
            root = Path(tmp)
            (root / "tests").mkdir()
            (root / "tests" / "test_unrelated.py").write_text("pass\n", encoding="utf-8")
            ranked = rank_repo_paths(root, ["archive", "traversal"])
        self.assertEqual(ranked, [])


class ClaimAssessmentTests(unittest.TestCase):
    def test_claim_text_cannot_substantiate_itself(self) -> None:
        assessment = assess_claim(
            "Generated zip contains an archive traversal entry such as ../../etc/passwd",
            "archive-path-traversal",
            "not-reproduced",
            "none-observed",
            [],
            [result("pytest", "")],
        )
        self.assertEqual(assessment["verdict"], "inconclusive")

    def test_observed_traversal_entry_is_partial_evidence(self) -> None:
        assessment = assess_claim(
            "Archive output may contain unsafe paths",
            "archive-path-traversal",
            "not-reproduced",
            "none-observed",
            [],
            [result("archive-list", "entry=../../etc/passwd")],
        )
        self.assertEqual(assessment["verdict"], "partially-substantiated")
        self.assertEqual(assessment["observed_evidence_sources"], ["step:archive-list:stdout"])

    def test_missing_test_runner_is_an_operational_failure(self) -> None:
        failed = StepResult(
            name="pytest",
            objective="test",
            tags=[],
            command="python3 -m pytest",
            cwd="/tmp",
            exit_code=1,
            expected=False,
            duration_seconds=0.01,
            stdout="",
            stderr="/usr/bin/python3: No module named pytest\n",
            collected_artifacts=[],
        )
        failures = detect_operational_failures([failed])
        assessment = assess_claim(
            "Archive traversal",
            "archive-path-traversal",
            "not-reproduced",
            "none-observed",
            [],
            [failed],
            failures,
        )
        self.assertEqual(failures, ["pytest: required test runner is unavailable"])
        self.assertEqual(assessment["verdict"], "operational-failure")

    def test_passing_test_name_is_not_stack_runtime_evidence(self) -> None:
        assessment = assess_claim(
            "Nested input exhausts the stack",
            "stack-overflow",
            "not-reproduced",
            "none-observed",
            [],
            [result("pytest", "test_stack_overflow PASSED")],
        )
        self.assertEqual(assessment["verdict"], "not-substantiated")


if __name__ == "__main__":
    unittest.main()
