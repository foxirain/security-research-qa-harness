from __future__ import annotations

from contextlib import redirect_stderr, redirect_stdout
from io import StringIO
import json
from pathlib import Path
from tempfile import TemporaryDirectory
import unittest

from security_qa_harness.cli import main
from security_qa_harness.executor import run_steps
from security_qa_harness.models import (
    AdapterConfig,
    AnalysisResult,
    ArtifactDiff,
    AuthenticationConfig,
    BoundaryExplorationSummary,
    ExecutiveSummary,
    ExecutionStep,
    ImpactAssessment,
    MemoryRiskLens,
    ReplayConfig,
    ReportMetadata,
)
from security_qa_harness.oss_workflow import execute_generated_case, triage_ranked_report_against_repo


ROOT = Path(__file__).resolve().parents[1]


def write_missing_command_case(path: Path) -> None:
    path.write_text(
        """[report]
id = "missing-command"
title = "Missing command"
reporter = "test"
category = "archive-path-traversal"
claim = "Archive traversal"
attack_surface = "archive-output"

[target]
name = "fixture"
root = "."
adapter = "generic"

[adapter]
kind = "generic"

[boundary]
enabled = true
max_variants = 1

[[boundary.axes]]
name = "mode"
kind = "env-set"
env_key = "MODE"
values = ["changed"]

[[steps]]
name = "missing tool"
command = "security-qa-command-that-does-not-exist"
cwd = "."
expected_exit_codes = [0]
""",
        encoding="utf-8",
    )


class CliSafetyTests(unittest.TestCase):
    def test_validate_does_not_require_execution_acknowledgement(self) -> None:
        output = StringIO()
        with redirect_stdout(output):
            status = main(["validate", str(ROOT / "examples" / "report-case.toml")])
        self.assertEqual(status, 0)
        self.assertIn("is valid", output.getvalue())

    def test_run_fails_closed_without_acknowledgement(self) -> None:
        with redirect_stderr(StringIO()):
            with self.assertRaises(SystemExit) as raised:
                main(["run", str(ROOT / "examples" / "report-case.toml")])
        self.assertEqual(raised.exception.code, 2)

    def test_synthetic_run_writes_reports_after_acknowledgement(self) -> None:
        with TemporaryDirectory() as tmp, redirect_stdout(StringIO()):
            status = main(
                [
                    "run",
                    str(ROOT / "examples" / "report-case.toml"),
                    "--output-root",
                    tmp,
                    "--acknowledge-execution-risk",
                ]
            )
            run_dirs = list(Path(tmp).iterdir())
            self.assertEqual(status, 0)
            self.assertEqual(len(run_dirs), 1)
            self.assertTrue((run_dirs[0] / "analysis.json").exists())
            self.assertTrue((run_dirs[0] / "executive_summary.md").exists())

    def test_executor_redacts_command_and_text_logs(self) -> None:
        with TemporaryDirectory() as tmp:
            step = ExecutionStep(
                name="redaction",
                command="python3 -c \"print('lab-secret')\"",
                cwd=Path(tmp),
                expected_exit_codes=[0],
            )
            results = run_steps([step], Path(tmp) / "out", ["lab-secret"])
            stdout = (Path(tmp) / "out" / "01-redaction" / "stdout.txt").read_text(encoding="utf-8")
        self.assertNotIn("lab-secret", results[0].command)
        self.assertEqual(stdout.strip(), "[REDACTED]")

    def test_oss_triage_is_draft_only_by_default(self) -> None:
        with TemporaryDirectory() as tmp:
            temp = Path(tmp)
            repo = temp / "repo"
            repo.mkdir()
            (repo / "pyproject.toml").write_text("[project]\nname='fixture'\nversion='0'\n", encoding="utf-8")
            report = temp / "report.md"
            report.write_text("# Review\n\n## S Tier\n\n- Synthetic parser crash: controlled test claim.\n", encoding="utf-8")
            output = triage_ranked_report_against_repo(report, repo, temp / "out", top_n=1)
            payload = json.loads((output / "triage_summary.json").read_text(encoding="utf-8"))
            draft = Path(payload["selected_findings"][0]["draft"]).read_text(encoding="utf-8")
        self.assertFalse(payload["execution_requested"])
        self.assertEqual(payload["selected_findings"][0]["run_status"], "not-executed")
        self.assertEqual(payload["executions"][0]["status"], "not-executed")
        self.assertEqual(
            payload["selected_findings"][0]["generated_input_provenance"],
            "harness-generated-input-not-observed-evidence",
        )
        self.assertIn("expected_exit_codes = [0]", draft)
        self.assertIn("collect_paths = []", draft)

    def test_oss_triage_cli_returns_nonzero_for_operational_failure(self) -> None:
        with TemporaryDirectory() as tmp, redirect_stdout(StringIO()):
            temp = Path(tmp)
            repo = temp / "repo"
            repo.mkdir()
            (repo / "pyproject.toml").write_text("[project]\nname='fixture'\nversion='0'\n", encoding="utf-8")
            report = temp / "report.md"
            report.write_text("# Review\n\n## S Tier\n\n- Synthetic parser crash: controlled test claim.\n", encoding="utf-8")
            status = main(
                [
                    "triage-oss",
                    str(report),
                    "--repo",
                    str(repo),
                    "--output-root",
                    str(temp / "out"),
                    "--top-n",
                    "1",
                    "--execute",
                ]
            )
            summary_path = next((temp / "out").glob("*/triage_summary.json"))
            payload = json.loads(summary_path.read_text(encoding="utf-8"))
        self.assertEqual(status, 3)
        self.assertEqual(payload["executions"][0]["status"], "operational-failure")

    def test_oss_triage_does_not_execute_an_empty_fallback_command(self) -> None:
        with TemporaryDirectory() as tmp, redirect_stdout(StringIO()):
            temp = Path(tmp)
            repo = temp / "repo"
            repo.mkdir()
            report = temp / "report.md"
            report.write_text("# Review\n\n## S Tier\n\n- Synthetic parser crash: controlled test claim.\n", encoding="utf-8")
            status = main(
                [
                    "triage-oss",
                    str(report),
                    "--repo",
                    str(repo),
                    "--output-root",
                    str(temp / "out"),
                    "--top-n",
                    "1",
                    "--execute",
                ]
            )
            summary_path = next((temp / "out").glob("*/triage_summary.json"))
            payload = json.loads(summary_path.read_text(encoding="utf-8"))
        self.assertEqual(status, 3)
        self.assertEqual(payload["executions"][0]["status"], "operational-failure")
        self.assertEqual(payload["executions"][0]["selected_command"], "")
        self.assertNotIn("result_dir", payload["executions"][0])

    def test_generated_case_reports_command_failure_without_running_variants(self) -> None:
        with TemporaryDirectory() as tmp:
            temp = Path(tmp)
            case = temp / "case.toml"
            write_missing_command_case(case)
            result = execute_generated_case(case, temp / "runs")
            output = Path(str(result["result_dir"]))
            assessment = json.loads((output / "claim_assessment.json").read_text(encoding="utf-8"))
            analysis = json.loads((output / "analysis.json").read_text(encoding="utf-8"))
            boundary_exists = (output / "boundary").exists()
        self.assertEqual(result["status"], "operational-failure")
        self.assertEqual(assessment["verdict"], "operational-failure")
        self.assertEqual(analysis["impact"]["verdict"], "operational-failure")
        self.assertFalse(boundary_exists)

    def test_standard_run_reports_command_failure_without_running_variants(self) -> None:
        with TemporaryDirectory() as tmp, redirect_stdout(StringIO()):
            temp = Path(tmp)
            case = temp / "case.toml"
            output_root = temp / "runs"
            write_missing_command_case(case)
            status = main(
                [
                    "run",
                    str(case),
                    "--output-root",
                    str(output_root),
                    "--acknowledge-execution-risk",
                ]
            )
            output = next(output_root.iterdir())
            analysis = json.loads((output / "analysis.json").read_text(encoding="utf-8"))
            boundary_exists = (output / "boundary").exists()
        self.assertEqual(status, 3)
        self.assertEqual(analysis["impact"]["verdict"], "operational-failure")
        self.assertFalse(boundary_exists)


class StructuredRedactionTests(unittest.TestCase):
    def test_analysis_json_shape_redacts_authentication(self) -> None:
        report = ReportMetadata("id", "title", "reporter", "category", "claim", "surface")
        auth = AuthenticationConfig(
            mode="bearer",
            bearer_token="token-value",
            cookie="cookie-value",
            headers={"X-Lab": "header-value"},
            login_command="login --secret value",
        )
        lens = MemoryRiskLens(False, "none-observed", "unknown", "unknown", "unknown", "none", [], [])
        impact = ImpactAssessment("not-reproduced", "low", "P3", False, "low", "low", "low", [], [], [])
        boundary = BoundaryExplorationSummary(False, 0, 0, None, [], [])
        executive = ExecutiveSummary("headline", [], [], [], [])
        result = AnalysisResult(
            report,
            auth,
            AdapterConfig(),
            ReplayConfig(),
            [],
            [],
            [],
            lens,
            impact,
            boundary,
            executive,
            Path("out"),
        )
        payload = result.to_dict()
        self.assertEqual(payload["auth"]["bearer_token"], "[REDACTED]")
        self.assertEqual(payload["auth"]["cookie"], "[REDACTED]")
        self.assertEqual(payload["auth"]["headers"]["X-Lab"], "[REDACTED]")
        self.assertEqual(payload["auth"]["login_command"], "[REDACTED]")


if __name__ == "__main__":
    unittest.main()
