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
from security_qa_harness.oss_workflow import triage_ranked_report_against_repo


ROOT = Path(__file__).resolve().parents[1]


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
        self.assertFalse(payload["execution_requested"])
        self.assertEqual(payload["selected_findings"][0]["run_status"], "not-executed")
        self.assertEqual(payload["executions"][0]["status"], "not-executed")


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
