from __future__ import annotations

from pathlib import Path
import unittest

from security_qa_harness.adapters import resolve_adapter
from security_qa_harness.config import load_case
from security_qa_harness.executor import auth_redaction_values, prepare_steps, redact_text
from security_qa_harness.models import GrpcReplay, OpenAPIReplay, ReplayConfig
from security_qa_harness.replay import generate_grpc_command, generate_openapi_command


ROOT = Path(__file__).resolve().parents[1]


class ConfigTests(unittest.TestCase):
    def test_loads_synthetic_case(self) -> None:
        case = load_case(ROOT / "examples" / "report-case.toml")
        self.assertEqual(case.metadata.report_id, "mail-20260409-001")
        self.assertEqual(case.target.root, ROOT)
        self.assertEqual(case.boundary.max_variants, 6)
        self.assertEqual(len(case.steps), 1)

    def test_adapter_adds_parser_defaults(self) -> None:
        raw = load_case(ROOT / "examples" / "report-case.toml")
        planned = resolve_adapter(raw.adapter).plan(raw)
        self.assertEqual(planned.adapter.product_type, "file-parser")
        self.assertIn("ASAN_OPTIONS", planned.steps[0].env)
        self.assertIn("input-driven", planned.steps[0].tags)

    def test_prepared_step_expands_variables(self) -> None:
        case = resolve_adapter(load_case(ROOT / "examples" / "report-case.toml").adapter).plan(
            load_case(ROOT / "examples" / "report-case.toml")
        )
        steps = prepare_steps(case)
        self.assertIn("fixtures/crash-input.txt", steps[0].command)
        self.assertTrue(steps[0].cwd.is_absolute())


class ReplayTests(unittest.TestCase):
    def test_openapi_command_quotes_body_and_url(self) -> None:
        replay = ReplayConfig(
            mode="openapi",
            openapi=OpenAPIReplay(
                path="/v1/items/{ITEM}",
                method="POST",
                body_variable="BODY",
                target_url_variable="URL",
            ),
        )
        command = generate_openapi_command(
            replay,
            {"URL": "http://127.0.0.1:8080", "BODY": "/tmp/body file.json", "ITEM": "demo"},
        )
        self.assertIn("curl -sS -X POST", command)
        self.assertIn("--data-binary @'/tmp/body file.json'", command)
        self.assertIn("http://127.0.0.1:8080/v1/items/demo", command)

    def test_openapi_requires_target_url(self) -> None:
        replay = ReplayConfig(mode="openapi", openapi=OpenAPIReplay(path="/", target_url_variable="URL"))
        with self.assertRaisesRegex(ValueError, "URL"):
            generate_openapi_command(replay, {})

    def test_grpc_command_preserves_method(self) -> None:
        replay = ReplayConfig(
            mode="grpc",
            grpc=GrpcReplay(target="127.0.0.1:50051", service="demo.Service", method="Parse"),
        )
        command = generate_grpc_command(replay, {})
        self.assertIn("127.0.0.1:50051", command)
        self.assertIn("demo.Service/Parse", command)

    def test_grpc_requires_service_and_method(self) -> None:
        replay = ReplayConfig(mode="grpc", grpc=GrpcReplay(target="localhost:50051", service="demo.Service"))
        with self.assertRaisesRegex(ValueError, "service and method"):
            generate_grpc_command(replay, {})


class RedactionTests(unittest.TestCase):
    def test_configured_auth_values_are_selected_for_redaction(self) -> None:
        case = load_case(ROOT / "examples" / "web-go-service.toml")
        values = auth_redaction_values(case)
        self.assertIn("REPLACE_ME", values)
        self.assertIn("research", values)

    def test_redaction_prefers_longer_values(self) -> None:
        text = redact_text("token-long token", ["token", "token-long"])
        self.assertEqual(text, "[REDACTED] [REDACTED]")


if __name__ == "__main__":
    unittest.main()
