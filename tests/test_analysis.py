from __future__ import annotations

import unittest

from security_qa_harness.analyzer import analyze, extract_signals
from security_qa_harness.memory_lens import build_memory_lens
from security_qa_harness.models import ReportMetadata, StepResult


def report(**overrides) -> ReportMetadata:
    values = {
        "report_id": "demo-001",
        "title": "Synthetic parser crash",
        "reporter": "researcher@example.invalid",
        "category": "memory-corruption",
        "claim": "Malformed input crashes a parser",
        "attack_surface": "file-parser",
        "exposure": "local",
        "privileges_required": "none",
        "repeatability": "high",
    }
    values.update(overrides)
    return ReportMetadata(**values)


def step(stdout: str = "", stderr: str = "", exit_code: int = 1, expected: bool = True) -> StepResult:
    return StepResult(
        name="replay",
        objective="exercise the synthetic parser",
        tags=["test"],
        command="synthetic-command",
        cwd="/tmp",
        exit_code=exit_code,
        expected=expected,
        duration_seconds=0.01,
        stdout=stdout,
        stderr=stderr,
        collected_artifacts=[],
    )


class CrashSignalTests(unittest.TestCase):
    def test_extracts_asan_access_region_and_adjacency(self) -> None:
        text = """
==1==ERROR: AddressSanitizer: heap-buffer-overflow on address 0xdeadbeef
WRITE of size 4 at 0xdeadbeef
#0 0x414141 in parse
0xdeadbeef is located 8 bytes to the right of 32-byte region in heap
"""
        signals = extract_signals(text)
        self.assertEqual(len(signals), 1)
        self.assertEqual(signals[0].kind, "heap-buffer-overflow")
        self.assertEqual(signals[0].access_type, "WRITE")
        self.assertEqual(signals[0].memory_region, "heap")
        self.assertEqual(signals[0].adjacency, "right-of-object")

    def test_extracts_ubsan(self) -> None:
        signals = extract_signals("runtime error: signed integer overflow")
        self.assertEqual(signals[0].kind, "ubsan")
        self.assertIn("signed integer overflow", signals[0].summary)

    def test_extracts_unclassified_sigsegv(self) -> None:
        signals = extract_signals("Segmentation fault while parsing")
        self.assertEqual([signal.kind for signal in signals], ["sigsegv"])

    def test_asan_prevents_duplicate_sigsegv_signal(self) -> None:
        text = "ERROR: AddressSanitizer: use-after-free on address 0xfacefeed\nSIGSEGV"
        signals = extract_signals(text)
        self.assertEqual([signal.kind for signal in signals], ["use-after-free"])


class ImpactTests(unittest.TestCase):
    def test_no_steps_is_insufficient_data(self) -> None:
        _, _, impact = analyze(report(), [])
        self.assertEqual(impact.verdict, "insufficient-data")
        self.assertEqual(impact.priority, "P3")

    def test_memory_corruption_is_reproduced_but_not_exploitation(self) -> None:
        output = """
ERROR: AddressSanitizer: stack-buffer-overflow on address 0xabad1dea
WRITE of size 8 at 0xabad1dea
0xabad1dea is located 16 bytes to the left of stack variable frame
"""
        _, lens, impact = analyze(report(exposure="unauthenticated-remote"), [step(stdout=output)])
        self.assertEqual(impact.verdict, "reproduced")
        self.assertEqual(impact.priority, "P1")
        self.assertTrue(lens.exploitability_review_needed)
        self.assertTrue(any("does not attempt exploitation" in item for item in impact.boundaries))

    def test_unexpected_exit_without_signal_is_partial(self) -> None:
        _, _, impact = analyze(report(), [step(stderr="tool failed", exit_code=2, expected=False)])
        self.assertEqual(impact.verdict, "partial-reproduction")
        self.assertEqual(impact.confidence, "high")

    def test_memory_lens_keeps_missing_control_data_as_unknown(self) -> None:
        signal = extract_signals(
            "ERROR: AddressSanitizer: heap-buffer-overflow on address 0xdeadbeef\nREAD of size 1"
        )
        lens = build_memory_lens(signal)
        self.assertNotEqual(lens.control_data_proximity, "confirmed")


if __name__ == "__main__":
    unittest.main()
