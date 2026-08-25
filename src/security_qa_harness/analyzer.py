from __future__ import annotations

import re

from .memory_lens import build_memory_lens
from .models import CrashSignal, ImpactAssessment, MemoryRiskLens, ReportMetadata, StepResult


ASAN_RE = re.compile(
    r"ERROR: AddressSanitizer: (?P<kind>[\w-]+) on address (?P<addr>0x[0-9a-f]+)",
    re.IGNORECASE,
)
ACCESS_RE = re.compile(r"\b(READ|WRITE)\b of size", re.IGNORECASE)
PC_RE = re.compile(r"\b(?:pc|#0)\s+(?P<pc>0x[0-9a-f]+)\b", re.IGNORECASE)
REGION_RE = re.compile(r"\b(?P<region>stack|heap|global)\b", re.IGNORECASE)
SIGSEGV_RE = re.compile(r"\b(SIGSEGV|segmentation fault)\b", re.IGNORECASE)
UBSAN_RE = re.compile(r"runtime error: (?P<summary>.+)")
FREED_RE = re.compile(r"freed by thread|heap-use-after-free|double-free", re.IGNORECASE)
RIGHT_RE = re.compile(r"to the right of", re.IGNORECASE)
LEFT_RE = re.compile(r"to the left of", re.IGNORECASE)
INSIDE_RE = re.compile(r"inside of", re.IGNORECASE)

MEMORY_CRITICAL = {"heap-buffer-overflow", "stack-buffer-overflow", "use-after-free", "double-free"}


def analyze(report: ReportMetadata, results: list[StepResult]) -> tuple[list[CrashSignal], MemoryRiskLens, ImpactAssessment]:
    signals: list[CrashSignal] = []
    for step in results:
        merged = "\n".join([step.stdout, step.stderr])
        signals.extend(extract_signals(merged))

    memory_lens = build_memory_lens(signals)
    impact = assess_impact(report, results, signals, memory_lens)
    return signals, memory_lens, impact


def extract_signals(text: str) -> list[CrashSignal]:
    signals: list[CrashSignal] = []

    for match in ASAN_RE.finditer(text):
        access = ACCESS_RE.search(text)
        pc = PC_RE.search(text)
        region = REGION_RE.search(text)
        signals.append(
            CrashSignal(
                kind=match.group("kind").lower(),
                summary=f"ASAN detected {match.group('kind').lower()}",
                access_type=access.group(1).upper() if access else None,
                memory_region=region.group("region").lower() if region else "unknown",
                fault_address=match.group("addr"),
                pc=pc.group("pc") if pc else None,
                allocator_state="freed" if FREED_RE.search(text) else None,
                adjacency=infer_adjacency(text),
                stack_excerpt=_stack_excerpt(text),
            )
        )

    for match in UBSAN_RE.finditer(text):
        signals.append(
            CrashSignal(
                kind="ubsan",
                summary=match.group("summary").strip(),
                stack_excerpt=_stack_excerpt(text),
            )
        )

    if SIGSEGV_RE.search(text) and not signals:
        signals.append(
            CrashSignal(
                kind="sigsegv",
                summary="Segmentation fault observed without sanitizer classification",
                stack_excerpt=_stack_excerpt(text),
            )
        )

    return signals


def assess_impact(
    report: ReportMetadata,
    results: list[StepResult],
    signals: list[CrashSignal],
    memory_lens: MemoryRiskLens,
) -> ImpactAssessment:
    if not results:
        return _empty_assessment("insufficient-data", "low", "P3")

    unexpected_steps = [step for step in results if not step.expected]
    reasoning: list[str] = []
    boundaries: list[str] = []
    next_actions: list[str] = []
    exploitability_review_needed = memory_lens.exploitability_review_needed
    availability_risk = "low"
    integrity_risk = "low"
    confidentiality_risk = "low"
    verdict = "not-reproduced"
    confidence = "medium"
    priority = "P3"

    if unexpected_steps and not signals:
        verdict = "partial-reproduction"
        confidence = "low"
        availability_risk = "medium"
        reasoning.append("Unexpected exit codes were observed without a recognizable crash signature.")
        boundaries.append("Execution diverged from expectation, but a vulnerability boundary was not established.")
        next_actions.append("Re-check prerequisites, sanitizer flags, symbols, and report assumptions.")

    if signals:
        verdict = "reproduced"
        availability_risk = "high"
        reasoning.append(f"Detected {len(signals)} crash signal(s) during replay.")
        next_actions.append("Preserve the exact runtime artifacts for follow-up review and vendor communication.")

    for signal in signals:
        if signal.kind in MEMORY_CRITICAL:
            availability_risk = "high"
            integrity_risk = "high"
            confidentiality_risk = max_risk(confidentiality_risk, "medium")
            confidence = "high"
            priority = "P1"
            reasoning.append(
                f"{signal.kind} observed with {signal.access_type or 'unknown'} access against {signal.memory_region or 'unknown'} memory."
            )
            boundaries.append(
                "Security-critical memory corruption is proven. The harness stops at evidence collection and does not attempt exploitation."
            )
        elif signal.kind in {"global-buffer-overflow", "sigsegv"}:
            integrity_risk = max_risk(integrity_risk, "medium")
            confidence = max_confidence(confidence, "medium")
            priority = min_priority(priority, "P2")
            reasoning.append(signal.summary)
            boundaries.append("Crash impact is supported by runtime evidence, but exploitability is not established.")
        else:
            reasoning.append(signal.summary)

    if report.exposure in {"remote", "external", "unauthenticated-remote"}:
        priority = "P1" if exploitability_review_needed else min_priority(priority, "P2")
        reasoning.append(f"Attack surface is marked as `{report.exposure}`, which increases operational urgency.")

    if report.privileges_required in {"none", "anonymous"}:
        reasoning.append("The report claims no privileges are required to reach the issue.")

    if report.repeatability in {"high", "always"}:
        confidence = max_confidence(confidence, "high")
        reasoning.append("The issue is documented as highly repeatable.")

    next_actions.extend(memory_lens.review_cues[:2])
    boundaries.extend(memory_lens.analyst_boundaries)

    return ImpactAssessment(
        verdict=verdict,
        confidence=confidence,
        priority=priority,
        exploitability_review_needed=exploitability_review_needed,
        availability_risk=availability_risk,
        integrity_risk=integrity_risk,
        confidentiality_risk=confidentiality_risk,
        reasoning=dedupe(reasoning),
        boundaries=dedupe(boundaries),
        next_actions=dedupe(next_actions),
    )


def _empty_assessment(verdict: str, confidence: str, priority: str) -> ImpactAssessment:
    return ImpactAssessment(
        verdict=verdict,
        confidence=confidence,
        priority=priority,
        exploitability_review_needed=False,
        availability_risk="unknown",
        integrity_risk="unknown",
        confidentiality_risk="unknown",
        reasoning=["No steps were executed."],
        boundaries=["No reproduction data was available."],
        next_actions=["Define at least one replay step before running the harness."],
    )


def infer_adjacency(text: str) -> str:
    if RIGHT_RE.search(text):
        return "right-of-object"
    if LEFT_RE.search(text):
        return "left-of-object"
    if INSIDE_RE.search(text):
        return "inside-object"
    return "unknown"


def _stack_excerpt(text: str) -> list[str]:
    lines = []
    for line in text.splitlines():
        if line.strip().startswith("#"):
            lines.append(line.strip())
        if len(lines) == 6:
            break
    return lines


def dedupe(items: list[str]) -> list[str]:
    seen: set[str] = set()
    ordered: list[str] = []
    for item in items:
        if item not in seen:
            seen.add(item)
            ordered.append(item)
    return ordered


def max_risk(current: str, candidate: str) -> str:
    order = {"unknown": 0, "low": 1, "medium": 2, "high": 3}
    return current if order[current] >= order[candidate] else candidate


def max_confidence(current: str, candidate: str) -> str:
    order = {"low": 1, "medium": 2, "high": 3}
    return current if order[current] >= order[candidate] else candidate


def min_priority(current: str, candidate: str) -> str:
    order = {"P1": 1, "P2": 2, "P3": 3}
    return current if order[current] <= order[candidate] else candidate
