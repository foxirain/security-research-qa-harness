from __future__ import annotations

from .models import CrashSignal, MemoryRiskLens


def build_memory_lens(crash_signals: list[CrashSignal]) -> MemoryRiskLens:
    if not crash_signals:
        return MemoryRiskLens(
            exploitability_review_needed=False,
            corruption_class="none-observed",
            allocator_state="unknown",
            adjacency="unknown",
            control_data_proximity="unknown",
            likely_impacted_asset="availability-only",
            review_cues=["No memory corruption signature was recognized in collected output."],
            analyst_boundaries=["No corruption boundary is proven."],
        )

    top = crash_signals[0]
    corruption_class = top.kind
    allocator_state = top.allocator_state or infer_allocator_state(crash_signals)
    adjacency = top.adjacency or infer_adjacency(crash_signals)
    control_data = infer_control_data_proximity(crash_signals)
    likely_asset = infer_impacted_asset(crash_signals)
    review_cues = build_review_cues(crash_signals, allocator_state, adjacency, control_data)
    analyst_boundaries = build_boundaries(crash_signals, control_data)
    exploitability_review_needed = corruption_class in {
        "heap-buffer-overflow",
        "stack-buffer-overflow",
        "use-after-free",
        "double-free",
    }

    return MemoryRiskLens(
        exploitability_review_needed=exploitability_review_needed,
        corruption_class=corruption_class,
        allocator_state=allocator_state,
        adjacency=adjacency,
        control_data_proximity=control_data,
        likely_impacted_asset=likely_asset,
        review_cues=review_cues,
        analyst_boundaries=analyst_boundaries,
    )


def infer_allocator_state(crash_signals: list[CrashSignal]) -> str:
    kinds = {signal.kind for signal in crash_signals}
    if "use-after-free" in kinds or "double-free" in kinds:
        return "freed"
    if any(signal.memory_region == "heap" for signal in crash_signals):
        return "allocated"
    return "unknown"


def infer_adjacency(crash_signals: list[CrashSignal]) -> str:
    for signal in crash_signals:
        if signal.adjacency:
            return signal.adjacency
    if any(signal.kind.endswith("overflow") for signal in crash_signals):
        return "adjacent-object-risk"
    return "unknown"


def infer_control_data_proximity(crash_signals: list[CrashSignal]) -> str:
    if any(signal.memory_region == "stack" for signal in crash_signals):
        return "possible-stack-control-data"
    if any(signal.kind == "use-after-free" for signal in crash_signals):
        return "possible-heap-metadata-or-object-reuse"
    if any(signal.kind == "heap-buffer-overflow" for signal in crash_signals):
        return "adjacent-heap-object-risk"
    return "not-evidenced"


def infer_impacted_asset(crash_signals: list[CrashSignal]) -> str:
    if any(signal.memory_region == "stack" for signal in crash_signals):
        return "stack-frame-adjacent-data"
    if any(signal.memory_region == "heap" for signal in crash_signals):
        return "adjacent-heap-object-or-metadata"
    if any(signal.memory_region == "global" for signal in crash_signals):
        return "global-state"
    return "process-availability"


def build_review_cues(
    crash_signals: list[CrashSignal],
    allocator_state: str,
    adjacency: str,
    control_data: str,
) -> list[str]:
    cues = [
        f"Observed corruption class: {crash_signals[0].kind}.",
        f"Allocator state inference: {allocator_state}.",
        f"Adjacency inference: {adjacency}.",
        f"Control-data proximity inference: {control_data}.",
    ]
    if any(signal.access_type == "WRITE" for signal in crash_signals):
        cues.append("Write access was observed, which raises integrity risk above a read-only fault.")
    if any(signal.memory_region == "stack" for signal in crash_signals):
        cues.append("Stack memory involvement warrants manual review for frame-local control data adjacency.")
    if any(signal.kind == "use-after-free" for signal in crash_signals):
        cues.append("Freed-object reuse was indicated; review object lifetime, allocator behavior, and adjacent fields manually.")
    return cues


def build_boundaries(crash_signals: list[CrashSignal], control_data: str) -> list[str]:
    boundaries = [
        "The harness establishes corruption evidence and likely affected memory context, not code-execution proof.",
        "Exploitability must be decided by a human analyst in an isolated review environment.",
    ]
    if control_data != "not-evidenced":
        boundaries.append(f"Potential control-data adjacency is inferred as `{control_data}`, but not demonstrated.")
    return boundaries
