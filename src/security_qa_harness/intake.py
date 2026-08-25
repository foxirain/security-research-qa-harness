from __future__ import annotations

from dataclasses import asdict, dataclass
from pathlib import Path
import json
import re


TIER_WEIGHT = {"S": 5, "A": 4, "B": 3, "C": 2, "D": 1}
SECTION_RE = re.compile(r"^##\s+([SABCD])\s+Tier\s*$", re.IGNORECASE)
BULLET_RE = re.compile(r"^[-*]\s+(.*\S)\s*$")


@dataclass(slots=True)
class IntakeFinding:
    finding_id: str
    tier: str
    rank: int
    title: str
    summary: str
    bug_class: str
    attack_surface: str
    target_component: str
    reproduction_priority: str
    exploitability_review_needed: bool
    analyst_notes: list[str]


def build_selected_findings(
    findings: list[IntakeFinding],
    allowed_tiers: tuple[str, ...] = ("S", "A", "B"),
    top_n: int = 5,
) -> list[IntakeFinding]:
    allowed = tuple(item.upper() for item in allowed_tiers)
    prioritized = [item for item in findings if item.tier in allowed]
    prioritized.sort(key=rank_key)
    return prioritized[:top_n]


def normalize_report(
    report_path: Path,
    output_root: Path,
    allowed_tiers: tuple[str, ...] = ("S", "A", "B"),
    top_n: int = 5,
) -> Path:
    text = report_path.read_text(encoding="utf-8")
    findings = parse_findings(text)
    allowed = tuple(item.upper() for item in allowed_tiers)
    selected = build_selected_findings(findings, allowed, top_n)

    output_root.mkdir(parents=True, exist_ok=True)
    drafts_dir = output_root / "drafts"
    drafts_dir.mkdir(parents=True, exist_ok=True)

    (output_root / "normalized_findings.json").write_text(
        json.dumps(
            {
                "source_report": str(report_path),
                "allowed_tiers": list(allowed),
                "top_n": top_n,
                "selected_count": len(selected),
                "skipped_count": len(findings) - len(selected),
                "findings": [asdict(item) for item in findings],
                "selected_findings": [asdict(item) for item in selected],
            },
            indent=2,
        ),
        encoding="utf-8",
    )
    (output_root / "intake_summary.md").write_text(render_summary(report_path, findings, selected, allowed, top_n), encoding="utf-8")
    for item in selected:
        (drafts_dir / (item.finding_id + ".toml")).write_text(render_toml_draft(item, report_path), encoding="utf-8")
    return output_root


def parse_findings(text: str) -> list[IntakeFinding]:
    findings: list[IntakeFinding] = []
    current_tier = ""
    counters: dict[str, int] = {}
    for raw_line in text.splitlines():
        heading = SECTION_RE.match(raw_line.strip())
        if heading:
            current_tier = heading.group(1).upper()
            continue
        bullet = BULLET_RE.match(raw_line)
        if not bullet or not current_tier:
            continue
        summary = bullet.group(1).strip()
        counters[current_tier] = counters.get(current_tier, 0) + 1
        findings.append(
            IntakeFinding(
                finding_id="%s-%02d" % (current_tier.lower(), counters[current_tier]),
                tier=current_tier,
                rank=TIER_WEIGHT[current_tier],
                title=derive_title(summary),
                summary=summary,
                bug_class=classify_bug_class(summary),
                attack_surface=classify_attack_surface(summary),
                target_component=extract_component(summary),
                reproduction_priority=classify_reproduction_priority(current_tier, summary),
                exploitability_review_needed=needs_exploitability_review(summary),
                analyst_notes=derive_notes(summary),
            )
        )
    return findings


def rank_key(item: IntakeFinding) -> tuple[int, int, int, str]:
    exploit_weight = 1 if item.exploitability_review_needed else 0
    memory_weight = 1 if item.bug_class in {"memory-corruption", "use-after-free", "heap-overflow", "stack-overflow", "null-dereference"} else 0
    return (-item.rank, -exploit_weight, -memory_weight, item.title)


def derive_title(summary: str) -> str:
    core = summary.split(":", 1)[0].strip()
    return core[:120] if core else summary[:120]


def classify_bug_class(summary: str) -> str:
    value = summary.lower()
    if "use-after-free" in value:
        return "use-after-free"
    if "heap" in value and "overflow" in value:
        return "heap-overflow"
    if "stack" in value and ("overflow" in value or "exhaust" in value):
        return "stack-overflow"
    if "null dereference" in value or "null-dereference" in value:
        return "null-dereference"
    if "traversal" in value or "zip entry" in value:
        return "archive-path-traversal"
    if "integer-overflow" in value or "integer overflow" in value:
        return "integer-overflow"
    if "dos" in value or "denial-of-service" in value:
        return "denial-of-service"
    if "memory corruption" in value:
        return "memory-corruption"
    if "recursion" in value or "stack exhaustion" in value:
        return "unbounded-recursion"
    return "needs-manual-classification"


def classify_attack_surface(summary: str) -> str:
    value = summary.lower()
    if ".proto" in value or "proto" in value:
        return "proto-input"
    if "text_format" in value or "text input" in value:
        return "protobuf-text-format"
    if "archive" in value or ".jar" in value or ".srcjar" in value:
        return "archive-output"
    if "php" in value:
        return "php-extension"
    if "python" in value:
        return "python-binding"
    if "java" in value or "kotlin" in value:
        return "java-generator"
    return "unknown"


def extract_component(summary: str) -> str:
    match = re.search(r"`([^`]+)`", summary)
    if match:
        return match.group(1)
    head = summary.split(":", 1)[0].strip()
    return head[:80]


def classify_reproduction_priority(tier: str, summary: str) -> str:
    value = summary.lower()
    if tier == "S":
        return "immediate"
    if tier == "A":
        return "immediate"
    if tier == "B" and ("reproducer" in value or "plausible" in value or "strong" in value):
        return "high"
    if tier == "B":
        return "medium"
    return "deferred"


def needs_exploitability_review(summary: str) -> bool:
    value = summary.lower()
    hot_terms = [
        "memory corruption",
        "use-after-free",
        "overflow",
        "null dereference",
        "integer-overflow",
        "integer overflow",
        "stack exhaustion",
        "recursionerror",
        "traversal",
    ]
    return any(item in value for item in hot_terms)


def derive_notes(summary: str) -> list[str]:
    notes: list[str] = []
    value = summary.lower()
    if "reproducer" not in value and "reproduced" not in value:
        notes.append("No concrete reproducer is embedded in this bullet; validate the claim path before severity sign-off.")
    if "downstream" in value or "extractor" in value:
        notes.append("Impact may depend on a downstream consumer rather than the immediate component alone.")
    if "stack" in value or "recursion" in value:
        notes.append("Recursion or stack-driven failures should be profiled with controlled depth increments.")
    if "archive" in value or "zip" in value:
        notes.append("Confirm whether the generated archive entry names are dangerous on extraction, not just at creation time.")
    return notes


def render_summary(
    report_path: Path,
    findings: list[IntakeFinding],
    selected: list[IntakeFinding],
    allowed_tiers: tuple[str, ...],
    top_n: int,
) -> str:
    lines = [
        "# Intake Summary",
        "",
        "- Source report: `%s`" % report_path,
        "- Allowed tiers: `%s`" % ", ".join(allowed_tiers),
        "- Top N selected: `%s`" % top_n,
        "- Parsed findings: `%s`" % len(findings),
        "- Selected findings: `%s`" % len(selected),
        "",
        "## Selected Findings",
    ]
    if not selected:
        lines.append("- No findings matched the requested tiers.")
    for item in selected:
        lines.append("### %s" % item.finding_id)
        lines.append("- Tier: `%s`" % item.tier)
        lines.append("- Title: %s" % item.title)
        lines.append("- Bug class: `%s`" % item.bug_class)
        lines.append("- Attack surface: `%s`" % item.attack_surface)
        lines.append("- Component: `%s`" % item.target_component)
        lines.append("- Reproduction priority: `%s`" % item.reproduction_priority)
        lines.append("- Manual exploitability review: `%s`" % item.exploitability_review_needed)
        lines.append("- Summary: %s" % item.summary)
        for note in item.analyst_notes:
            lines.append("- Note: %s" % note)
        lines.append("")
    return "\n".join(lines).rstrip() + "\n"


def render_toml_draft(item: IntakeFinding, report_path: Path) -> str:
    notes = ["Derived automatically from markdown intake."] + item.analyst_notes
    asset = "poc-input"
    if item.attack_surface == "archive-output":
        asset = "archive-output"
    elif item.attack_surface == "protobuf-text-format":
        asset = "text-input"
    elif item.attack_surface == "proto-input":
        asset = "proto-input"
    claim = item.summary.replace('"', "'")
    title = item.title.replace('"', "'")
    component = item.target_component.replace('"', "'")
    notes_block = "; ".join(note.replace('"', "'") for note in notes)
    return """[report]
id = \"{finding_id}\"
title = \"{title}\"
reporter = \"unknown\"
category = \"{bug_class}\"
claim = \"{claim}\"
attack_surface = \"{attack_surface}\"
exposure = \"unknown\"
privileges_required = \"unknown\"
user_interaction = \"unknown\"
input_origin = \"report-derived\"
repeatability = \"unknown\"
assets = [\"{asset}\"]
notes = \"Source report: {report_path}; Component hint: {component}; {notes_block}\"

[target]
name = \"target-under-review\"
root = \"/absolute/path/to/isolated/test/target\"
adapter = \"generic\"
setup = []
cleanup = []

[adapter]
kind = \"generic\"
product_type = \"generic\"
language = \"generic\"
framework = \"unknown\"
sanitizer_profile = \"none\"
notes = [\"Replace adapter metadata with the real target before replay.\"]

[replay]
mode = \"none\"

[variables]
POC_FILE = \"artifacts/poc-input.bin\"

[boundary]
enabled = true
max_variants = 5
combine_depth = 1

[[steps]]
name = \"Replay report claim\"
objective = \"Validate the normalized finding and confirm the highest safe impact boundary\"
tags = [\"intake-generated\", \"tier-{tier}\", \"priority-{priority}\"]
command = \"echo Replace this command with a safe local repro for {component}\"
cwd = \".\"
timeout_seconds = 60
expected_exit_codes = [0, 1]
collect_paths = [\"artifacts/poc-input.bin\"]
""".format(
        finding_id=item.finding_id,
        title=title,
        bug_class=item.bug_class,
        claim=claim,
        attack_surface=item.attack_surface,
        asset=asset,
        report_path=report_path,
        component=component,
        notes_block=notes_block,
        tier=item.tier.lower(),
        priority=item.reproduction_priority,
    )
