# Review Summary Intake

Use this when the session starts from curated artifacts rather than raw source.

## Best input shape

The preferred input pair is:

- `review_index.json`
- `REVIEW_SUMMARY.md`

Why:

- `review_index.json` carries structured fields such as title, tier, confidence, disposition, reachability, attacker_control, impact, blocking_gaps, and next_actions
- `REVIEW_SUMMARY.md` carries analyst-compressed narrative and tier ordering that helps calibrate emphasis

When both are present, use them like this:

1. Treat `review_index.json` as the primary evidence ledger.
2. Use `REVIEW_SUMMARY.md` to confirm tier emphasis, including any `S tier` above `A tier`, and to catch summary-level framing useful for leadership language.
3. If they conflict, prefer the JSON for exact field content and call out the inconsistency.

## Goal

Turn the two review artifacts into a working attack board for aggressive reproduction and aggressive expansion.

## Procedure

1. Read the JSON rows first.

For each review, extract:
- title
- tier
- confidence
- disposition
- summary
- reachability
- attacker_control
- impact
- key_evidence
- blocking_gaps
- next_actions

2. Read the Markdown summary second.

Use it to:
- confirm relative importance of tiers, including `S > A > B > C > D` when present
- check whether any finding is framed more cautiously or more aggressively at the summary level
- extract the headline claims likely to matter in an executive escalation

3. Normalize each finding into these attack-board columns:
- finding
- tier and confidence
- current primitive
- attacker starting position
- asset or boundary at risk
- strongest defensible claim now
- stronger plausible claim
- exact blocker
- next highest-value validation

4. Classify the finding's current state:
- `Report-ready`: enough evidence to support a strong technical claim now
- `Promising but blocked`: real primitive, but stronger impact needs one or two decisive artifacts
- `Overclaimed`: code path may be real, but the threat model or impact story is not yet credible
- `Not a registry/product issue`: sink exists, but there is no meaningful attacker-controlled product boundary

5. Rank findings for deep analysis using this rule:
- if `S-tier` exists, analyze every `S-tier` finding first
- after that, choose only the most promising `A-tier` findings for deep work
- use `B/C/D` primarily as chain-support material or as constraints on stronger findings
- only promote a lower-tier finding when it materially raises, constrains, or disproves the ceiling of an `S/A` branch
- compress all non-promoted lower-tier findings

## How to use `blocking_gaps` and `next_actions`

Treat `blocking_gaps` and `next_actions` as analyst-provided hints, not binding instructions.

Use `blocking_gaps` to understand why the current ceiling is not higher yet.
Use `next_actions` to understand what the prior analyst thought was a useful next move.

But do not let either field lock the analysis path.
If a more aggressive, more decisive, or higher-value validation path exists, prefer it and explain why.

Good use:
- `blocking_gaps` helps identify the missing artifact for a stronger claim
- `next_actions` provides a candidate follow-up branch

Bad use:
- blindly following `next_actions` when a more aggressive chain-expansion branch exists
- treating `blocking_gaps` as a complete list of all meaningful missing evidence

## Path-based workflow

When the user gives file paths instead of pasted content:

1. Read only the provided artifact paths first.
2. Build the attack board before reading broader source context.
3. Use the board to decide which source files or code paths deserve deeper inspection.
4. Spend the first serious effort on `S-tier`, then on the strongest `A-tier` branches.
5. Pull in `B/C/D` only if they help chain or cap the more important branches.

## Review-summary specific rules

- Do not repeat the summary back as if that were analysis.
- Normalize analyst language into security boundaries and chain steps.
- Preserve uncertainty exactly.
- Prefer concrete missing artifacts, such as a crash trace, generated source sample, unauthorized cross-scope read, overwrite target, or proof of controllable sink reachability.
- Default to aggressive reproduction and aggressive expansion when the current primitive is credible.

## Good reframing examples

Instead of:
- "This looks severe."

Prefer:
- "The summary supports attacker-controlled source injection into generated C++ or Rust output, which is a supply-chain and build-integrity issue. It does not yet show automatic code execution in a consumer environment."

Instead of:
- "Possible RCE."

Prefer:
- "A pre-execution primitive is present. RCE remains unproven because execution trigger, controllable sink semantics, and target runtime context are not yet demonstrated."
