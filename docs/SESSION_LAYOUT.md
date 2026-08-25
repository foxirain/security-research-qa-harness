# Session Layout

Use one directory per investigation.

Recommended pattern:

- `sessions/<session-id>/inputs/`
- `sessions/<session-id>/work/`
- `sessions/<session-id>/artifacts/`
- `sessions/<session-id>/report/`

Example:

```text
sessions/20260411-bcr-strip-prefix/
  inputs/
    review_index.json
    REVIEW_SUMMARY.md
  work/
    repro_notes.md
    crafted_inputs/
    helper_scripts/
  artifacts/
    command_logs/
    traces/
    generated_samples/
    proof_files/
  report/
    attack_board.md
    interim_summary.md
    final_report.md
```

## Usage

- `inputs/`: copied or referenced case inputs
- `work/`: scratch work, repro payloads, helper code, temporary experiments
- `artifacts/`: logs, traces, outputs, screenshots, generated files, captured evidence
- `report/`: attack board, escalation notes, final summaries

## Rule

If a file is created because of the investigation, put it inside the active session directory unless there is a specific reason not to.
