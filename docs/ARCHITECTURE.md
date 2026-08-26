# Architecture

Security Research QA Harness separates report intake, controlled execution,
result comparison, and final review. A completed command records process state;
it does not by itself establish vulnerability impact or exploitability.

![Evidence-led QA pipeline](assets/qa-evidence-pipeline.svg)

## Processing stages

| Stage | Input | Output | Trust boundary |
| --- | --- | --- | --- |
| Intake | Ranked Markdown report or TOML case | Normalized finding set and draft cases | Analyst-supplied claims are untrusted hypotheses |
| Planning | Target profile, adapter, replay metadata | Explicit commands, variables, controls, collection paths | Generated commands require human review |
| Execution | Reviewed case in an isolated target | Exit state, redacted stdout/stderr, selected artifacts | Commands run only after an explicit execution flag |
| Boundary exploration | Base case and declarative axes | Controlled variants and artifact diffs | Variant count is bounded by the case definition |
| Result analysis | Runtime output and collected artifacts | Crash signals, runtime observations, memory-risk fields | Pattern classification does not establish exploitability |
| Reporting | Structured analysis | Technical report and executive summary | Final severity and disclosure require separate review |

## Relationship to FoxCompany QA

FoxCompany and this repository operate at different layers. FoxCompany owns the
QA employee identity, sandbox profile, filesystem view, network policy, job
assignment, and artifact handoff. This repository owns the case schema, replay
steps, bounded variants, runtime classification, and report format.

The current FoxCompany `qa-test-run` worker runs generic project tests and does
not call `security-qa-harness`. Integration is therefore manual: install this
package in an authorized QA workspace, review the case, and execute it under the
FoxCompany policy selected for that worker. The execution acknowledgement in
this CLI is not a substitute for the FoxCompany boundary.

## Module map

| Module | Responsibility |
| --- | --- |
| `config.py`, `models.py` | TOML case parsing and structured contracts |
| `adapters.py` | Product and language defaults for files, services, APIs, libraries, JNI, native harnesses, and CLIs |
| `replay.py`, `executor.py` | Declarative request generation, explicit command execution, timeout handling, and secret redaction |
| `orchestration.py` | Target setup, service lifecycle, health checks, and cleanup |
| `boundary.py`, `diffing.py` | Bounded variants and comparison with the base replay |
| `analyzer.py`, `memory_lens.py`, `collectors.py` | Crash, runtime, allocator, adjacency, and exploitability-review cues |
| `intake.py`, `oss_workflow.py` | Ranked-report normalization, repository profiling, draft generation, and optional execution |
| `reporting.py` | Machine-readable, analyst, and leadership outputs |

## Execution boundary

Case files are executable specifications. `run` refuses to proceed without `--acknowledge-execution-risk`, and `triage-oss` drafts cases without running them unless `--execute` is supplied. These flags are intentional friction, not a sandbox. Run reviewed cases only against authorized targets in a disposable, credential-minimized environment such as [Agent Security Company](https://github.com/foxirain/agent-security-company).

Bearer tokens, cookies, and configured header values are redacted from stored commands, stdout, stderr, and `analysis.json`. Arbitrary target artifacts may still contain secrets, so artifact review is required before publication.

Auto-generated OSS cases use a narrower evidence boundary:

- generated PoC files are inputs and are not collected as target evidence;
- source matching excludes generated output, dependency, build, and cache trees;
- runtime evidence comes from the current command output unless an analyst adds
  reviewed collection paths;
- a missing runner, unavailable command, or empty test selection produces an
  `operational-failure`, skips boundary variants, and returns CLI exit code 3;
- claim text is retained for reporting but is not part of observed evidence.
