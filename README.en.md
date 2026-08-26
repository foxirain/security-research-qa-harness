# Security Research QA Harness

[한국어](README.md) | [English](README.en.md)

[![CI](https://github.com/foxirain/security-research-qa-harness/actions/workflows/ci.yml/badge.svg)](https://github.com/foxirain/security-research-qa-harness/actions/workflows/ci.yml)

A Python tool for turning vulnerability reports into reproducible cases and recording the run and its controls in one format.

This public repository consolidates two internal prototypes from April 2026: a Python engine for executing TOML cases and a QA procedure based on evidence ledgers and severity ceilings. Unpublished vulnerability material and internal run records are not included.

The current release is a **research prototype**. Its bundled demo uses synthetic output, and the repository does not claim that this public snapshot validated earlier CVEs.

## What it does

- Selects review candidates from a ranked Markdown report and drafts cases.
- Describes commands, environment, timeouts, expected exit codes, and collected paths in TOML.
- Runs a base case and a bounded set of nearby variants.
- Stores stdout, stderr, exit codes, and declared artifacts.
- Classifies ASan, UBSan, SIGSEGV, and selected language runtime output.
- Writes JSON and Markdown comparisons of the base and variants.

It does not:

- confirm vulnerabilities automatically;
- turn a crash into an RCE claim;
- create a sandbox or VM;
- treat generated PoC input as observed evidence;
- decide final severity or disclosure.

## How this differs from FoxCompany QA

Both projects cover QA, but at different layers.

| Area | FoxCompany QA | Security Research QA Harness |
| --- | --- | --- |
| Scope | Worker identity, sandbox, filesystem, network policy, and job assignment | Reproduction procedure and result format for one vulnerability report |
| Unit of execution | QA employee and work profile | TOML case and step |
| Default behavior | Isolated QA account, workspace, and generic `npm test` or `pytest` execution | Replay, controls, bounded variants, artifact comparison, and reports |
| Security boundary | Linux UID/GID, bubblewrap, seccomp, and proxy policy | None; only explicit execution acknowledgement |
| Final decision | Human operator and independent QA reviewer | Human review of the generated record |

FoxCompany's current `qa-test-run` worker does not invoke this CLI. The harness is therefore not an embedded FoxCompany component today. FoxCompany controls **where and under whose privileges a task runs**; this repository defines **what to replay and how to record it**. A reviewed case can be run manually inside a FoxCompany QA workspace.

## Install

Python 3.11 or newer is required. The runtime package uses only the standard library.

```bash
git clone https://github.com/foxirain/security-research-qa-harness.git
cd security-research-qa-harness

python3 -m venv .venv
source .venv/bin/activate
python -m pip install .
security-qa-harness --help
```

## Quick check

Validate a case without running its target commands:

```bash
security-qa-harness validate examples/report-case.toml
```

Run the bundled synthetic demo:

```bash
security-qa-harness run examples/report-case.toml \
  --output-root /tmp/security-qa-runs \
  --acknowledge-execution-risk
```

`--acknowledge-execution-risk` only records that the commands were reviewed. It does not provide isolation.

## Case format

| Section | Content |
| --- | --- |
| `[report]` | Reported behavior, attack surface, exposure, and repeatability |
| `[target]` | Target path and setup or cleanup commands |
| `[auth]` | Tokens, cookies, and headers |
| `[adapter]` | Language, product type, service, and runtime settings |
| `[replay]` | Direct command or OpenAPI/gRPC replay metadata |
| `[variables]` | Values used by commands and replay generation |
| `[boundary]` | Limits for variants and combinations |
| `[[steps]]` | Commands, working directory, timeout, expected exit codes, and collection paths |

Minimal example:

```toml
[report]
id = "parser-001"
title = "Parser crash"
category = "memory-corruption"
claim = "Malformed input crashes the parser"
attack_surface = "file-parser"

[target]
name = "local-target"
root = "/path/to/target"
adapter = "file-parser"

[boundary]
enabled = false

[[steps]]
name = "replay"
command = "./parser {POC_FILE}"
cwd = "."
timeout_seconds = 30
expected_exit_codes = [0]
collect_paths = []
```

Cases contain shell commands and must be reviewed like code. The current executor uses `shell=True`.

## Ranked report intake

Normalize a Markdown report into draft cases:

```bash
security-qa-harness intake examples/ranked-report.md \
  --output-root /tmp/security-qa-intake \
  --tiers S,A,B \
  --top-n 5
```

Profile an authorized repository and draft finding-specific commands:

```bash
security-qa-harness triage-oss examples/ranked-report.md \
  --repo /path/to/authorized-repository \
  --output-root /tmp/security-qa-oss \
  --top-n 3
```

The default is **draft only**. Review the generated TOML before adding `--execute`.

```bash
security-qa-harness triage-oss examples/ranked-report.md \
  --repo /path/to/authorized-repository \
  --output-root /tmp/security-qa-oss \
  --top-n 3 \
  --execute
```

Generated drafts apply these rules:

- Generated input is labeled `harness-generated-input-not-observed-evidence`.
- Generated input is not automatically collected as a target artifact.
- Generated and dependency trees such as `runs/`, `oss-runs/`, `build/`, `.venv/`, and `node_modules/` are excluded from source matching.
- Missing test runners, unavailable commands, and empty test selection become `operational-failure`.
- Variants do not run when the base command fails operationally.
- `run` and `triage-oss --execute` return exit code `3` when an operational failure occurs.
- The original claim text is never searched as observed evidence.

An automatically selected repository command may not be a finding-specific reproducer. Claim assessment is a review aid, not a final verdict.

## Output

```text
runs/<report-id>-<UTC-timestamp>/
├── 01-<step>/
│   ├── stdout.txt
│   └── stderr.txt
├── boundary/
├── analysis.json
├── analysis.md
└── executive_summary.md
```

`triage-oss --execute` also writes `claim_assessment.json` and `claim_assessment.md`. Each assessment separates runtime evidence sources from operational failures.

Configured bearer tokens, cookies, and header values are replaced with `[REDACTED]` in stored commands and text output. Arbitrary binary artifacts and target-created files are not inspected automatically.

## Supported inputs

- Adapters: file parser, service, OpenAPI, gRPC, library, JNI, native, and CLI
- Runtime signals: ASan, UBSan, SIGSEGV, Go panic, JVM fatal log, Python traceback, Node exception, and Rust panic
- Boundary axes: environment, variable, string length, file append or replacement, HTTP method/header/query, and argv append

See [Architecture](docs/ARCHITECTURE.md), [Adapter Matrix](docs/ADAPTERS.md), and [Methodology](docs/METHODOLOGY.md) for details.

## Verification

Checks recorded on 26 August 2026:

- unit tests: **40 / 40 passed**
- Python 3.12 compilation: passed
- wheel build and clean install: passed
- GitHub Actions on Python 3.11, 3.12, and 3.13

The tests cover case parsing, replay commands, runtime classification, variants, redaction, execution acknowledgement, operational failures, and prevention of claim self-substantiation. They do not measure vulnerability-detection accuracy or exploitability. Commands and claim boundaries are recorded in the [Validation Receipt](docs/VALIDATION.md).

## Known limitations

- The public example is a synthetic fixture, not a vulnerable program.
- The CLI is not automatically integrated with the current FoxCompany QA worker.
- A declared artifact in a general `run` may predate the execution; an analyst must check provenance.
- Repository command selection does not prepare target dependencies or build environments.
- Execution acknowledgement does not provide a container, VM, or network isolation.
- Pattern classification is not proof of vulnerability validity or exploitability.
- The repository does not claim that earlier CVEs were validated by this public snapshot.

## Repository map

| Path | Purpose |
| --- | --- |
| `src/security_qa_harness/` | Python package and CLI |
| `examples/`, `fixtures/` | Case examples and synthetic target |
| `docs/` | Architecture, methodology, publication safety, and validation records |
| `tests/` | Regression tests |

See [Project Lineage](docs/LINEAGE.md) for the relationship between the internal prototypes and this public repository.

## Related repositories

- [FoxCompany / Agent Security Company](https://github.com/foxirain/agent-security-company): worker identity and execution boundary
- [Agent Egress Lock](https://github.com/foxirain/agent-egress-lock): earlier network-containment prototype
- [Linux Kernel Codex Harness](https://github.com/foxirain/linux-kernel-codex-harness): Linux kernel review prioritization
- [Linux Kernel Codex Harness v2](https://github.com/foxirain/linux-kernel-codex-harness-v2): provenance-aware finding triage
- [Codex OSS Vulnerability Harness v2](https://github.com/foxirain/codex-oss-vuln-harness-v2): cross-language OSS review orchestration
- [Adaptive Codex OSS Vulnerability Harness](https://github.com/foxirain/codex-adaptive-oss-vuln-harness): execution and merge of isolated search sessions

## License

[Apache License 2.0](LICENSE)
