# Project Lineage

This public repository consolidates two internal prototypes without modifying either source repository.

| Internal lineage | Contribution retained here |
| --- | --- |
| `poc_harness` | Executable Python engine: adapters, report intake, declarative replay, service orchestration, boundary variants, runtime collectors, artifact diffs, memory-risk lens, and reports |
| `poc-harness` | Analyst methodology: attack boards, evidence ladders, impact expansion, severity ceilings, anti-patterns, playbooks, and session organization |

The consolidation is intentionally selective:

- generated internal run directories and research sessions are not included;
- the old multi-account `QA-department` Docker wrapper is not copied because containment is represented by the separate Agent Security Company lineage;
- package and CLI names are changed to `security_qa_harness` and `security-qa-harness`;
- public-release safety gates, credential redaction, tests, CI, bilingual documentation, and an Apache-2.0 license are added in this repository.

FoxCompany QA is a separate implementation. It provides worker identities,
sandbox and network policy, job assignment, and a generic test runner. Its
current `qa-test-run` worker does not invoke this package. The two can be used
together, but this public repository must not be described as an already
embedded FoxCompany component.

This repository is the assurance layer in the broader portfolio. It does not claim that the original private prototypes preserved every historical CVE QA run, nor that every public CVE was processed by this exact snapshot.
