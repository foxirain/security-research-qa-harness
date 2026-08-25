# Validation Receipt

## Release candidate

- Project: `security-research-qa-harness`
- Version: `0.2.0`
- Validation date: 26 August 2026
- Environment: local Linux workspace, Python 3.12

## Checks performed

| Check | Result | Claim boundary |
| --- | --- | --- |
| Standard-library regression suite | **30 / 30 passed** | Software and safety contracts covered by `tests/` |
| Python bytecode compilation | Passed | Tracked Python source imports and compiles in the validation environment |
| PEP 517 wheel build | Passed | A no-runtime-dependency wheel can be built from the repository |
| Fresh virtual-environment install | Passed | The built wheel imports as version `0.2.0` and exposes `security-qa-harness --help` |
| Synthetic case execution | Passed | Explicitly acknowledged demo run produced structured, technical, and executive outputs |
| Default OSS triage | Passed | Draft cases were generated with `execution_requested=false` and `not-executed` status |
| Execution gate | Passed | `run` without acknowledgement exited with CLI status 2 |
| Credential redaction | Passed | Configured token, cookie, header, command, and text-output values were masked in tested output paths |
| Source preservation | Passed | Both internal source worktrees remained clean after consolidation |

Commands used:

```bash
PYTHONPATH=src python3 -m unittest discover -s tests -v
python3 -m compileall -q src tests fixtures
python3 -m pip wheel . --no-deps -w /tmp/security-qa-wheels
```

The built wheel was installed into a fresh virtual environment outside the
repository. The installed package reported `0.2.0` and rendered CLI help.

## What this receipt does not prove

- vulnerability-detection precision or recall;
- exploitability of a reported memory-safety condition;
- safety of arbitrary case files or target repositories;
- containment of target commands;
- automatic removal of secrets from arbitrary binary artifacts;
- historical use of this exact public snapshot for any CVE.

CI repeats the unit and installed-wheel checks on Python 3.11, 3.12, and 3.13.
