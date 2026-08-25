# Anti-Patterns

These are the common ways model-driven vulnerability analysis becomes mediocre.
Do not do these.

## 1. Bug-class autopilot

Do not jump from a familiar bug class to a catastrophic conclusion.
Example failures:
- file write therefore RCE
- OOB read therefore info leak therefore code execution
- code generation injection therefore immediate developer compromise

State the exact proven primitive and the missing chain steps.

## 2. Defensive underreach

Do not stop at the first demonstrated effect when adjacent impact is obvious.
Example failures:
- proving one out-of-scope object read but not testing arbitrary peer objects
- proving parser crash possibility but not asking if the crash is deterministic and remotely reachable
- proving generated source injection but not asking whether it reaches default build paths or trusted CI workflows

## 3. Summary parroting

A curated review summary is a compressed evidence set, not the final answer.
Transform it into attack primitives, boundaries, blockers, and next validations.

## 4. Severity-by-adjective

Do not say "critical", "high", or "low" before stating the boundary crossed and the real ceiling.

## 5. Missing negative findings

If an important catastrophic path is not justified, say exactly why.
This makes the eventual stronger claim more credible.

## 6. Over-indexing on novelty

Choose the branch with the highest decision value, not the weirdest branch.

## 7. Treating build-path findings as harmless by default

Code-generation or schema-driven source injection may not be direct RCE, but it can still be a serious build-integrity or supply-chain issue.
Analyze who consumes the generated artifact, under what trust assumptions, and how automated the path is.

## 8. Treating memory-safety weirdness as automatically exploitable

A malformed-input crash, underflow, or unchecked read must still be translated into a realistic impact ceiling.
Verifier presence, parser context, process model, and attacker control all matter.
