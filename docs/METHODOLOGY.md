# Evidence-Led QA Methodology

The harness implements a narrow defensive question: **what is the highest impact statement that the current evidence can support?**

## 1. Normalize the claim

Convert prose into testable fields:

- attacker starting position;
- reachable entrypoint;
- attacker-controlled value or state;
- sensitive sink or broken invariant;
- observed consequence;
- missing evidence for any stronger consequence.

The ranked intake keeps `S > A > B > C > D` ordering, but ranking only allocates QA effort. It is not a severity verdict.

## 2. Establish the base replay

The base replay should preserve the reporter's smallest credible path, environment assumptions, exact command, expected exit states, and collection paths. A valid case definition is not proof that the claim reproduces.

## 3. Add controls

Use the same target and measurement path for:

- a positive case expected to trigger the behavior;
- a negative case that removes the suspected condition;
- a stability case that repeats or perturbs the trigger without changing its security meaning.

Controls are represented as explicit replay steps or bounded axes. They should be small enough that a changed result has a defensible explanation.

## 4. Explore the nearest boundary

Boundary axes change one property at a time where possible: environment mode, variable value, input size, file token, HTTP method/header/query, or argv fragment. The goal is not blind fuzzing. The goal is to answer whether the primitive survives a meaningful change in privilege, scope, object, parser mode, or input shape.

See the [expansion loop](methodology/expansion-loop.md) and [evidence ladders](methodology/evidence-ladders.md).

## 5. Build an evidence ledger

Each severe chain step is marked:

| Grade | Meaning |
| --- | --- |
| `Confirmed` | Direct runtime or artifact evidence establishes the step |
| `Supported` | Evidence makes the step credible, but a decisive artifact is missing |
| `Unknown` | Current material does not establish or falsify the step |
| `Disproven` | A required path, sink, trigger, or boundary did not hold in the relevant test |

## 6. Set the severity ceiling

State three things separately:

1. current ceiling;
2. stronger plausible ceiling;
3. exact blocking evidence.

For example, arbitrary source injection into a generated file may establish build-integrity risk without establishing code execution. A sanitizer-confirmed invalid read may establish a memory-safety defect and availability risk without establishing an arbitrary read or control-flow primitive.

## 7. Preserve negative findings

Important failed hypotheses belong in the report. They explain why a stronger claim was rejected and make the surviving claim more credible.

## 8. Require human closure

The harness classifies evidence and produces reports. A human still verifies authorization, target provenance, affected versions, environmental realism, remediation, coordinated disclosure, and publication safety.
