# Validation Methodology

The harness records which reported behavior reproduced, which controls changed
the result, and which impact statements still require additional validation.

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

## 5. Classify result status

Each severe chain step is marked:

| Grade | Meaning |
| --- | --- |
| `Confirmed` | Direct runtime or artifact evidence establishes the step |
| `Supported` | Evidence makes the step credible, but a decisive artifact is missing |
| `Unknown` | Current material does not establish or falsify the step |
| `Disproven` | A required path, sink, trigger, or boundary did not hold in the relevant test |

## 6. Record impact limits

The report keeps three fields separate:

1. demonstrated impact;
2. possible but unverified impact;
3. the test or artifact still required.

For example, arbitrary source injection into a generated file may establish build-integrity risk without establishing code execution. A sanitizer-confirmed invalid read may establish a memory-safety defect and availability risk without establishing an arbitrary read or control-flow primitive.

## 7. Record negative results

Failed hypotheses and controls are retained when they affect interpretation of
the reported issue.

## 8. Final review

Before publication, the reviewer verifies authorization, target provenance,
affected versions, environmental assumptions, remediation, disclosure status,
and artifact safety.
