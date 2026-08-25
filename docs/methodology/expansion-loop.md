# Expansion Loop

Use this loop whenever a finding appears real and the question becomes "how far can it go?"

## Loop

1. Name the primitive precisely.

Examples:
- arbitrary file write under service account
- code-generation source injection in produced header
- attacker-controlled parser worst-case recursion
- read-before-beginning during binary-to-text conversion

2. Identify the nearest higher-order consequence.

Examples:
- broader unauthorized read
- broader unauthorized write
- deterministic crash
- build poisoning
- execution-adjacent control
- privilege or tenant boundary crossing

3. Choose the single highest-value branch.

Good branches often:
- require one additional artifact
- clarify whether the finding is report-grade
- materially move the severity ceiling

4. Pressure-test the branch.

Ask:
- what exact preconditions are required?
- which are already established?
- what environment assumption is unstated?
- what minimal artifact would settle it?

5. Update the ceiling.

After every branch, restate:
- strongest defensible claim now
- strongest plausible but unproven claim
- why the stronger one is still blocked

## Branch heuristics

Prefer branches that test:

- arbitrary scope rather than single-instance scope
- low-privilege starts rather than privileged starts
- realistic deployment paths rather than lab-only paths
- stable repeatable effects rather than one-off weirdness
- impact relevant to leadership language

## Stop condition

Stop only when one of these is true:

- the ceiling is clear and additional work is low-yield
- the key branch is blocked on unavailable environment or authorization
- the remaining stronger claims are mostly speculative
