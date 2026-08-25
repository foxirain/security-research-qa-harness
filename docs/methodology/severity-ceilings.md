# Severity Ceilings

The goal is not to guess a CVSS score from intuition.
The goal is to state the strongest defensible impact ceiling from current evidence.

## Rule

Prefer a concrete impact statement over a label.

Examples:
- "Any authenticated user can read arbitrary peer invoices within a tenant."
- "An attacker-controlled schema can inject arbitrary tokens into generated C++ headers consumed by downstream builds."
- "Malformed attacker input can deterministically crash the JSON parser with attacker-controlled O(n^2) work and deep recursion."

## Ceiling framing

For each finding, state:

1. `Current ceiling`
2. `Stronger plausible ceiling`
3. `Blocking evidence`

## Typical upward moves

- single object -> arbitrary object
- same user scope -> other user scope
- same tenant -> cross tenant
- local crash -> remote unauthenticated crash
- malformed output -> trusted build ingestion
- parser weirdness -> deterministic service impact
- write primitive -> privileged or executable path influence

## Typical downward constraints

- requires trusted local operator action
- only affects generated source that is manually reviewed before use
- only crashes debug-only tooling or opt-in code paths
- verifier or bounds checks eliminate attacker-controlled dereference in real entrypoints
- severe claim depends on an unshown environment assumption

## Wording discipline

Good:
- "Build-integrity risk is supported; downstream code execution is not yet demonstrated."
- "Denial of service is credible; memory corruption is not established from the current evidence."
- "A schema-driven source injection primitive is proven in generated output; compromise of consumers depends on automated ingestion and trust in generated artifacts."

Bad:
- "Basically critical."
- "Probably RCE somehow."
