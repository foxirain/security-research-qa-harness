# Playbook: Memory-Safety Exploitability Risk

Use this for OOB read, OOB write, underflow, overflow, UAF, double free, verifier bypass, malformed buffer handling, or adjacent memory-corruption claims.

## Goal

Do not stop at "there is a crash" or "there is an invalid read."
Explain:

- what memory is actually at risk
- why that memory matters
- what attacker control exists today
- why the primitive is or is not exploitation-relevant
- what evidence is still missing for a stronger exploitability claim

## Questions to answer

1. What exact primitive exists?
- invalid read
- invalid write
- underflow
- overflow
- use-after-free
- double free
- type confusion
- verifier bypass leading to unsafe dereference

2. What exact memory region or object boundary is at risk?
- stack
- heap
- global/static
- object field boundary
- vector/string buffer boundary
- allocator metadata-adjacent region
- control-flow-adjacent object or callback slot

3. What attacker control exists?
- offset control
- size/length control
- contents control
- allocation shape or layout influence
- trigger repeatability
- crash reliability

4. What protects or limits exploitation?
- verifier coverage
- bounds checks on real entrypoints
- parser structure requirements
- allocator behavior assumptions
- object layout uncertainty
- missing write primitive
- missing control-flow-relevant target

5. What is the demonstrated consequence today?
- deterministic crash
- ASAN/UBSAN invalid read or write
- silent corruption hypothesis
- parser misbehavior
- possible info disclosure hypothesis

6. What stronger consequence is being implied without evidence?
- reliable arbitrary read
- reliable arbitrary write
- control-flow hijack
- code execution

## Exploitability-risk framing

For memory-safety findings, explicitly answer these:

- `Why exploitation risk exists`
- `Why exploitation risk is currently limited`
- `What evidence would move the claim upward`

Good examples:

- "Exploitability risk is present because the attacker controls both length and contents of a heap-adjacent overwrite, and the affected boundary is not limited to read-only parsing state."
- "Exploitability risk is currently limited because the evidence only shows an invalid read before the beginning of a transient buffer, with no demonstrated write primitive or control-flow-adjacent corruption target."
- "A stronger claim would require proof that attacker-controlled malformed input reaches a stable overwrite of security-relevant heap state in a real entrypoint."

## Ceiling discipline

A credible memory-safety finding may justify:

- denial of service
- info disclosure risk hypothesis
- memory-corruption exploitability risk
- high-severity parser robustness failure

Do not imply full exploitation beyond the current evidence.
But also do not collapse a meaningful corruption primitive into "just DoS" if overwrite direction, attacker control, and sensitive adjacency make exploitability risk real.

## High-value validation artifacts

- sanitizer trace
- crashing reproducer
- verifier coverage gap tied to the unsafe operation
- proof that malformed input survives to the sink in the real product path
- proof of attacker control over offset, size, contents, or trigger repetition
- evidence about the corrupted object boundary or sensitive adjacent structure

## Output template

For a memory-safety finding, prefer this structure:

1. `Primitive`
2. `Memory region or boundary at risk`
3. `Attacker control`
4. `Why exploitability risk exists`
5. `Why exploitability risk is limited`
6. `Current strongest defensible claim`
7. `Evidence needed for a stronger claim`
