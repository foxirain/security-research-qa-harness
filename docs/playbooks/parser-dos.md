# Playbook: Parser DoS

Use this for recursion, worst-case complexity, unbounded memory growth, stack exhaustion, or crash-on-parse claims.

## Questions to answer

1. Is the parser path reachable from attacker input in a real service or tool workflow?
2. Is the effect CPU, memory, stack, or direct crash?
3. Is the behavior deterministic and repeatable?
4. What input structure maximizes the effect?
5. Are there caps, guards, verifier checks, or depth limits?

## Ceiling discipline

A parser DoS can still be serious if it is remotely reachable and deterministic.
But do not inflate it into memory corruption without proof.

## High-value validation artifacts

- end-to-end crash trace or sanitizer trace
- measured complexity blow-up
- stack depth or recursion evidence
- minimum malicious input required
- service reachability from an attacker-controlled path
