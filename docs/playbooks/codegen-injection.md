# Playbook: Code-Generation Injection

Use this for findings where attacker-controlled schema or metadata is emitted into generated source.

## Questions to answer

1. What exact field is attacker-controlled?
2. Is escape decoding applied before emission?
3. Is emission performed inside a quoted literal, directive, comment, attribute, or raw source region?
4. What syntax breakouts become possible?
5. Who consumes the generated artifact?
6. Is consumption manual, semi-automated, or trusted and automated?

## Important ceilings

Common realistic ceilings are:

- build poisoning
- source integrity compromise
- developer workstation risk if generated code is trusted and built automatically
- CI pipeline contamination

## Common mistake

Do not jump directly to `RCE`.
The strongest defensible claim may be:
- arbitrary source injection into generated artifacts
- trusted build-path compromise
- downstream execution-adjacent risk if automated ingestion is normal

## High-value validation artifacts

- minimal schema showing breakout in generated source
- generated output snippet proving arbitrary token injection
- proof that default tooling or CI consumes the artifact automatically
- proof that manual review is absent or bypassed in normal workflow
