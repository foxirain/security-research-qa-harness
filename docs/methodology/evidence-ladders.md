# Evidence Ladders

Use these ladders to avoid both overclaiming and premature stopping.

## RCE

To justify `RCE`, most of the following must be established:

1. attacker-controlled influence reaches an execution sink, loader path, or trusted component that can invoke one
2. the influence remains attacker-controlled at that point
3. there is a trigger for execution
4. execution occurs in a meaningful target context

Evidence grades:

- `Confirmed`: controlled execution or equivalent decisive sink control is demonstrated
- `Supported`: a pre-execution primitive is demonstrated, such as file write, template injection, or command influence, but sink control or trigger is missing
- `Unknown`: the summary suggests a bridge but not enough to assess
- `Disproven`: a claimed sink or trigger is not actually reachable in the relevant path

Safe phrasing:

- "Arbitrary file write as the service user is proven. Full RCE is still unsupported because no executable load path, trigger, or controllable execution sink has been demonstrated."
- "Generated source injection is proven. Downstream code execution depends on trusted automated build consumption and is not yet directly demonstrated."

## Account takeover

To justify takeover, establish:

1. credential or session bypass path
2. access as another principal
3. ability to perform protected actions as that principal

## Tenant escape or authorization bypass

To justify a strong claim, establish:

1. attacker start position
2. unauthorized access or mutation outside intended scope
3. whether scope widens to arbitrary peer objects or cross-tenant objects

## Parser DoS

To justify a serious availability claim, establish:

1. attacker reachability to the parser path
2. deterministic resource amplification or crash behavior
3. practical input sizes and trigger reliability
4. service or workflow importance of the affected path

## Code-generation injection

To justify more than a code-quality issue, establish:

1. attacker control of schema or metadata reaching emitted source
2. missing escaping or validation in generation
3. whether the generated artifact is trusted and automatically consumed
4. whether that trust can realistically become build poisoning, developer compromise, or execution-adjacent impact

Do not flatten all code-generation injection into `RCE`.
Treat build integrity and supply-chain implications as first-class ceilings.

## Memory-safety findings

For underflow, OOB read, or verifier gaps, keep separate:

1. malformed input control
2. exact unsafe operation
3. reachable product entrypoint
4. demonstrated consequence today
5. strongest realistic consequence not yet proven
