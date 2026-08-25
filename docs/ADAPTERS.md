# Adapter Matrix

`security-qa-harness` treats target behavior as the combination of a product preset and a language preset.

## Product Types

- `file-parser`
- `service`
- `web-app`
- `openapi`
- `grpc`
- `library`
- `jni-library`
- `native-harness`
- `cli-tool`
- `generic`

## Authentication

Cases may now declare an `[auth]` block with:

- `mode`
- `bearer_token`
- `cookie`
- `headers`
- `login_command`

This keeps authenticated replay explicit and reproducible. Configured token,
cookie, and header values are redacted from stored text outputs, but case files
still contain the supplied values and must not be committed with live secrets.

## Dump Collection

Adapters can declare `dump_globs` to collect crash artifacts such as:

- `core*`
- `hs_err_pid*.log`
- `*.hprof`
- `panic*.log`

## Example Templates

- [report-case.toml](../examples/report-case.toml)
- [intake-template.toml](../examples/intake-template.toml)
- [web-go-service.toml](../examples/web-go-service.toml)
- [cpp-library.toml](../examples/cpp-library.toml)
- [python-cli-tool.toml](../examples/python-cli-tool.toml)
- [jni-java-native.toml](../examples/jni-java-native.toml)
