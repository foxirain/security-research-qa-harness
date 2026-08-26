# Security Research QA Harness

[한국어](README.md) | [English](README.en.md)

[![CI](https://github.com/foxirain/security-research-qa-harness/actions/workflows/ci.yml/badge.svg)](https://github.com/foxirain/security-research-qa-harness/actions/workflows/ci.yml)

취약점 보고서를 재현 가능한 case로 만들고, 실행 결과와 대조군을 같은 형식으로 남기는 Python 도구다.

이 저장소는 2026년 4월에 만든 두 내부 prototype을 공개용으로 합친 것이다. 하나는 TOML case를 실행하는 Python 코드였고, 다른 하나는 evidence ledger와 severity ceiling을 사용하는 QA 절차였다. 공개본에는 미공개 취약점 자료와 내부 실행 기록을 넣지 않았다.

현재 상태는 **research prototype**이다. 포함된 demo는 synthetic output을 사용하며, 이 공개 snapshot으로 기존 CVE를 검증했다고 주장하지 않는다.

## 하는 일

- Markdown 보고서에서 우선 검토할 finding을 뽑아 case 초안을 만든다.
- 재현 명령, 환경 변수, timeout, 예상 종료 코드와 수집 파일을 TOML로 정의한다.
- base case와 제한된 조건 변형을 실행한다.
- stdout, stderr, 종료 코드와 지정한 artifact를 저장한다.
- ASan, UBSan, SIGSEGV와 일부 언어별 runtime output을 분류한다.
- base와 variant의 결과 차이를 JSON과 Markdown으로 정리한다.

이 도구가 하지 않는 일도 분명하다.

- 취약점을 자동으로 확정하지 않는다.
- crash를 RCE로 해석하지 않는다.
- sandbox나 VM을 만들지 않는다.
- 생성한 PoC 입력을 관찰된 증거로 취급하지 않는다.
- 최종 severity와 공개 여부를 결정하지 않는다.

## FoxCompany QA와의 차이

두 프로젝트 모두 QA를 다루지만 역할이 다르다.

| 구분 | FoxCompany QA | Security Research QA Harness |
| --- | --- | --- |
| 담당 범위 | 작업자 identity, sandbox, filesystem, network policy, 작업 배정 | 개별 취약점의 재현 절차와 결과 형식 |
| 실행 단위 | QA 직원과 work profile | TOML case와 step |
| 기본 기능 | 분리된 QA 계정, 작업공간, 범용 `npm test`·`pytest` 실행 | replay, control, bounded variant, artifact 비교, 보고서 |
| 보안 경계 | Linux UID/GID, bubblewrap, seccomp, proxy policy | 없음. 명시적 실행 승인만 제공 |
| 최종 판단 | 사람과 별도 QA reviewer | 사람이 출력 자료를 검토 |

현재 FoxCompany의 `qa-test-run` worker는 이 저장소의 CLI를 호출하지 않는다. 따라서 이 도구가 FoxCompany QA에 이미 내장돼 있는 것은 아니다. FoxCompany는 **어디서 누구 권한으로 실행할지**를 관리하고, 이 저장소는 **무엇을 어떻게 재현하고 기록할지**를 정의한다. 필요하면 검토한 case를 FoxCompany QA 작업공간 안에서 수동으로 실행할 수 있다.

## 설치

Python 3.11 이상이 필요하다. runtime dependency는 표준 라이브러리뿐이다.

```bash
git clone https://github.com/foxirain/security-research-qa-harness.git
cd security-research-qa-harness

python3 -m venv .venv
source .venv/bin/activate
python -m pip install .
security-qa-harness --help
```

## 빠른 확인

Case 형식만 검사한다. 대상 명령은 실행하지 않는다.

```bash
security-qa-harness validate examples/report-case.toml
```

포함된 synthetic demo를 실행한다.

```bash
security-qa-harness run examples/report-case.toml \
  --output-root /tmp/security-qa-runs \
  --acknowledge-execution-risk
```

`--acknowledge-execution-risk`는 case의 명령을 검토했다는 표시일 뿐이다. 격리를 제공하지 않는다.

## Case 형식

Case는 다음 내용을 담는다.

| Section | 내용 |
| --- | --- |
| `[report]` | 보고된 동작, attack surface, exposure, 재현성 |
| `[target]` | 대상 경로와 setup·cleanup 명령 |
| `[auth]` | token, cookie, header |
| `[adapter]` | 언어, 제품 유형, service와 runtime 설정 |
| `[replay]` | 직접 명령 또는 OpenAPI·gRPC replay 정보 |
| `[variables]` | 명령과 replay에서 사용하는 값 |
| `[boundary]` | 조건 변형 수와 조합 제한 |
| `[[steps]]` | 실행 명령, timeout, 예상 종료 코드와 수집 경로 |

짧은 예시는 다음과 같다.

```toml
[report]
id = "parser-001"
title = "Parser crash"
category = "memory-corruption"
claim = "Malformed input crashes the parser"
attack_surface = "file-parser"

[target]
name = "local-target"
root = "/path/to/target"
adapter = "file-parser"

[boundary]
enabled = false

[[steps]]
name = "replay"
command = "./parser {POC_FILE}"
cwd = "."
timeout_seconds = 30
expected_exit_codes = [0]
collect_paths = []
```

Case에는 shell command가 들어 있으므로 코드와 같은 수준으로 검토해야 한다. 실행기는 현재 `shell=True`를 사용한다.

## Ranked report intake

Markdown 보고서를 case 초안으로 정리한다.

```bash
security-qa-harness intake examples/ranked-report.md \
  --output-root /tmp/security-qa-intake \
  --tiers S,A,B \
  --top-n 5
```

대상 저장소를 살펴보고 finding별 명령 초안을 만들 수도 있다.

```bash
security-qa-harness triage-oss examples/ranked-report.md \
  --repo /path/to/authorized-repository \
  --output-root /tmp/security-qa-oss \
  --top-n 3
```

기본 동작은 **초안 생성만** 한다. 실행하려면 생성된 TOML을 먼저 검토한 뒤 `--execute`를 붙인다.

```bash
security-qa-harness triage-oss examples/ranked-report.md \
  --repo /path/to/authorized-repository \
  --output-root /tmp/security-qa-oss \
  --top-n 3 \
  --execute
```

자동 초안에는 다음 제한이 적용된다.

- 생성한 input은 `harness-generated-input-not-observed-evidence`로 표시한다.
- 생성한 input은 자동으로 target artifact에 포함하지 않는다.
- `runs/`, `oss-runs/`, `build/`, `.venv/`, `node_modules/` 같은 생성·dependency 경로는 source match에서 제외한다.
- test runner 누락, 명령 미존재, test 미수집은 `operational-failure`로 기록한다.
- base command가 operational failure이면 variant를 실행하지 않는다.
- `run`과 `triage-oss --execute`는 operational failure가 있으면 exit code `3`을 반환한다.
- 원래 claim 문장은 관찰 증거 검색에 포함하지 않는다.

자동 선택 명령은 finding 전용 reproducer가 아닐 수 있다. 이 경로에서 나온 claim assessment는 검토 편의를 위한 분류이며 최종 판정이 아니다.

## 출력

```text
runs/<report-id>-<UTC-timestamp>/
├── 01-<step>/
│   ├── stdout.txt
│   └── stderr.txt
├── boundary/
├── analysis.json
├── analysis.md
└── executive_summary.md
```

`triage-oss --execute`는 `claim_assessment.json`과 `claim_assessment.md`도 만든다. 각 assessment에는 runtime evidence source와 operational failure가 별도 필드로 기록된다.

설정된 bearer token, cookie와 header value는 저장되는 명령과 text output에서 `[REDACTED]`로 치환된다. 임의의 binary artifact나 target이 직접 생성한 파일 내용은 자동으로 검사하지 않는다.

## 지원 범위

- Adapter: file parser, service, OpenAPI, gRPC, library, JNI, native, CLI
- Runtime signal: ASan, UBSan, SIGSEGV, Go panic, JVM fatal log, Python traceback, Node exception, Rust panic
- Boundary axis: environment, variable, string length, file append·replace, HTTP method·header·query, argv append

세부 내용은 [Architecture](docs/ARCHITECTURE.md), [Adapter Matrix](docs/ADAPTERS.md), [Methodology](docs/METHODOLOGY.md)에 있다.

## 검증

2026년 8월 26일 현재 확인한 범위는 다음과 같다.

- unit test: **40 / 40 passed**
- Python 3.12 compile: passed
- wheel build와 clean install: passed
- GitHub Actions Python 3.11, 3.12, 3.13

테스트는 case parsing, replay command, runtime 분류, variant, redaction, 실행 승인, operational failure와 claim 자기입증 방지를 검사한다. 취약점 탐지 정확도나 exploitability를 측정하지 않는다. 자세한 명령과 범위는 [Validation Receipt](docs/VALIDATION.md)에 기록한다.

## 알려진 제한

- 공개 예제는 실제 취약 프로그램이 아니라 synthetic fixture다.
- 실제 FoxCompany QA worker와 자동 연동돼 있지 않다.
- 일반 `run`의 declared artifact는 실행 전에 이미 존재한 파일일 수 있으므로 analyst가 provenance를 확인해야 한다.
- 자동 repository command는 dependency와 build 환경을 준비하지 않는다.
- 실행 승인 option은 container, VM, network isolation을 제공하지 않는다.
- pattern 분류는 취약점 유효성이나 exploitability 증거가 아니다.
- 기존 CVE가 이 공개 snapshot으로 검증됐다고 주장하지 않는다.

## 저장소 구성

| Path | 용도 |
| --- | --- |
| `src/security_qa_harness/` | Python package와 CLI |
| `examples/`, `fixtures/` | Case 예제와 synthetic target |
| `docs/` | 구조, 방법론, 안전한 공개 기준과 검증 기록 |
| `tests/` | 회귀 테스트 |

두 내부 prototype과 공개본의 관계는 [Project Lineage](docs/LINEAGE.md)에 정리돼 있다.

## 관련 저장소

- [FoxCompany / Agent Security Company](https://github.com/foxirain/agent-security-company): 작업자 identity와 실행 경계
- [Agent Egress Lock](https://github.com/foxirain/agent-egress-lock): 초기 network containment prototype
- [Linux Kernel Codex Harness](https://github.com/foxirain/linux-kernel-codex-harness): Linux kernel 조사 우선순위화
- [Linux Kernel Codex Harness v2](https://github.com/foxirain/linux-kernel-codex-harness-v2): provenance-aware finding triage
- [Codex OSS Vulnerability Harness v2](https://github.com/foxirain/codex-oss-vuln-harness-v2): 범용 OSS 조사 orchestration
- [Adaptive Codex OSS Vulnerability Harness](https://github.com/foxirain/codex-adaptive-oss-vuln-harness): 분리된 여러 search session 실행과 병합

## License

[Apache License 2.0](LICENSE)
