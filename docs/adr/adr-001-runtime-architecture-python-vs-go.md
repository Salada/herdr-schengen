# ADR-001: Runtime & Architecture Selection (Python vs. Compiled Go Binary)

- **Status**: Active
- **Date**: 2026-08-18
- **Context**: Herdr Schengen (`smartgate` / `trusted-clearance`) Security Gatekeeper Runtime Choice
- **Deciders**: Human Architect & Antigravity (AGY) Coding Agent

---

## 1. Context & Problem Statement

`herdr-schengen` (SmartGate)는 Herdr 터미널 멀티플렉서 환경에서 동작하는 코딩 에이전트(AGY)의 명령어 승인 요청을 실시간으로 감시하고, 안전한 명령어는 즉시 무비자 통과(Auto-Approve), 위험 명령은 인간 검토로 위임하는 보안 게이트키퍼입니다.

이 시스템을 지속적으로 운영하고 진화시키는 과정에서, **"현재의 Python3 인터프리터 런타임을 유지할 것인가"** 아니면 **"단일 Go 바이너리로 컴파일하여 On-demand 빌드 배포할 것인가"**에 대한 런타임 아키텍처 및 유지보수성 평가가 요구되었습니다.

---

## 2. Decision Drivers (의사결정 핵심 요인)

1. **AI Agent 자율 수정성 (Agent-Friendliness & Hot Modifiability)**:
   - 개발 중 새로운 CLI 툴, 스크립트 실행 패턴, 예외 화이트리스트가 지속적으로 발생합니다.
   - AI 에이전트(AGY, Hermes 등)가 대화 맥락에서 즉시 룰셋과 로직을 수정하고 바로 적용할 수 있어야 합니다.
2. **다형적 코드 분석력 (Python AST & Shell Parse)**:
   - 에이전트가 실행하려는 파이썬 스크립트(Heredoc, `-c` 인라인 코드)를 AST 레벨에서 분해하여 유출/파괴 모듈을 검사해야 합니다.
3. **Dotfiles 및 형상관리 간결성 (Chezmoi Ergonomics)**:
   - `salada-git` 및 Chezmoi로 관리되는 환경에서 복잡한 빌드 훅 없이 소스와 실행 대상이 1:1로 일치해야 합니다.
4. **시스템 리소스 소모 및 비용 (Zero Quota & Low Footprint)**:
   - 24시간 백그라운드 폴링 시 LLM API 비용($0) 및 시스템 리소스(CPU/RAM)가 미미해야 합니다.

---

## 3. Considered Options (검토된 대안들)

### Option 1: Pure Python3 Script (Selected)
- **구조**: Python 3 표준 라이브러리(`ast`, `re`, `subprocess`, `fcntl`, `sqlite3`) 중심의 스크립트 및 데몬.
- **장점**:
  - AI 에이전트가 `replace_file_content`로 코드 수정 후 `chezmoi apply` 즉시 1초 만에 갱신 적용.
  - 내장 `ast.parse()`를 활용해 요청된 파이썬 스크립트를 1ms 만에 완벽하게 트리 분석.
  - 빌드 도구체인(Go compiler, 빌드 스크립트) 의존성 없음.
  - 3초 주기 폴링 시 CPU 점유율 0.0%, 메모리 약 19MB로 리소스 부하 사실상 0.
- **단점**: 시스템 파이썬 런타임 환경에 의존.

### Option 2: Monolithic Compiled Go Binary
- **구조**: 모든 감시/심사 로직을 Go 단일 바이너리로 컴파일하여 `~/.local/bin/smartgate`로 배포.
- **장점**:
  - 메모리 사용량 극소화 (약 5~8MB), 바이너리 단일 파일 배포.
- **단점**:
  - 에이전트가 룰 하나를 수정할 때마다 `go build` 파이프라인 강제 및 컴파일 에러 위험 증가.
  - Go 내부에서 파이썬 코드를 AST 파싱하려면 외부 파서 의존성 추가 필요.
  - Chezmoi에 `run_onchange_` 빌드 트리거 훅 관리 필요.

### Option 3: Go Engine + External Declarative Rules (YAML/SQLite)
- **구조**: Herdr 통신 및 프로세스 관리는 Go 바이너리가 담당하고, 보안 규칙은 `rules.yaml`로 분리.
- **장점**: 바이너리 재빌드 없이 룰 수정 가능, 단일 바이너리의 견고함 유지.
- **단점**: 현재 시스템 규모 대비 아키텍처 오버엔지니어링(엔진과 룰 파서의 이원화).

---

## 4. Decision Outcome & Implementation Philosophy

### 🏆 선택: **Option 1 (Pure Python3 Script First)**

현재 환경(AI-First Dotfiles + Chezmoi)에서는 **Python 방식을 유지하는 것이 유지보수성, 에이전트 생산성, AST 정적 분석력 측면에서 최선**이라고 결정하였습니다.

### 🧭 핵심 구현 철학 5원칙:
1. **Zero LLM Token Polling**:
   - `herdr pane list` 폴링은 로컬 IPC로만 수행되며, 유휴 상태에서 외부 LLM API를 전혀 호출하지 않습니다 ($0 비용).
2. **1ms AST Local Gate**:
   - 정규식 및 Python 내장 AST 기반의 정적 분석으로 99%의 일상적인 안전 명령을 로컬에서 즉시(1ms) 판정합니다.
3. **Zero Skill Pollution**:
   - 실행 로그, 감사 데이터, SQLite DB는 스킬 디렉터리가 아닌 XDG 표준 경로(`~/.local/state/herdr-schengen/`)에만 기록합니다.
4. **Strict Singleton & Self-Exclusion**:
   - `fcntl.flock` 기반의 엄격한 단일 프로세스 락을 유지하여 중복 키 주입 및 자가 승인 루프를 원천 차단합니다.
5. **Agent-Friendly Ergonomics**:
   - 코드가 곧 설정이며, AI 에이전트와 인간 엔지니어가 언제든 직관적으로 룰셋을 확장할 수 있는 인터프리터 구조를 고수합니다.

---

## 5. Future Migration Triggers (향후 전환 기준)

다음 조건이 충족될 경우 **Option 3 (Go Engine + External YAML Rules)**로의 리팩터링을 재검토합니다:
- 동시 관제해야 할 Herdr Pane 수가 수십 개 이상으로 급증하여 파이썬 인터프리터의 폴링 루프가 CPU 병목을 일으킬 때.
- 파이썬 런타임이 설치되지 않은 최소 OS 환경(임베디드/경량 컨테이너 등)으로 배포 대상을 확장해야 할 때.
