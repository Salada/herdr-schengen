# Herdr-Schengen Phase 4: Active Execution Roadmap & Backlog

> 본 문서는 Phase 3(Sprint 1/2/3 완결, PR #161~PR #182)에 이어, 활성 실행 대상인 잔여 과제 및 Sprint 4 중심의 동시성/인터랙션 고도화 로드맵을 관리하는 공식 백로그입니다.

## Handoff — Phase 4 Priority Roadmap & Thematic Tracks

Phase 3에서 긴급 버그(Sprint 1), 관측성/인터랙션(Sprint 2), 코드베이스 위생 및 거버넌스(Sprint 3)가 모두 수렴되었습니다.
Phase 4는 **"멀티에이전트 고속 동시성(Concurrency)과 무마찰 사용자 경험(Frictionless UX)"**을 핵심 테마로 하여 아래 4대 트랙으로 편성·추진합니다.

---

### 🎯 Phase 4 확정 4대 실행 트랙 (Priority Tracks)

```
[Track 1: Quick-Wins & Precision Engine] ────► [Track 2: Sprint 4 Parallel Concurrency]
  • #3670 Read-Only Chain Fast-Track             • M1: DB WAL & In-Flight Lock
  • #4027 Heredoc & Semantic Complexity          • M2: ThreadPool Worker & Silent Clearance
  • #3143/#3219 Prefix/Path Match                • M3: Single-Slot DeferredHumanQueue
  • TTL & SettingsModal UI Toggles               • M4: Pre-Display Liveness Purge
                                                          │
                                                          ▼
[Track 4: Deep Research & Hardening] ◄─────── [Track 3: Observability & Interaction]
  • LLM Base URL Auto-Recovery & Circuit Break    • Universal Deep-Link ([#ID], [▼ Details])
  • Irreversible Command Ruleset (make/kubectl)  • 4-Tier Queue Status Badges
  • Context Compact & Test Layout Refactor       • Fullscreen Audit Exchange Integration
```

1. ⚡ **[Track 1 — Quick-Wins & Precision Engine (최우선 착수)]**:
   - 1) **#3670 Read-Only 체인 진단 명령 Fast-Track 확장** (`INV-5/6` Narrow Carve-out, 일상 피로도 즉시 해소)
   - 2) **#4027 Heredoc 본문 마스킹 & 시맨틱 복잡도(Multi-Factor) 완화** (커밋 메시지 과도한 복잡도 패널티 제거)
   - 3) **#3143 / #3219 OpenCode Prefix & 상하위 디렉터리 경로 매칭** (화면 절단으로 인한 키 주입 실패 방어, `ctrl+f`는 신중 모드)
   - 4) **TUI SettingsModal UI 토글 연동** (`approve_advisory`, `Approval Bias`, `Fast-Track Mode`) & `get_complexity_tax_config` TTL 캐시 무효화.

2. ⚙️ **[Track 2 — Sprint 4 대형 동시성 엔진 (EPIC Concurrency)]**:
   - **Parallel Silent Inspection & Single-Slot Deferred UI (M1 ~ M4)**:
     • M1 (DB & Lock): SQLite WAL 모드 + Thread-safe 커넥션 풀 + `_in_flight_panes` Mutex Lock.
     • M2 (Watcher Worker): `ThreadPoolExecutor(max_workers=10)` 기반 백그라운드 무음 검사 & 자율 승인 주입 (`INV-CONC-1/2`).
     • M3 (TUI Scheduler): `DeferredHumanQueue` FIFO 스케줄러 & 단일 슬롯(`INV-CONC-3`) 순차 디스플레이.
     • M4 (Stale Purge): 화면 승격 직전 Pre-Display Liveness 검증 및 Stale 자동 소멸 (`INV-CONC-4`).

3. 🎨 **[Track 3 — 관측성 & 감사 인터랙션 고도화 (Observability & UX)]**:
   - 1) **TUI Universal Deep-Link** (`[#ID]`, `[Audit #ID]`, `[▼ Details]` 원클릭 팝업/인라인 전개).
   - 2) **Pending Queue 4단계 상태 배지** (`🔍 Gatekeeper Checking`, `🚨 Action Required`, `⏳ Deferred (Slot #N)`, `⚡ Approved`).
   - 3) **AuditFullscreenModal 교환 뷰(`get_adjudication_exchange`) 전면 연동** 및 `scope_context`(Session vs Global) 메타데이터 감사 레저 반영.
   - 4) **동적 URL / WebSearch (curl, wget) 듀얼 정책(Allowlist & Denylist) 관리** (SQLite `url_policy_rules` + Tool Call + TUI 탭/정렬 뷰).
   - 5) **유저 구성 기반 Fast-Track 확장(`chezmoi status` 등) 및 TUI 자연어 해석 Tool-Call 추가 엔진** (`~/.config/herdr-schengen/fast_track_rules.json` + `add_command_allowlist_rule` 툴).
   - 6) OpenCode 보조 지침 비동기 딜레이 큐 & 플러그인 IPC 확장 (#3615/#3623 후속).

4. 🔬 **[Track 4 — 딥 리서치 & 장기 안정성 (Research & Hardening)]**:
   - 1) **[EPIC/Priority: Mid-High] Gatekeeper/Judge 프롬프트 외부 파일화 및 `*_PROMPT_OVERRIDE.md` 기반 프롬프트 증강/자가개선 체계** (하드코딩 분리, 3계층 오버라이드, gpt-5.6-sol med+ 권장).
   - 2) **LLM Base URL 엔드포인트 서버 장애 감지·서킷 브레이커 & 자동 복구(Auto-Restart)** 메커니즘.
   - 3) **비가역적 상태 변경 명령 리서치** (`make`, `kubectl`, `magick` 에셋 생성 등 Fast-Track/Sandbox 정책).
   - 4) **Codex 지원 잔여 과제** (network/edit 템플릿 live 검증, reject 경로, Ctrl+A fullscreen).
   - 5) **Context Compact 및 Python 관례 기반 테스트 코드 디렉터리 재배치**.

---

## 🎯 Active Execution Backlog (상세 항목)

### 🚨 [P0 Urgent / Bug] Disagree-and-Commit 규약 도입 후 과잉 Reject 및 Gatekeeper 권능 월권 회귀 수정 (PR #179 / #3864 후속)
[] [Bug/Gatekeeper] Gatekeeper의 독자적 Reject 남발 및 인간 승인 의사 묵살 결함 긴급 해소:
  - 현상 및 부작용 보고 (사용자 인시던트):
    1) Gatekeeper가 인간에게 판단을 위임/요청하지 않고 자체적으로 `reject`를 섣불리 결정하여 에이전트에 에러/거절 메시지를 넘김 (인간 판단 요청 단계 생략 빈번).
    2) 인간이 `/approve` 슬래시 커맨드가 아닌 채팅 메시지로 강력한 승인 의견을 제시했음에도 Gatekeeper가 이를 무시하고 자체 판정으로 `reject`를 강행함.
  - **사용자 핵심 거버넌스 원칙 (Invariants)**:
    • **원칙 1: 최종 결정권과 법적/보안 책임은 항상 인간 지휘관에게 귀속됨.**
    • **원칙 2: Gatekeeper는 승인/거절을 독자적으로 '결정(Decide)'하지 말고, 자신의 전문적 소신 의견(Advisory Opinion)만 브리핑·주장해야 함.**
    • **원칙 3: Gatekeeper 자체 Reject은 오직 "의심의 여지 없이 명백한 위험(Unambiguous Denylist/Critical Risk)"에 한해서만 극히 제한적으로 허용되어야 하며, 일반적 Gray-zone/복잡도 초과 건에서 인간을 건너뛰고 자의적으로 거절하는 행위는 절대 금지됨.**
  - 해결 방향 및 아키텍처 재설계 (Redesign Directions):
    1) `scripts/tools/schengen_agent_llm.py` 프롬프트 및 의사결정 머신 개편:
       - Gatekeeper의 도구 호출(`reject_escalation`) 권한을 엄격히 축소하고, 인간 개입 필요 시 오직 **"판단 유보 및 사전 위험 브리핑(Advisory Assessment Card)"**만 생성하도록 강제.
       - 인간의 자유 텍스트 메시지가 승인 뉘앙스일 경우, AI가 이에 반하여 단독 거절하는 동작을 원천 차단하고 인간의 지시를 존중(Direct Directive)하도록 시스템 프롬프트 수정.
    2) `approve_advisory` 기본 동작 정밀화: 조언 모드에서도 AI는 거절을 '집행'하는 주체가 아니라 '위험을 경고하는 참모' 역할에 머물도록 결재 상태 머신 재정렬.

---

### [Track 1] Quick-Wins & Precision Engine

[] [Bug/Guard] 따옴표/이스케이프된 셸 제어문자 과도 에스컬레이션 완화:
  - `security_evaluator.py`의 구조 뷰가 인용된 `|`, `;`, `&`, `<`, `>`를 인자 데이터로 마스킹하되, 원문 오프셋을 유지한다. 비인용 제어문자, 동적 치환, 민감 경로, 변이 명령은 기존 fail-closed 규칙을 유지한다.
  - [ ] **AGY (Coder tab):** PR을 검토하고 전체 단위 테스트가 통과하면 Forgejo `main`에 merge한다.
  - [ ] **OpenCode:** merge 뒤 깨끗한 worktree에서 `git pull --ff-only origin main` 후 `HERDR_ENV=1 ~/.local/share/herdr-schengen-tui-venv/bin/python3 -m unittest discover -s tests`를 실행하고, quoted-control 회귀 사례와 `rm -rf`/`.env` 차단 사례를 확인한다.

[] [Refactor/TestRunner] 안전한 read-only 체인 진단 명령 Fast-Track 확장 (사례: #3670 후속 백로그):
  - 현상 및 요구사항:
    • 에이전트들의 일상적인 검증/진단용 안전 체인 명령(`cd <worktree> && python3 -m unittest discover -s tests 2>&1 | tail -30`, `git status --short && echo "..." && git diff --stat`)이 `NOT_ALLOWLISTED`로 인간 승인을 매번 요구하여 피로도 유발.
    • `cd <safe_dir> && <safe_runner>` 결합 체인 및 `| tail -N` / `| head -N` 안전 파이프라인의 Fast-Track / Test-Runner 인정 규칙 정밀화.
  - **[INV-5/6 긴장 명시 및 Narrow Carve-out 요건]**:
    • 주의: INV-5/6 불변식은 Fast-Track에서 셸 메타문자(`|`, `&`, `;`, `&&`, `||`)를 원칙적으로 거부함. #2555(item 3)에서 `pytest 2>&1 && rm -rf /` 우회 갭을 fail-closed로 엄격 차단한 보안 원칙과 정면 충돌하지 않아야 함.
    • 따라서 단순 메타문자 허용이 아닌, **"모든 세그먼트가 엄격히 검증된 read-only 체인인 경우에만 한정 허용 + sensitive path 및 변이(mutating) 세그먼트 즉시 재거부"**하는 좁은 예외(Narrow Carve-out) 모델만 적용.

    • 구현 힌트: `security_evaluator.py:1118` `_is_read_only_pipeline` 확장 검토 (read-only 세그먼트만 파싱·검증, `&& rm -rf` 등 변이 세그먼트 탐지 시 fail-closed 에스컬레이션).

[] [Idea/Complexity] Heredoc 페이로드 분리 및 시맨틱 복잡도(Semantic Risk & Multi-Factor Complexity) 산정 체계 재설계 (사례: #3864, #4027):
  - Context & Core Problem (사례: #3864 복합 파이프라인, #4027 Heredoc 커밋 메시지):
    • 현재 `compute_complexity`는 연산자 수(`&&`, `|`, `;`), 서브쉘, 리다이렉션(`2>&1`) 뿐만 아니라 **개행 문자(`\n`, `\r`)를 세그먼트 분리자(`_COMPLEXITY_CONTROL_RE = re.compile(r"[|&;\n\r]+")`)로 취급**.
    • 이로 인해 **Heredoc 본문(`cat <<'EOF' ... EOF`) 내부의 단순 줄바꿈/텍스트 내용이 각각 독립 명령 세그먼트로 오인식**되어 복잡도 점수가 폭발적으로 과계산됨 (`#4027`: 단순 16줄 커밋 메시지 작성 + git commit/push 체인인데 `complexity=26 > 6`으로 과도하게 치솟음).
    • 실제로는 순수한 데이터 페이로드(Data Payload)인 텍스트가 제어 흐름(Control Flow) 복잡도로 둔갑하여 인간 승인 피로도를 가중시킴.
  - Heredoc 및 복잡도 완화 기획 (Heredoc Isolation & Semantic Scoring Model):
    1. **Heredoc 본문(Body) 복잡도 산정 제외 / 마스킹 (Heredoc Payload Stripping)**:
       - `compute_complexity` 계산 전, `<<'EOF' ... EOF` 또는 `<<EOF ... EOF` 구간을 단일 데이터 리다이렉션(`1 redir point`)으로만 계상하고 **내부 개행 및 문자열은 제어 흐름 분리 대상에서 완전 마스킹/제외**.
       - 주의: 따옴표 없는 Heredoc(`<<EOF`) 내의 `$()` 커맨드 치환은 보안상 실행될 수 있으므로, 내부 치환(`$()`, ``` ` ```)만 선별적으로 스캔하되 단순 개행/텍스트는 세그먼트 가산에서 배제.
    2. **세그먼트별 시맨틱 변이 가중치 (Segment Mutation Weighting)**:
       - 단순 연결자(`&&`, `|`) 횟수 1:1 선형 가산 대신, 체인을 이루는 각 세그먼트의 본질적 행위(Verb / Action)에 따른 차등 가중치:
         • Read-Only / Diagnostic (`git status/log/diff`, `cd`, `echo`, `shasum`, `tail`): 가중치 0 ~ 0.5 (복잡도 기여 극소화).
         • Non-destructive VCS Sync (`git checkout`, `git pull --ff-only`, `git commit`): 가중치 1.0.
         • Mutating / Destructive (`rm`, `rsync`, `worktree remove`, `kill`, `chmod`): 가중치 3.0 ~ 5.0 (위험 변이 집중 부과).
    3. **컨텍스트 독립성 및 파이프라인 안전성 (Pipeline Safety Context)**:
       - 출력 제어용 꼬리 파이프(`| tail -N`, `| head -N`, `| grep pattern`, `2>&1`)는 복잡도 가산 면제 또는 감면.
       - 반복문(`for ...; do ...; done`) 및 임의 문자열 치환(`eval`, `xargs`) 등 비결정적 흐름 제어 구문에만 고위험 복잡도 부여.
    4. **복잡도 임계치 다단계화 (Tiered Complexity & Routing)**:
       - 단순 `score > threshold` -> 즉시 Human Escalation 대신:
         • Low-risk Read Chain (누적 점수 높아도 변이 세그먼트 0건): Cloud Judge 또는 Fast-Track 경로로 흡수.
         • High-risk Compound Chain (변이 세그먼트 포함 + 높은 구문 결합도): 인간 에스컬레이션 및 사전 브리핑 강화.
  - Action Items:
    • `scripts/core/security_evaluator.py` 내 `compute_complexity`에 Heredoc 본문 마스킹 정규식/파서 도입 및 단위테스트(`tests/test_complexity_tax.py`) 추가.

[] [Bug/OpenCode] OpenCode 승인 시 `_norm_req_cmd` 불일치(뷰포트 절단 및 access_directory 경로 차이)로 인한 키 주입 실패 & DB 상태 불일치 (사례: #3143, #3219):
  - 현상 및 원인 (사례: Escalation #3143 Git 커밋 & Escalation #3219 `access_directory`):
    • Gatekeeper LLM이 승인(`APPROVE`)하여 DB 상에는 `status='RESOLVED', resolution='APPROVED', approver='gatekeeper'`로 기록되었으나, 실제 OpenCode 터미널은 `Permission required` 모달 상태로 계속 멈춰 있어 승인이 해소되지 않는 현상 반복 발생.
    • 근본 원인 (2가지 불일치 유형):
      1) **사례 #3143 (장문 커밋 절단)**: 원문 `req_cmd`는 다줄 Heredoc 전체(~800자)이나, 터미널 뷰포트에서는 화면 크기 한계로 커밋 본문 중간이 잘린 채 렌더링되어 `live_req`가 절단된 문자열로 추출됨.
      2) **사례 #3219 (구조화 이벤트 vs 시각 다이얼로그 경로 표현 차이)**: 구조화 채널 `req_cmd`는 파일 절대경로(`/path/to/scripts/cmd/schengen_tui.py`)인 반면, 터미널 화면상 `live_req`는 상위 디렉터리(`~/code/.../scripts/cmd` 또는 glob `.../scripts/cmd/*`)로 렌더링되어 문자열 불일치 발생.
      3) **결과**: `_norm_req_cmd` 비교 실패로 `inject_approval`이 `(False, INJECT_SKIP_CHANGED)`를 반환하고 실제 `enter` 키를 전송하지 못함. 그럼에도 상위 승인 로직은 DB를 `RESOLVED`로 전이시켜 심각한 상태 불일치 초래.
  - 해결 방안:
    1) Prefix 및 상위/하위 경로 포괄 매칭: `live_req`가 `req_cmd`의 Prefix이거나, `access_directory`의 경우 파일 경로의 상위 디렉터리와 매칭 시 동일 요청으로 인정.
    2) `ctrl+f` 풀스크린 전개 연동 (PR #152 `expand_dialog` 활용): 절단 의심 시 `ctrl+f`로 전개 후 재비교 (사용자 지침: 키 전개는 천천히 신중히).
  - **[Caveat & Warning — AGY `ctrl+g` / 전개 시 다이얼로그 소멸 및 오승인 위험 & 포커스 추론]**:
    • AGY 등에서 장문 스크립트를 확인하기 위해 `ctrl+g`(또는 전개 키)를 입력하여 뷰포트를 전환할 경우, **기존 프롬프트의 승인 확인 모달(Confirmation Dialog)이 화면에서 일시적으로 사라지는 현상 발생**.
    • 이 때 Watcher나 Eviction 로직(`dialog_is_live == False`)이 이를 "사용자가 직접 승인/완료하여 다이얼로그가 해소됨(`pane-direct`)"으로 오판(False Positive)하여 승인 처리하거나, 반대로 주입할 다이얼로그를 찾지 못해 상태 불일치가 일어날 수 있음.
    • **유저 포커스(Focus)와 상호작용 추론의 필요성**:
      - 유저가 해당 Pane에 포커스하고 있는 상태라면, 반대로 유저가 직접 내용을 보기 위해 `ctrl+g`를 눌렀거나 터미널을 조작 중일 가능성이 높으므로 단순 상태 전이만으로 결론내리지 않는 정밀 추론 필요.
      - **권장 어프로치**: `ctrl+g`를 통한 덤프/전개는 **"해당 Pane에 유저 포커스가 없거나(Unfocused), 사용자 키 입력이 전혀 감지되지 않는 유휴(Idle) 상태일 때만"** 열고 닫도록 제어하는 것이 안전함.
      - **타 에이전트 일반화 (Universal Extension)**: AGY의 `ctrl+g`뿐만 아니라 OpenCode(`ctrl+f`), Codex(`ctrl+a` fullscreen) 등 단축키만 다를 뿐 전개/확대 시 다이얼로그 레이아웃이 변형되는 모든 에이전트 어댑터에 공통 적용되는 일반화 아키텍처 과제임.
    • 따라서 전개 덤프 중에는 일시적 다이얼로그 부재를 즉시 승인/소멸로 간주하지 않도록 가드 락(Liveness Eviction Hold)을 반드시 연계해야 함.

[] [Deferred/TUI] `SettingsModal` 내 잔여 설정 토글 연동 (Approval Bias, Fast-Track, approve_advisory):
  - 1) `SettingsModal` (Automation 섹션) 내 `approve_advisory` On/Off 토글 스위치 연동 (PR #180 후속).
  - 2) `guard_config` 테이블 내 bias/fast-track 전용 키 선행 정의 후 `SettingsModal` 라디오/스위치 연동.

[] [Deferred/ConfigCache] `get_complexity_tax_config()` 프로세스-로컬 캐시 무효화 및 런타임 동기화 (#171 후속 피어리뷰 제안):
  - Context: PR #171에서 적용된 read-once 메모리 캐시는 프로세스 단위로 동작하여, TUI에서 임계치(Threshold)를 변경하더라도 Watcher 데몬 프로세스가 SIGHUP 리로드 전까지 변경사항을 즉시 인지하지 못함.
  - Solution: 짧은 TTL (예: 5~10s) 도입, SIGHUP/인메모리 invalidate 연동 또는 동기화 문서화. (Non-blocking Deferred)

---

### [Track 2] Sprint 4 대형 동시성 엔진 (Parallel Concurrency)

[] [EPIC/Architecture] Gatekeeper 백그라운드 병렬 평가(Parallel Silent Inspection) & 지연 큐 기반 단일 순차 디스플레이(Single-Slot Deferred UI) 체계 구축
  - Context & Core Problem:
    - 현재 다중 에이전트(AGY, OpenCode, Codex 등)가 동시 작업할 때, Watcher 메인 루프가 순차 직렬로 처리되어 다른 Pane의 자율 검사까지 병목 지연이 발생함.
    - 또한 인간 개입이 불필요한 자율 승인 대상까지 중간 상태가 TUI에 노출되어 작업 흐름을 방해함.
  - Core Architecture & Feasibility Dimensions:
    1. [Silent Background Parallel Inspection (무음 병렬 자율 검사)]:
       - 인간의 명시적 인터랙션이 필요 없는 상태(Gatekeeper/Judge/AST가 자체 판정 가능한 단계)에서는 최대 10개까지 병렬(`ThreadPoolExecutor(max_workers=10)` / 비동기 워커 풀)로 동시 평가 수행.
       - 자율 검증 통과(`is_safe=True`, `AUTO_APPROVED`) 시, 인간 UI(채팅창, 사운드, 배너)에 일체 인터럽트 없이 즉시 승인 주입 및 감사 기록 완료.
    2. [Deferred Display Queuing Engine (지연 버퍼링 & 단일 순차 디스플레이)]:
       - 오직 Gatekeeper가 "자체 판정 불가 / 인간 검토 필수(Fail-Closed / Gray-zone / Denylist)"로 최종 결론 내린 건에 한해서만 인간 대기열(`DeferredHumanQueue`)로 이관.
       - TUI 화면에는 동시에 여러 알림이 난립하지 않고 **오직 1개의 활성 에스컬레이션(Active Slot)만 순차적(FIFO)**으로 노출.
       - 활성 슬롯의 건이 승인/거절되면, 지연 큐에서 대기 중이던 다음 건이 TUI 화면에 순차적으로 디스플레이됨.
    3. [Stale Eviction & Race Condition 방어 (지연 큐 무음 정리)]:
       - 지연 큐에서 대기 중인 항목이 TUI 화면에 노출되기 전에, 사용자가 대상 Pane에서 직접 처리(y/n)했거나 에이전트 상태가 해제된 경우 화면에 노출하지 않고 큐에서 즉시 무음 제거(Silent Pruning).
    4. [Invariants & Guardrails]:
       - INV-CONC-1 (Per-Pane In-Flight Mutex): 동일 Pane에 대한 중복 평가/주입 경합 방지.
       - INV-CONC-2 (Silent Autonomous Clearance): 자율 승인 완료 건은 UI 방해 제로(0% interruption).
       - INV-CONC-3 (Single-Slot Screen UI): 화면 프롬프트는 항상 1개 슬롯 유지, 초과분은 내부 지연 큐 버퍼링.
       - INV-CONC-4 (Pre-Display Liveness Check): 지연 큐에서 화면으로 승격되는 순간 `dialog_is_live` 재검증 후 유효한 건만 렌더링.
    5. [4단계 구현 마일스톤 로드맵 (Feasibility Plan)]:
       - M1 (DB & Lock): SQLite WAL 모드 + Thread-safe 커넥션 풀 + `_in_flight_panes` Lock.
       - M2 (Watcher Worker): `ThreadPoolExecutor` 기반 백그라운드 Silent Inspection & Auto-Approval.
       - M3 (TUI Scheduler): `DeferredHumanQueue` FIFO 스케줄러 & 단일 슬롯 상태 전이.
       - M4 (Stale Purge): 화면 노출 직전 Pre-Display Liveness 검증 및 Stale 자동 소멸.

---

### [Track 3] 관측성 & 감사 인터랙션 고도화 (Observability & UX)

[] [Task/UX] TUI 채팅 Universal Deep-Link (Audit/에스컬레이션 즉시 점프) & Pending Queue 다단계 상태 뱃지 (최소 정보량 시각화)
  - Context & UX Motivation:
    - 채팅창에 에스컬레이션이나 감사 로그가 언급될 때 원문이나 승인 사유를 보기 위해 감사 테이블로 일일이 이동해야 하는 번거로움 해소.
    - 또한 백그라운드 병렬 평가/지연 큐 환경에서 지연된 에스컬레이션이 '왜 대기 중인지/왜 승인되었는지'를 최소한의 정보량으로 한눈에 파악할 수 있는 시각적 큐 상태 체계 필요.
  - Key Architecture & UX Requirements:
    1. [Universal Deep-Link & Inline Expand (원클릭 디테일 점프)]:
       - TUI 채팅 메시지 내 `[#2868]`, `[Audit #7771]`, `[▼ Details]` 형태의 대괄호 링크 렌더링.
       - 마우스 클릭 또는 키보드 포커스(`Enter`) 시 해당 레코드의 `AuditDetailModal`을 즉시 팝업하거나, 장문 스크립트/Diff를 인라인으로 전개(Expand).
    2. [Pending Queue Status Taxonomy (지연/진행 4단계 상태 배지)]:
       - 대기 큐 및 사이드바 목록에 진행 상태를 명확하고 정돈된 배지로 표기:
         • `🔍 [Gatekeeper Checking]` : AI 백그라운드 툴콜/Cloud Judge 자율 조사 진행 중
         • `🚨 [Human Action Required]` : 자율 통과 불가, 지휘관의 `/approve` 대기 중
         • `⏳ [Deferred (Slot #N)]` : 단일 슬롯 정책에 의해 백그라운드 큐에서 대기 중
         • `⚡ [Approved (Gatekeeper)]` / `👤 [Approved (Human)]` / `⌨️ [Approved (Pane-Direct)]`
    3. [사후 판단 근거 추적성 (Post-Adjudication Traceability)]:
       - 처리 완료된 건도 큐/채팅에서 링크 클릭 한 번으로 왜 승인이 내려졌는지(결정 레이어, Gatekeeper 판단 사유, AST 검증 결과) 즉시 열람 가능.

[] [Deferred/Provenance] `get_adjudication_exchange` / `has_human_opinion` 프로덕션 모달 전면 연동 (PR #177 후속):
  - Context: PR #177에서 정의·테스트된 신규 exchange 조회 헬퍼가 현재 프로덕션 모달의 `get_adjudications_for_audit`와 부분 분리되어 있음.
  - Solution: future-facing 주석 처리 또는 프로덕션 감사 모달 전체를 exchange 뷰로 일원화 전환 검토. (Non-blocking Deferred)

[] [Idea/Audit] System Auto-Approval의 스코프 맥락(Session-Specific vs Global/Stateless) 감사 메타데이터 명시화
  - Context & Objective:
    - 시스템에 의해 자동 승인(`AUTO_APPROVED`)될 때, 해당 승인이 '세션 한정 일시적 기억/이력(Session-Specific / TTL Memory)'에 의한 것인지, '전역 불변 룰(Global Invariant / Fast-Track AST / User Allowlist)'에 의한 것인지 구분하기 어려워 사후 감사(Audit) 시 판단 근거 추적이 모호함.
  - Design & Scope Taxonomy:
    1. `scope_context` (또는 `approval_scope`) 메타데이터 분류:
       - `GLOBAL_RULE` (또는 `global`): 세션과 무관하게 언제나 안전한 AST Fast-Track 닫힌 집합(ls, pwd, git status 등) 또는 영속 user_allowlist에 의한 승인.
       - `SESSION_TRANSIENT` (또는 `session`): 해당 세션/Pane에서 인간의 선행 승인 이력, 세션 메모리 캐시(1h TTL), 또는 작업 스코프 내 학습된 안전 패턴에 의한 승인.
       - `REPO_LOCAL` (또는 `repo`): 특정 워크스페이스/저장소 내부로 스코프가 제한된 로컬 정책 기반 승인.
    2. DB Schema & TUI Audit Ledger 반영:
       - `audit_logs` 테이블에 `scope_context` 컬럼 추가 (또는 `mechanism` 컬럼 값 표준화: `fast-track:global`, `session-memory:pane_id`, `allowlist:repo`).
       - TUI Audit Table 및 Detail Modal에 스코프 태그/배지 노출 (예: `[🤖 AUTO: Session]` vs `[🤖 AUTO: Global]`).

[] [Feature/Security] 동적 URL / WebSearch (curl, wget, webfetch) 듀얼 정책(Allowlist & Denylist) 관리 및 TUI 테이블 연동:
  - Context & Objective:
    • 에이전트의 외부 웹 탐색(`webfetch`, `websearch`) 및 네트워크 명령어(`curl`, `wget`)에 대해, 안전 허용(Allow)뿐만 아니라 명백한 악성/유출 위험 도메인 차단(Deny)을 명확하게 통제할 수 있는 동적 URL 정책 체계 필요.
    • 정적 코드 수정 없이 TUI 및 도구 호출(Tool Call)을 통해 실시간으로 신뢰 도메인(Allow) 및 유출/위험 도메인(Deny) 패턴을 추가/삭제/조회/토글할 수 있어야 함.
  - Architecture & SQLite Schema Design:
    1. **통합 정책 테이블 구축 (`url_policy_rules`)**:
       - `id INTEGER PRIMARY KEY AUTOINCREMENT`
       - `pattern TEXT NOT NULL` (도메인, URL 접두사, 정규식 또는 glob: 예 `api.github.com`, `*.pastebin.com`, `http://malicious.net/*`)
       - `rule_type TEXT NOT NULL CHECK(rule_type IN ('ALLOW', 'DENY'))` (허용/차단 명시)
       - `category TEXT DEFAULT 'general'` (`docs`, `api`, `search`, `exfil`, `malware`, `suspicious`)
       - `reason TEXT` (등록 사유 및 메모)
       - `created_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP`
       - `created_by TEXT DEFAULT 'human'` (`human`, `gatekeeper_tool`)
       - `UNIQUE(pattern, rule_type)`
    2. **판정 우선순위 규약 (Deny-First Security Invariant)**:
       - 1) **Denylist 일치 시**: `Tier A (UNAMBIGUOUS CRITICAL / EXFIL_GUARD)`로 즉시 자율 거절(`reject_escalation`).
       - 2) **Allowlist 일치 시**: `Tier B / Fast-Track (SAFE_NETWORK)`로 즉시 자율 승인(`approve_escalation`).
       - 3) **둘 다 미해당 시**: `Tier C (Gray-Zone)`로 분류하여 맥락 조사 후 통상 처리.
    3. **Gatekeeper Tool-Calling 인터페이스 확장**:
       - `query_url_policy(url)`: 대상 URL의 Allow/Deny 여부 및 등록 사유 조회.
       - `add_url_rule(pattern, rule_type, reason)` / `remove_url_rule(pattern, rule_type)`: 게이트키퍼가 신뢰 문서 등록 또는 차단 사이트 동적 블랙리스팅.
    4. **TUI 정책 매니저 뷰 (`UrlPolicyModal` / `SettingsModal` 연계)**:
       - **대소문자 무시 알파벳순(Case-Insensitive Alphabetical Sorting)** 정렬 및 표시.
       - 상단 필터 탭: `[All]`, `[🟢 Allowlist]`, `[🔴 Denylist]`.
       - TUI 단축키/버튼: `Add Rule` (Allow/Deny 선택), `Delete Rule`, `Toggle Type` (Allow ↔ Deny 빠른 전환).
    5. **보안 평가기 연동 (`security_evaluator.py`)**:
       - `evaluate_network_calls` 및 `webfetch` 단계에서 `url_policy_rules`를 선행 조회하여 Deny 우선 차단 및 Allow 고속 패스트트랙 집행.

[] [Feature/Policy] 유저 구성 기반 Fast-Track 확장(`chezmoi status` 등), 에이전트별 Pattern Auto-Allow 룰 및 TUI 자연어 해석 Tool-Call 추가 엔진:
  - Context & Motivation:
    • 사례 1: `chezmoi status`, `chezmoi diff` 등 개인화된 도트파일 도구는 읽기/진단 성격이 명확하나 고정된 내장 allowlist에 없어 매번 불필요한 인간 승인을 유발함.
    • 사례 2: `rsync skill mirror` 등 개발 환경에서 검증된 정형화 동기화 체인.
    • Codex, Claude Code, OpenCode의 설정(`config.json`, `settings.json`, `rules`)처럼, 사용자가 `~/.config/herdr-schengen/` 내 설정 파일(`fast_track_allowlist.json` 또는 `rules.yaml`)을 통해 안전 명령어 및 패턴별 Auto-Allow 규칙을 직접 선언·보강할 수 있는 구조 필요.
    • 특히 TUI 채팅에서 인간이 "chezmoi status는 항상 통과시켜줘", "skill rsync 패턴은 앞으로 자동 승인해"와 같이 자연어로 지시했을 때, **Inspector 또는 Gatekeeper(적격 Agent)가 지시 의도를 정확히 추론하여 tool call을 통해 규칙을 동적으로 추가/갱신**할 수 있어야 함.
  - Core Architecture & Reference Design:
    1. **`~/.config/herdr-schengen/` 기반 Fast-Track & Pattern 룰 설정 파일**:
       - `~/.config/herdr-schengen/fast_track_rules.json` (또는 YAML):
         ```json
         {
           "exact_commands": ["chezmoi status", "chezmoi diff", "brew list --formula"],
           "prefix_commands": ["chezmoi status ", "chezmoi cat "],
           "pattern_rules": [
             {
               "id": "rsync-skill-mirror",
               "pattern": "rsync -a <WORKSPACE>/scripts/ <AGENTS_DIR>/skills/<NAME>/scripts/ && ...",
               "agents": ["opencode", "agy", "codex"],
               "action": "AUTO_ALLOW",
               "reason": "Skill synchronization"
             }
           ]
         }
         ```
       - 보안 평가기(`security_evaluator.py`)가 기동/리로드 시 해당 파일을 로드하여 정적 `FAST_TRACK_SAFE_COMMANDS`와 매끄럽게 결합(Zero-latency In-Memory Lookup).
    2. **인간 지시 해석 및 동적 룰 추가 Tool (`add_command_allowlist_rule`)**:
       - TUI 채팅에서 인간 지휘관의 의도(자연어)를 해석하여 적격 Agent(Inspector / Gatekeeper)가 호출하는 신규 Tool:
         • `tool: add_command_allowlist_rule(command_or_pattern, match_type='exact'|'prefix'|'regex', scope='global'|'repo', reason=str)`
         • `tool: remove_command_allowlist_rule(rule_id_or_pattern)`
         • `tool: query_command_allowlist()`
       - 동작 방식:
         - 인간이 "chezmoi status 허용해줘" 입력 ➔ Gatekeeper/Inspector가 자연어 파싱 후 `add_command_allowlist_rule(command_or_pattern="chezmoi status", match_type="exact", reason="Human requested in TUI")` 도구 호출 ➔ 파일(`fast_track_rules.json`) 및 DB(`command_allowlist`)에 즉시 영속 반영 ➔ Watcher에 SIGHUP 또는 인메모리 리로드 통지.
    3. **엄격한 안전 불변식 (Security Guardrails & Invariants)**:
       - **Denylist Immiscibility (불변 방어선)**: `rm -rf`, `sudo`, `mkfs`, `git push --force` 등 Tier A Denylist에 속하는 위험 명령은 파일에 직접 적거나 Tool Call로 추가를 시도하더라도 **로더 및 도구 레벨에서 원천 거부(Reject/Error)**.
       - **Confirmation & Provenance**: 도구를 통해 룰이 추가되었을 때 TUI 채팅창에 `[Auto-Allow Rule Added: chezmoi status (by human intent)]` 명시적 피드백 출력.
    4. **TUI 화이트리스트 매니저 뷰 (`CommandAllowlistModal`) 연동**:
       - 알파벳순(Case-Insensitive) 정렬, 등록된 커스텀 룰/패턴 목록 열람 및 삭제(Revoke) 지원.

[] [Deferred/OpenCode] OpenCode 보조 지침 전달 큐, 다이얼로그 디바운스 및 배치 Defer UX 개선 (#3615/#3623/#3636 후속):
  - 1) **지침 전달 큐 (Instruction Queue)**: Bubble Tea 모달 상태에서 `send-text` 무효화 대응을 위해 모달 닫힘 이후(실행 재개/명령 완료 시점) 지침 주입 비동기 딜레이 큐 연동.
  - 2) **플러그인 IPC 확장**: OpenCode 플러그인 레벨에서의 지침 전달 채널 확장 (`opencode_permissions` IPC 연계).
  - 3) **다이얼로그 디바운스**: 연쇄 명령 다이얼로그 연속 발생 시 뷰포트 안정화 디바운스.
  - 4) **Batch Approval Defer 가이드 & Sweeper 로그**: `/approve-batch` 실행 시 화면 전이로 인해 `deferred`된 ID에 대한 친절 안내 문구 및 백그라운드 Sweeper(`pane-direct`) 전이 로그 가시화.

---

### [Track 4] 딥 리서치 & 장기 안정성 (Research & Hardening)

[] [EPIC/Priority:Mid-High] Gatekeeper/Judge 프롬프트 외부 파일화 및 `*_PROMPT_OVERRIDE.md` 기반 역할별 프롬프트 증강/자가개선 체계 구축:
  - Model Requirement: **gpt-5.6-sol (medium 이상)** 깊은 추론 모델 기반 기획/설계 권장.
  - Priority: **중상 (Medium-High)**.
  - Context & Motivation:
    • 현재 `scripts/tools/schengen_agent_llm.py`와 `core/cloud_judge.py` 내부에 수백 줄의 Python 하드코딩 문자열로 갇혀 있는 시스템 프롬프트를 **별도의 마크다운 파일(Externalized Prompt Files)**로 추출.
    • Hermes의 자가 개선 프롬프트/메모리 체계처럼, 게이트키퍼가 실시간 심사 과정에서 발생한 과잉 거절(Over-rejection)이나 과잉 완화(Rubber-stamping) 피드백을 학습하여 편향성(Approval Bias)을 스스로 정밀 보정할 수 있는 메커니즘 제공.
    • 코드 수정/재배포 없이 사용자와 자가개선 도구가 런타임에 역할별 프롬프트를 오버라이드하고 증강(Augmentation)할 수 있는 표준 설정 계층 구조 확립.
  - Core Architecture & Reference Design:
    1. **프롬프트 외부 파일화 (Base Prompts Extraction)**:
       - 기본 프롬프트를 파이썬 코드에서 분리하여 템플릿/리소스 디렉터리에 표준 마크다운으로 관리:
         • `resources/prompts/gatekeeper_adjudication.md` (Gatekeeper Triage/Review)
         • `resources/prompts/cloud_judge_general.md` (Cloud Judge Dual-Model)
         • `resources/prompts/read_only_interpreter.md` (Read-only Analysis)
    2. **`*_PROMPT_OVERRIDE.md` 및 `MEMORY.md` 3계층 프롬프트 합성 엔진 (Override Hierarchy)**:
       - 프롬프트 로더가 빌드 시 다음 우선순위로 템플릿을 병합/증강:
         • **Layer 1 (Core Invariant Base)**: Git 저장소 내 기본 프롬프트 (Tier A 불변 룰, 도구 스키마 등 절대 타협 불가 영역).
         • **Layer 2 (User/System Global Override)**:
           - `~/.config/herdr-schengen/GATEKEEPER_PROMPT_OVERRIDE.md` (전역 게이트키퍼 오버라이드/추가 지침)
           - `~/.config/herdr-schengen/CLOUD_JUDGE_PROMPT_OVERRIDE.md` (전역 클라우드 저지 지침)
           - `~/.config/herdr-schengen/GATEKEEPER_MEMORY.md` (전역 학습/피드백 메모리)
         • **Layer 3 (Workspace Repo Override)**:
           - `<workspace>/.schengen/PROMPT_OVERRIDE.md` (해당 저장소 전용 커스텀 심사 규약)
           - `<workspace>/.schengen/MEMORY.md` (해당 저장소 전용 예외 및 도메인 지식)
       - 병합 전략: 베이스 프롬프트의 특정 섹션(예: `<!-- OVERRIDE: TRIAGE_BIAS -->`) 치환 또는 하단에 `[RUNTIME MEMORY & OVERRIDE DIRECTIVES]` 블록으로 깔끔하게 증강 주입.
    3. **자가 개선(Self-Improvement) 툴콜 및 피드백 루프**:
       - 게이트키퍼/심사 엔진이 호출할 수 있는 메타 도구 설계:
         • `update_gatekeeper_memory(topic, observation, suggested_rule)`: 인간 지휘관의 오버라이드(`/approve` or `/reject` 전환) 발생 시 원인 분석 후 오버라이드/메모리 파일 업데이트 제안.
         • `reflect_and_tune_bias(incident_id)`: 인시던트 발생 후 피드백 루프를 돌아 자신의 심사 성향(과도한 깐깐함 vs 방심)을 자가 평가하고 가이드라인 미세 조정.
       - 안전 불변식(Security Guardrails):
         • 자가 개선 도구가 Tier A Denylist(INV 불변식, `rm -rf`, `sudo` 등)를 무력화하는 오버라이드를 생성하지 못하도록 스키마 검증 및 엄격한 샌드박싱 가드 적용.
    4. **TUI 프롬프트/오버라이드 매니저 (`PromptOverrideModal` 연계)**:
       - TUI 화면에서 현재 적용 중인 각 Role의 활성 프롬프트(Base + Global Override + Repo Override)를 한눈에 열람.
       - TUI 상에서 `~/.config/herdr-schengen/*_PROMPT_OVERRIDE.md` 내용을 즉시 수정하거나 초기화(Reset to Default)할 수 있는 편집 뷰 제공.
    5. **단계별 구현 로드맵 (Milestones)**:
       - M1 (Prompt Externalization): `scripts/tools/schengen_agent_llm.py` 내 문자열을 `resources/prompts/` 마크다운으로 분리.
       - M2 (Override Loader Engine): `~/.config/herdr-schengen/*_PROMPT_OVERRIDE.md` 및 `.schengen/` 3계층 병합 로더 구현.
       - M3 (Self-Improvement Tools): `update_gatekeeper_memory` 툴 및 인간 피드백 기반 자동 프롬프트 제안 구현.
       - M4 (TUI Integration): TUI 프롬프트 검사기/오버라이드 편집 모달 연동.

[] [Research/Stability] LLM Base URL 엔드포인트 서버 상태 이상(Unhealthy/Hang) 감지 및 재시작/복구(Auto-Restart) 로직 분석 및 강화
  - Context & Objective:
    - SmartGate/Inspector가 호출하는 LLM Base URL(로컬 모델 서버, vLLM, Synology 컨테이너, 프록시 등)이 응답 불가(Hang/Timeout/5xx) 상태에 빠졌을 때의 현재 재시작/장애 복구 메커니즘을 점검.
  - Investigation Checkpoints:
    1. 현재 구현 분석:
       - `scripts/tools/schengen_agent_llm.py` 및 `security_evaluator.py`의 retry(최대 10회), TCP timeout, fallback(Fail-Closed/Human Review) 처리 로직 현황 파악.
       - 로컬/원격 LLM 데몬(컨테이너, 프로세스) 헬스체크 및 프로세스 재시작 트리거 연계 여부 조사.
    2. 향후 개선 검토:
       - Health Check 프로브(지속 실패 시 서킷 브레이커 발동).
       - 원격/로컬 컨테이너(Synology Docker / 로컬 서비스) 자동 재시작 스크립트/Webhook 연계 가능성 검토.
       - LLM 서버 다운 시 무한 대기 방지 및 안전한 Fail-Closed 에스컬레이션 보장.

[] codex 지원 잔여: network/edit 등 템플릿 live 검증, reject 경로, Ctrl+A fullscreen long-command 경로.

[] 비가역적 상태의 위험성이 있는 command에 대한 research
- make
- kubectl
- magick (ImageMagick): 에셋 생성/변환 활동의 Fast-Track 적합성 분석
  • 기획 분석: 생성 활동(이미지 변환, 리사이징 등)은 기본적으로 생산적이나, 임의 파일 덮어쓰기(Overwrite) 및 델리게이트 취약점(MSL/HTTPS/Ghostscript) 리스크 상존.
  • 권장 방안: 전역 무조건 Fast-Track 대신, (1) 안전 확장자(.png/.webp/.svg 등) 한정 (2) 민감 파일 Denylist(INV-SENS-1/2) 가드 (3) 프로토콜 델리게이트 차단 조건부 패턴 또는 `#7207 Workspace .schengen/` 자동 프로모션 활용.
- 그외에 이런 ruleset을 잘 관리할수있는 별도 파일 포맷으로 체계를 가지고 조사하는게 좋을지 조사.

[] context compact 구현

[] test code를 source code와 동일한 folder구조를 가지거나, (Most recommended) Python 관례상 가장 best practice가 되도록 테스트 코드 위치가 수정되도록 refactor
