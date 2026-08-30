## Handoff — Next Pick (맥락 보존 우선순위)
> 세션이 길어 handoff가 필요하므로, 맥락(불변식·@oracle verdict·어댑터 세부)이 보존되어야 더 잘
> 진행되는 이슈를 아래 순서로 picking. 각 항목에 필요한 맥락을 요약해두었다.
> **🎉 Epic Fail-closed 편향 전환 M1~M7 전면 완료 (PR #126~PR #144)**
> **🎉 핵심 아키텍처 4종 완료: Approver Provenance(PR #147) / Persistent CUD(PR #150) / Codex edit_file(PR #151) / AGY·OpenCode 전개(PR #152)**

### 🎯 확정된 4-Sprint 진행 로드맵

1. 🚨 **[Sprint 1 — P0 긴급 버그 일괄]** Liveness/Auto-Eviction 정밀화 (보안 회귀 #7771/#7938 + 블로커 #2800)
   - 1a) `#7771` (AGY) & `#7938` (Codex ppt space) (보안 회귀 최우선): 어댑터별 `dialog_is_live()` 앵커/가변 윈도우 보강 + TUI pre-render 즉시 승인 방지(Debounce/프로세스 상태전이 가드) ➔ 가짜 `pane-direct` 승인 박멸 (`INV-PD-4`).
   - 1b) `#2800` (블로킹 해소): TUI pre-render `is_question` 예외 제거 + Watcher QUESTION 소멸 시 auto-evict (`resolution="ANSWERED"`).

2. 🎨 **[Sprint 2 — 관측성 & 인터랙션 극대화]** Action Required 3단 패널 + Queue Taxonomy + Universal Deep-Link
   - Top Banner(붉은 점멸) + Radar 상태 카드 + 채팅창 결재 카드 + 큐 4단계 배지 + `[#ID]` 원클릭 Audit 점프.
3. 🧹 **[Sprint 3 — 코드베이스 위생 & 테스트 수렴]** 피어리뷰 후속 일괄 수렴
   - #137 회귀 / #17 / #52 / #45 / #33 / M6 / M7 / #2555 / #7207 / #146 등 종합 정리.
4. ⚙️ **[Sprint 4 — 대형 동시성 엔진]** [EPIC] Parallel Silent Inspection & Single-Slot Deferred UI
   - M1(WAL/Lock) ➔ M2(ThreadPool 10) ➔ M3(DeferredHumanQueue) ➔ M4(Pre-Display Purge).

---

## 🏛️ Completed Milestones & Architecture Ledger (25 Items)

[x] TUI가 terminal resize를 감지 못함: terminal 크기가 바뀌어도 작게 유지됨. (PR #94)
  - 실제 원인: NoPixelMouseDriver가 _enable_in_band_window_resize(2048h)만 no-op하고
    _query_in_band_window_resize(2048$p)는 그대로 실행 → Herdr가 "2048 supported"로
    응답 → LinuxDriver.process_message가 _in_band_window_resize=True로 플립 →
    SIGWINCH 핸들러(`if not self._in_band_window_resize`)가 죽음.
    즉, in-band resize는 실제로 켜지지 않았는데 SIGWINCH도 꺼져 resize 이벤트 전무.
  - 해결: capability query(2048$p)도 no-op 처리 → 플래그가 False로 유지되어
    SIGWINCH fallback이 정상 동작. 1016(pixel mouse)은 그대로 off로 mouse cell-mode 유지.
  - 검증: live — pane 154→30cols 축소 시 narrow re-render, 30→180cols 확장 시 wide re-render 확인.

[x] opencode 텍스트 누출 잔여(#57) half-measure (PR #95): 플러그인 `event` 훅으로 `permission.asked`를
    per-pane JSON 채널(~/.local/state/herdr-schengen/opencode_permissions/)에 기록, 어댑터가 clean 커맨드를
    1차 소스로 읽고 pane-text 파싱은 fail-closed fallback. (명령 추출 신뢰성 개선, 완료)

[x] #57 full closure (PR #105): `client.permission.reply(permission_id)` 승인 바인딩 + 결정 채널 + plugin decision poller.
    pane-text를 opencode 승인 임계경로에서 제거 (bare enter fail-open 해소). AGY pane-text는 별도.

[x] escalation poller JSON parse error (PR #100): `runHistoryPending()`이 빈 출력/실패 시 `[]` 반환 + 실패 원인 로깅.

[x] Codex `edit_file` 실제 승인(Pane 직접 입력 'y' 또는 TUI /approve) 완료 후에도 Pending에 잔류하는 현상 수정 (PR #146 완료):
  - 해결: `dialog_is_live` tail-anchored 검증(`rfind` 헤더 + `› 1. Yes` focused-row 앵커)으로 과거 스크롤백 오인식 원천 방지 및 auto-eviction 연동.

[x] [Bug/Eviction] AGY 및 Codex 다이얼로그 오판(tail 오버플로우/앵커 누락)으로 인한 조기 Auto-Eviction(가짜 pane-direct 승인) 버그 (PR #153 완료, INV-PD-1/4/5):
  - 해결: (1) AGY `dialog_is_live` 앵커 전면 보강 (2) Codex 헤더(`rfind`) 기준 가변 윈도우 탐색 적용 (3) TUI/Watcher debounce & 프로세스 상태전이 가드(`INV-PD-4/5`)로 가짜 `pane-direct` 승인 완벽 차단.




  1) tail window 동적/유연화: `tail_lines=8` 고정값으로 인해 긴 다이얼로그/스피너/줄바꿈 발생 시 실제 live 다이얼로그를 stale로 오판(over-block)하는 갭 해소 (가변 window 또는 footer 역방향 탐색 검토).
  2) marker 잔류 오인식 방지: 종료된 다이얼로그의 footer marker가 8줄 뷰포트에 잔류할 때 여전히 live 상태로 오판하는 이슈 방지 정밀화.
  3) tail window 경계 단위테스트: footer 위치(8줄 vs 9줄 등)에 따른 경계 조건 테스트케이스 추가.

[x] [Bug/Approval] Escalation #1910 & #2339 승인 발화 성공 후 실제 Pane(OpenCode w1D:p1) 명령 미승인 현상 (PR #137 완료):
  - 해결: (1) `approve_escalation` inject-first / record-after 트랜잭션 순서 확립 (2) `inject_approval` unknown-stage fail-closed (3) `_norm_req_cmd` 수술적 정규화 + CHANNEL_TTL 30s→3600s 확장 (4) defer vs hard-failure 에러 구분.

[x] [Refactor/Channel] OpenCode 권한 채널 및 테스트 러너 Fast-Track 후속 3종 (PR #137, PR #142 완료):
  1) Stale event 회귀 테스트: '다른 ask 발생, 동일 command string' 상황에서 CHANNEL_TTL 3600 안전성 고정 단위테스트 추가.
  2) `_norm_req_cmd` 공백 붕괴 유의: soft-wrap으로 path/token이 newline 분할될 때의 동작 정합성 및 향후 렌더러 변경 시 주의점 문서화.
  3) [x] Test Runner Fast-Track 허용 (PR #142): `python3 -m unittest` 및 `2>&1 | grep` 파이프라인 Fast-Track + Complexity Tax 사전 통과 완료 (#2555 해소).

[x] [Task/Allowlist] 단독 실행 읽기 전용 sed(`sed -n '<range>p' <file>`) — PR #141 완료 (폐쇄 화이트리스트 + -e/-f 가드 + 파이프라인 하드닝):
  - 현상 및 원인:
    • Codex 에이전트가 파일/스킬 문서 열람을 위해 `sed -n '1,260p' /path/to/file`을 빈번히 실행하나, 현재 `security_evaluator.py`의 `READONLY_PIPELINE_COMMANDS`에는 `sed`가 포함되어 있으나 단독 명령 allowlist인 `FAST_TRACK_SAFE_COMMANDS`에는 `sed`가 누락되어 있어 파이프라인(`|`) 없는 단독 `sed -n`이 `NOT_ALLOWLISTED`로 fail-closed 에스컬레이션됨.
  - 안전성 검증 및 Allowlist 등록 조건:
    1) `-n` 플래그 및 `...p` 출력 패턴 확인 (인-플레이스 수정 `-i`, `--in-place` 절대 금지).
    2) 리다이렉트(`>`, `>>`) 및 치환 쓰기 배제 확인.
    3) Sensitive File Denylist (`.env*`, `~/.ssh/*`, `*.key` 등) 및 광범위 와일드카드(`~`, `/`) 차단 불변식(INV-SENS-1/2) 통과 전제.
  - 해결 방안:
    • `security_evaluator.py`의 단독 명령 판정 로직에 읽기 전용 `sed` 패턴(`^sed\s+-n\s+['"][^'"]*p['"]\s+\S+`) 또는 `FAST_TRACK_SAFE_COMMANDS` + in-place 가드 추가.

[x] [Task/Architecture] Pane 직접 승인(Pane-Direct Adjudication) 실시간 감지 및 Stale Escalation 자동 해제(Auto-Eviction) 아키텍처 구현 (PR #146 완료):
  - 해결: (1) `dialog_is_live` 어댑터별 tail 앵커링 (2) watcher `should_evict_pane_direct` 3단계(PD-A/B/C) 실시간 퇴출 (3) TUI pre-render slot validation으로 Stale 에스컬레이션 즉시 자동 정리.

[x] [Bug/SAST] Daemon 실행 환경 PATH 누락으로 인한 SAST(shellcheck/semgrep) Degraded 과에스컬레이션 버그 (PR #132): `_inject_runtime_path()`로 런타임 bin 디렉터리 주입 완료.

[x] [Refactor/Codex] Codex edit-dialog 파서 정밀화 및 경로 누락(Bare `edit_file`) 방지 (PR #151 완료, INV-EF-1..5):
  - 해결: (1) `^\s*(?:│\s*)?(?:Destination|File):` 인덴트/프레임 허용 (2) `re.IGNORECASE` 대소문자 포용 (3) 다중 파일 워크스페이스 검증 및 bare `edit_file` 누락 방지.

[x] [Prerequisite/Host] 호스트 머신 semgrep 바이너리 미설치로 인한 SAST DEGRADED 해소: semgrep 1.175.0 설치(/opt/homebrew/bin/semgrep) 및 기능 스캔/SAST BLOCK 정상 탐지 검증 완료. shellcheck+semgrep 모두 READY.

[x] Full screen 에서 item클릭했을때 한 record만 focus해서 더 자세히 볼수있는 뷰
  - 과거에 추가의견에 대해서 보관한 table이 있을텐데 join해서 보여줄수있으면 더 좋음. (AuditDetailModal + get_audit_log_by_id/get_adjudications_for_audit join)

[x] Verdict=ESCALATED시에 Schengen을 통한 추가 처리 상태 ( Approve/Reject/Unanswer/etc
.. ) 를 표시 -> 표시되지 못한다면 tui뿐만 아니고 내부 로직도 확장 (pending_escalations.resolution 컬럼 추가 + record_adjudication/cleanup_escalations에서 APPROVED/REJECTED/UNANSWERED 기록, audit ledger Res 컬럼/상세 resolution 표시)

[x] 내부 답변을 위한 언어에 English/한국어/日本語 를 표시하여 셋중에 하나를 선택할수있는 버튼그룹을 만들고, 선택된 버튼그룹의 언어가 chat화면의 답변으로 렌더링이 "유도"될수있게 prompt를 구성해줘. 단 여기서 주의할점은, 지침이 agent에게 herdr를 통해 전달될때는 반드시 토큰을 아끼기 위해 영어여야된다는 전제를 지켜야 된다는 것이다. (default: 한국어, guard_config.answer_language, herdr english_feedback은 영어 유지)

[x] codex adapter 지원 (PR #106): Codex CLI 승인 모달 파싱(exec/network/edit/stdin/permissions) + 'y' key auto-approve. live 검증 완료. (codex는 untrusted 모드 필요)

[x] Fullscreen 및 detail item 화면에서 마우스만으로 컨트롤 가능하게 X 버튼 구현 (PR #104). ModalCloseMixin + MODAL_CLOSE_CSS 공용 컨벤션으로 일반화.

[x] Schengen gatekeeper message에 Time format 추가 (PR #103): HH:MM:SS + 날짜는 일자 변경 시에만.

[x] 승인/거절 provenance(당사자) 명확화 — APPROVED/REJECTED/UNANSWERED resolution에 대해 (PR #125)
   [정확 감지 가능]:
     1) machine  (guard auto-approve → decision=AUTO_APPROVED)
     2) human-tui (gatekeeper LLM / /approve /reject → adjudication_log.action)
   [정확 감지 불가 → 나머지 버킷으로 축소]:
     3) other/remainder (= machine/tui 외 나머지. pane 직접 입력 y/n/esc는 출처 구분 불가 —
        send-keys든 사용자 타이핑이든 둘 다 pane PTY로 들어가 pane 텍스트에 안 남음)
   - best-effort y/n 추론(선택, 의미 있음): dialog clear 후 command 실제 실행 여부 등으로 승인/거절 간접 추론.
     단 조용한 실행/재프롬프트 시 오판 가능 → 신뢰도 낮음, 별도 표기.
   - 필요 시 audit_logs/adjudication_log에 approver provenance 컬럼 추가 (machine / human-tui / other)
   - TUI audit table/detail 모달에 approver 배지 표시 (예: 🤖 / 👤 / ❓)
    - Reject/Unknown도 동일 적용 (reject: machine-no-autoreject / human-tui / other)

[x] [Idea] TUI 런타임 핫 리로드(Hot-reloadable) Persistent Allowlist & 동적 Policy CUD 생명주기 관리 (PR #150 완료, INV-PL-1..5):
   - 해결: (1) TUI `/allow`, `/revoke` 명령어 및 Gatekeeper `register_allowlist` tool call (2) SQLite `user_allowlist` 테이블 기반 동적 CUD (3) 런타임 무중단 핫리로드 및 INV-PL-1..5 불변식 완결.

[x] [Task/Architecture] Workspace별 `.schengen/` 기반 영속 Allowlist & 승인 후 기계적 지속 자동승인(Auto-Promotion) 체계 구축 (PR #145 완료):

   - Context & Problem (사례: #7207 `access_directory /path/to/worktree` 등):
     - 워크스페이스 외부 경로(worktree, 공유 디렉터리, 라이브러리) 접근이나 반복 명령에 대해, 1회 승인된 이후에도 세션이 바뀌거나 캐시가 만료되면 다시 에스컬레이션되는 비효율 발생.
   - Solution & Architecture Design:
     1. Workspace-Local 정책 저장소 (`<workspace>/.schengen/`):
        - 프로젝트 루트마다 `.schengen/allowlist.json` (또는 `directory_whitelist.json`) 파일 유지.
        - 워크스페이스 범위에서 허용된 외부 디렉터리 경로 및 안전 패턴을 저장 (VCS 커밋 또는 로컬 ignore 선택 가능).
     2. 지속 승인 프로모션 파이프라인 (Auto-Promotion Pipeline):
        - [1차 진입]: 최초 `access_directory` 또는 특정 명령 발생 시 ➔ Gatekeeper LLM / Human Commander에게 에스컬레이션.
        - [승인 및 영속화]: 인간 또는 고신뢰 판정으로 승인 완료 시 ➔ 해당 워크스페이스의 `.schengen/allowlist.json`에 영속 룰 자동 등록.
        - [2차 이후 기계적 즉시 통과]: 이후 동일 경로/패턴 요청 시 ➔ 에스컬레이션 전 단계인 결정론적 AST/경로 검사기에서 `.schengen/`을 먼저 조회하여 **0.1s 미만 기계적 자동 승인(`decision_layer=FAST_TRACK_WORKSPACE_ALLOWLIST`)**으로 직행.
     3. 불변식 (Invariants):
        - INV-WS-1 (Scope Confinement): `.schengen/` 정책은 해당 워크스페이스 작업에만 국한 적용.
        - INV-WS-2 (Denylist Overrides Whitelist): 시스템 민감 경로(`~/.ssh`, `~/.aws`, 루트 `/`)는 `.schengen/`에 기재되어 있어도 절대 허용 불가 (Hard Fail-Closed).

[x] [Task/Feature] 에스컬레이션 로그(#1800~) 기반 Fast-Track 후보군 발굴 (PR #129: sub-task 1·2 완료 — 읽기전용 파이프라인 fast-track + 민감 Denylist)
   - 잔여: sub-task 3 (TUI Slash Command / Tool Call: /allow, /allow-last, /revoke) → Persistent Allowlist CUD(#91)와 통합 추진
   - Context:
     - fail-closed 편향 전환 이후 #1800~#1970 구간의 에스컬레이션 88건 분석 결과, 안전한 읽기 전용 파이프라인/Git 조회/테스트 실행이 복합 명령(;, &&, |) 결합으로 인해 과도하게 에스컬레이션됨.
     - 인간이 TUI 프롬프트 창이나 Gatekeeper Tool Call(`add_fast_track_pattern`, `register_allowlist_rule`)을 통해 손쉽게 패턴을 allowlist에 등록하고 제어할 수 있는 실행 경로 필요.
   - Key Subtasks & Requirements:
     1. #1800~ 에스컬레이션 분석 기반 Fast-Track Allowlist 후보군 5개 범주 전면 반영:
        - [1. Read-Only Code/File Inspection 체인] (40건 분석 반영):
          • `sed -n '<range>p' <file>`, `rg <pattern> <path>`, `grep <pattern>`, `cat <file>`, `head -n <N>`, `tail -n <N>`, `pwd && rg --files ...`
          • 리다이렉트(`>`, `>>`), 치환 쓰기(`sed -i`), 삭제(`rm`)가 배제된 순수 Read-only 파이프라인/복합문 체인(`|`, `&&`, `;`)의 Fast-Track Safe 처리 (아래 민감 파일 Denylist 준수 전제).
        - [2. Git Read-Only Inspection & CWD 이동 체인] (5건 분석 반영):
          • `git (-C <path> )?(status|log|diff|branch|worktree list)(\s+[^;&|<]+)?`
          • `cd <repo_path> && git status --short && git log -1` 및 `git diff --check`, `git worktree list | grep ...` 등 비파괴적 저장소 상태 조회 허용.
        - [3. Salada Forgejo CLI 읽기 전용 조회 서브커맨드] (2건 분석 반영):
          • `.*salada-forgejo\.sh (issue list|issue view|pr list|pr view|branch list).*`
          • 단순 이슈/PR 목록 및 내용 조회의 자율 승인 (단, `pr create`, `issue close` 등 변이성 명령은 Human Review 유지).
        - [4. SQLite 안전 조회 및 스키마 검사] (5건 분석 반영):
          • `sqlite3 <db> "(\.tables|\.schema.*|SELECT .*)"`
          • 불변 쿼리 및 메타데이터 조회 허용 (단, `INSERT|UPDATE|DELETE|DROP|ALTER|CREATE|ATTACH` 등 데이터/스키마 변이 키워드는 Fail-Closed 차단).
        - [5. Local Test Runner (단위 테스트 실행)] (5건 분석 반영):
          • `(HERDR_ENV=1 )?(~/.local/share/[^/]+/bin/)?python3 -m unittest discover -s tests.*`
          • `pytest tests/.*`
          • 프로젝트 내부 격리된 테스트 스위트 실행의 세션/CWD 스코프 자동 승인.
     2. [보안 기획 보강] 읽기 명령(sed, rg, grep, cat 등) 대상 민감 파일 Denylist 차단 체계:
        - 원칙: `sed`, `rg` 등이 read-only fast-track 허용 대상이라도, 조회 대상 파일/디렉터리가 민감 경로에 해당하면 무조건 fail-closed 에스컬레이션.
        - 민감 파일 패턴(Sensitive Denylist):
          • 환경변수/설정: `.env*`, `*.env`, `local.properties`, `settings.json`(시크릿 포함 경로)
          • 인증키/인증서: `~/.ssh/*`, `*.key`, `*.pem`, `id_rsa*`, `id_ed25519*`, `*.p12`, `*.pfx`, `known_hosts`, `authorized_keys`
          • 클라우드/API 자격증명: `~/.aws/*`, `~/.config/gcloud/*`, `~/.kube/config`, `~/.netrc`, `~/.npmrc`, `~/.pypirc`, `*token*`, `*credential*`, `*secret*`
          • 히스토리/키체인/볼트: `~/.zsh_history`, `~/.bash_history`, `*.kdbx`, `*.keychain*`
        - 불변식 (Invariants):
          • INV-SENS-1 (Target Path AST Parsing): AST 파서가 명령 인자에서 파일 경로/glob을 분리 및 절대경로 canonical화 후 Sensitive Denylist 대조.
          • INV-SENS-2 (Broad Wildcard Hard-Escalate): 광범위 탐색(예: `rg pattern ~`, `cat .*`, `grep -r /`)으로 민감 경로 침범 가능성이 있을 시 fast-track 배제 및 human 에스컬레이션.
          • INV-SENS-3 (Redaction Linking): 민감 경로 접근 시 TUI 프롬프트/로그 상에 시크릿 누출 방지를 위한 redaction 연동.
     3. TUI Slash Command / Tool Call 인터페이스 구현:
        - TUI Command: `/allow <pattern>`, `/allow-last` (직전 에스컬레이션 등록), `/allow-list` (현재 등록 목록), `/revoke <id>`
        - Gatekeeper Tool Calling: `register_allowlist(pattern, scope, reason)` tool call 지원 및 인간 확인 후 핫 리로드.

[x] [Bug/Audit] 승인 주체(Approver Provenance) 오귀속 수정: 시스템/Gatekeeper LLM 자동 승인과 인간 직접 승인(Human TUI) 엄격 분리 (PR #147 완료, INV-AP-1..6):
   - 해결: `adjudication_log.action` 및 `pending_escalations.approver`에 `⚡ GATEKEEPER` vs `👤 HUMAN` vs `🤖 MACHINE` vs `❓ OTHER` 명확 분리 및 신뢰 프로모션 불변식 확립.

[x] [Task/Feature] AGY 장문/생략 명령(⋯ lines hidden) 발생 시 `ctrl+g` 전개 및 OpenCode `ctrl+f` 풀스크린 전개 자율 검증 (PR #152 완료, INV-EX-1..5):
   - 해결: `adapter.expand_dialog` 인터페이스를 통해 AGY(`ctrl+g`), OpenCode(`ctrl+f`), Codex(`ctrl+a`) 전개 ➔ 100% 전문 AST 검증 및 자율 승인 완료.
