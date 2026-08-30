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





Bug (HIGHEST PRIORITY — handoff 후 최우선):
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

[] [Bug/Question] Pane 질문(decision_layer='QUESTION') 답변 완료 후에도 TUI 상단 배너 및 Pending 큐에 영구 잔류하는 현상 수정 (사례: #2800):
  - 대원칙: **Question에는 명령과 같은 '승인/거절(resolve)' 상태가 없음** (단순히 인간이 Pane에서 직접 타이핑/엔터하여 다이얼로그가 사라지면 큐에서 자동 제거/소멸되어야 하는 대상).
  - 현상 및 원인 (사례: Escalation #2800 Codex 질문 등):
    • 에이전트가 사용자에게 질문(`Question 1/1 ...`)을 하여 `decision_layer='QUESTION'`으로 에스컬레이션된 후, 사용자가 해당 Pane에서 직접 답변을 완료했음에도 TUI 상단 배너와 `pending_escalations` 큐에서 제거되지 않고 계속 Pending 상태로 고착됨.
    • 근본 원인:
      1) `schengen_tui.py`: `pre-render slot validation`에서 `if not is_question`으로 `QUESTION` 레이어를 의도적으로 제외하여, TUI 렌더링 시 다이얼로그 소멸 검사 및 Auto-Eviction이 전혀 발동하지 않음.
      2) `schengen_watcher.py`: `pane_direct_maybe_evict`가 `not is_safe`인 UNSAFE 에스컬레이션만 검사(`is_safe=True`인 QUESTION은 제외)하여 데몬 루프에서도 소멸 감지 누락.
      3) Cross-Workspace/Idle 감시 갭: 감시 대상이 아닌 워크스페이스/Pane이거나 답변 후 에이전트가 즉시 다음 작업/idle로 전이될 때 `not req_cmd` 트리거가 유실됨.
  - 임시 Workaround 조치 (2026-08-31 완료):
    • 블로킹 긴급 해소를 위해 Escalation #2800 레코드를 SQLite에서 `status='RESOLVED', resolution='ANSWERED', approver='human-pane'`로 수동 업데이트하여 TUI 배너 클리어 완료. (코드 수준 근본 해결 필요)
  - 해결 방향 (최저 난이도 / 최소 변경):
    • **Watcher 및 TUI의 단순 Liveness 소멸 감지 & Auto-Evict (가장 낮은 난이도 적용)**:
      1) `schengen_watcher.py`: `decision_layer == "QUESTION"` 에스컬레이션에 대해 어댑터의 질문 다이얼로그(header/footer)가 소멸되었거나 에이전트가 `blocked`를 벗어난 경우 즉시 큐에서 해소/제거(`resolve_escalation` 또는 `status=RESOLVED, approver="pane-direct"` / `resolution="ANSWERED"`).
      2) `schengen_tui.py`: `pre-render slot validation`에서 `is_question` 예외를 제거하고, `adapter.dialog_is_live(pane_text) == False`일 때 즉시 큐에서 자동 퇴출(Silent Eviction)하여 상단 배너 고착 해소.

[] [Idea/Architecture] Question 분리 처리: 커맨드 에스컬레이션 큐 비차단(Non-blocking) & 사이드바/힌트 버튼 기반 Pane 점프 분리
  - Context & Core Problem:
    • Question은 TUI에서 승인/거절할 수 없고 반드시 사용자가 해당 Pane으로 가서 텍스트를 입력해야 함.
    • 현재 구조에서는 Question이 발생하면 TUI 단일 활성 슬롯을 점유하여, 다른 에이전트들의 모든 위험 명령 에스컬레이션 및 승인 파이프라인이 전면 병목(Block)되는 심각한 비효율 발생.
  - Solution & UI/UX Architecture:
    1) [Command Approval Slot과 Question 전면 분리 (Non-blocking)]:
       - Question(`decision_layer == "QUESTION"`)은 메인 커맨드 결재 슬롯(`Active Action Required Slot`)을 점유하지 않고 백그라운드 힌트로 격리.
       - 다른 Pane의 쉘 명령 에스컬레이션은 차질 없이 계속 TUI 메인 화면에 올라오고 정상 승인/거절 수행.
    2) [사이드바/레이더 힌트 배지 & 원클릭 Jump 연동]:
       - 우측 사이드 패널(Radar) 또는 상단 칩에 `💬 [w1N:p1 Question Awaiting Answer]` 미니 힌트 배지 표시.
       - 클릭 또는 `/jump <pane_id>` 입력 시 Herdr를 통해 해당 Pane으로 포커스를 즉시 전환하여 사용자가 타이핑할 수 있도록 안내.
    3) [자동 소멸 생명주기]:
       - 사용자가 해당 Pane에서 답변을 제출하면 `dialog_is_live == False` 감지와 함께 사이드바 힌트 배지가 무음 소멸.



[] [Bug/Eviction] AGY 및 Codex 다이얼로그 오판(tail 오버플로우/앵커 누락)으로 인한 조기 Auto-Eviction(가짜 pane-direct 승인) 버그 (사례: #7771 AGY / #7938 Codex):
  - 현상 및 원인 (사례: Audit #7771 AGY Git 커밋 & Audit #7938 / Escalation #2947 Codex SQLite 장문 쿼리):
    • 대상 Pane(`w1D:p5X` AGY, `w1N:p1` Codex)에서 명령이 실제로 승인되지 않고 승인 모달에서 대기 중이었음에도, TUI/Watcher가 생성 직후(사례 #7938의 경우 129ms 만에) `APPROVED (pane-direct)`로 오판하여 큐와 배너를 강제 소멸시킴.
    • 이로 인해 TUI/DB 상에는 승인 완료된 것으로 기록되지만, 실제 에이전트는 터미널에서 승인을 기다리며 영구 대기(Deadlock)에 빠지는 심각한 보안/운영 회귀 발생.
    • 근본 원인:
      1) 어댑터별 `dialog_is_live()` 앵커 불완전 및 Tail Window 한계:
         - AGY: 표준 권한 프레임(`Do you want to proceed?`, `1. Yes`, `Requesting permission for:` 등) 앵커 누락.
         - Codex: 장문 명령(예: #7938 긴 SQL문) 실행 시 `visible_text[-400:]` 고정 길이 윈도우를 벗어나 `_ACTIVE_CHOICE_RE` 매칭 실패 ➔ `dialog_is_live == False` 반환.
      2) TUI Pre-render Slot Validation의 과격한 즉시 승인: `dialog_is_live`가 1회 `False`를 반환하는 순간, 사용자가 Pane에서 직접 승인한 것으로 단정하고 즉시 `resolve_escalation(..., resolution="APPROVED", approver="pane-direct")`을 호출함.
  - 해결 방안:
    1) 어댑터 `dialog_is_live()` 전면 보강:
       - `agy.py`: 전체 권한 다이얼로그 텍스트 프레임 누락 없이 포함.
       - `codex.py`: `visible_text[-400:]` 고정값 대신 다이얼로그 헤더(`rfind`) 기준으로 가변 윈도우 탐색 적용.
    2) Eviction 판정 가드 강화 (`INV-PD-4`):
       - 단순 liveness 1회 실패로 즉시 `APPROVED` 처리하지 않고, 에이전트의 실제 프로세스 상태(`blocked` -> `working/idle`)를 확인하거나 연속 n회 불일치(debounce) 확인 후 퇴출하도록 방어.



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

[] [Refactor/Adapters] Codex 및 AGY 다이얼로그 앵커 liveness 한정 주석 명시 2종 (#146 피어리뷰 후속):
  1) Codex 앵커(digit) 확대는 liveness-only 전용: 향후 옵션 번호 -> 승인/거절 매핑 시 '1=Yes' 가정 금지 주의.
  2) AGY 앵커(digit) liveness-only 주석 명시: liveness 검사 외 다른 용도로의 전용 방지.

[] [Refactor/Eviction] Stale Escalation Eviction 로직 정밀화 3종 (#33 피어리뷰 후속):

  1) 에이전트 상태 문자열 대소문자 무시: `_should_evict_stale_escalation`의 `blocked` vs `working/idle/done` 매칭에 `.lower()` 또는 공용 상태 상수 적용 (Herdr 상태 케이싱 차이로 인한 eviction 누락 방지).
  2) 해소 상태값 표준화 및 검증: `resolve_escalation`의 `RESOLVED` vs `CANCELLED` 처리 경로 일관성 점검 및 `approver="pane-direct"` 다운스트림 정상 연동 확인.
  3) 명령 일치성(Command-Match) 검사 추가: `pane_id` 단독 키 매칭 외에 `raw_command` 동일성 확인을 추가하여, 다이얼로그 내용이 다른 미승인 명령으로 교체된 경우의 오퇴출 방지.
[x] [Bug/SAST] Daemon 실행 환경 PATH 누락으로 인한 SAST(shellcheck/semgrep) Degraded 과에스컬레이션 버그 (PR #132): `_inject_runtime_path()`로 런타임 bin 디렉터리 주입 완료.

[x] [Refactor/Codex] Codex edit-dialog 파서 정밀화 및 경로 누락(Bare `edit_file`) 방지 (PR #151 완료, INV-EF-1..5):
  - 해결: (1) `^\s*(?:│\s*)?(?:Destination|File):` 인덴트/프레임 허용 (2) `re.IGNORECASE` 대소문자 포용 (3) 다중 파일 워크스페이스 검증 및 bare `edit_file` 누락 방지.


[x] [Prerequisite/Host] 호스트 머신 semgrep 바이너리 미설치로 인한 SAST DEGRADED 해소: semgrep 1.175.0 설치(/opt/homebrew/bin/semgrep) 및 기능 스캔/SAST BLOCK 정상 탐지 검증 완료. shellcheck+semgrep 모두 READY.
[] [Task/Dependency] semgrep 필수 디펜던시(Required Dependency) 체계적 관리 및 자동화 방안 수립:
  - Context & Objective:
    • semgrep은 SmartGate의 SAST Pre-Filter 및 Fail-Closed 보안의 핵심 축이나, 현재 호스트 수동 설치에 의존하고 있어 환경 간 드리프트(Drift) 발생 위험이 있음.
  - Recommended Solutions & Multi-Layer Management:
    1) [Python venv 디펜던시 선언 (pyproject.toml)]:
       - `semgrep`은 PyPI 표준 배포 패키지(`semgrep>=1.70.0`)이므로, `pyproject.toml` 및 `requirements.txt`에 명시적 의존성으로 추가.
       - TUI venv(`~/.local/share/herdr-schengen-tui-venv/`) 생성/동기화 시 `semgrep` CLI 바이너리가 venv `bin/`에 자동 설치·동기화되도록 보장.
    2) [Host Runtime Gate 강제 (Startup Pre-Flight Check)]:
       - `verify_host_runtime_environment()`에서 `semgrep` 탐색 실패 시 무조건 fail-closed 및 명확한 액션 가이드(`pip install semgrep` 또는 `brew install semgrep`) 안내.
    3) [CI / Forgejo Runner 및 Dotfiles 연동]:
       - `.forgejo/workflows/` CI 테스트 환경 및 배포 스크립트에 semgrep 설치 스텝 공식화.

[] [Refactor/SAST] `_inject_runtime_path()` 및 Host Runtime Gate 안정화 4종 (#45 피어리뷰 후속):
  1) `_inject_runtime_path()` 선행순서 버그 수정: `parts.insert(0, d)` 반복으로 `~/.local/bin`이 최우선순위가 되어 Homebrew 바이너리를 섀도잉(shadow)할 위험 해소 (reverse iteration 또는 시스템/Homebrew 우선순위 보존).
  2) 빈 PATH 항목(`.`) 처리: `os.environ["PATH"].split(":")` 필터 시 빈 항목 drop 동작 정리 및 명시적 문서화.
  3) 플랫폼 가드: `_RUNTIME_BIN_DIRS`에 macOS 전용(`/opt/homebrew`, `/usr/local`) 외 `sys.platform` 분기 및 Linux 경로 지원.
  4) 실행 순서 최적화: `SAST telemetry print`가 host-runtime gate 검증 완료 후 출력되도록 순서 조정.

[] [Refactor/Complexity] Complexity Tax 정밀화 및 DB 쿼리 최적화 5종 (#139 피어리뷰 후속):
  1) `2>&1` over-count 보정: `&`가 분리자로 취급되어 `ls 2>&1`이 3점으로 과계산되는 엣지케이스(`n>&m` 리다이렉션 특수처리) 보정.
  2) Herestring(`<<<`) under-count 보강: `_COMPLEXITY_REDIR_RE`에 `<<<` 리다이렉션 패턴 추가.
  3) 산술확장(`$((...))`) vs 커맨드 치환(`$(...)`): 산술확장이 커맨드 치환으로 오인식되어 과계산되는 갭 정밀화 (fail-closed 무해).
  4) `get_complexity_tax_config()` in-memory 캐싱: 비-allowlist 명령마다 SQLite `init_db` 및 `SELECT` 2회 반복 조회를 1회 캐시/read-once로 최적화.
  5) `complexity_mode='judge'` 모드 M6 Cloud Judge 라우팅 연계 완료.

[] [Refactor/CloudJudge] Cloud Judge Confidence & Complexity Mode 안정화 4종 (M6 피어리뷰 후속):
  1) Judge 모드 gray-zone guidance(`format_decision_guidance`) 유실 방지: judge-mode context 병합 검토.
  2) Cloud-Judge 캐시 키에 `confidence_threshold` 포함: 런타임 threshold 변경 시 TTL 만료 전까지 스테일되는 현상 방지.
  3) `set_cloud_judge_config` clamp 하한선 상향: 0.5 하한이 약하므로 0.7 상향 검토.
  4) LLM Inspector(`audit_dynamic_substitution_with_llm`)의 의도적 confidence 무-게이트 범위 명문화.

[] [Refactor/TestRunner] Test Runner 파이프라인 정규식 대칭화 2종 (#2555 피어리뷰 후속):
  1) fd-redirect 스트립 대칭화: `2>&1` 외 `1>&2`, `&>` 미커버 갭 해소.
  2) 공백 포함 엣지케이스: `2 >&1` 등 스페이스 포함 시 미스트립(over-block) 방어.

[] [Refactor/AntiFatigue] Anti-Fatigue 배치 집계 및 동의 품질 개선 4종 (M7 피어리뷰 후속):
  1) 배치 배너 raw 명령 목록 표시: quoted string/path 축약 패턴 대신 실제 raw 명령 목록을 표시하여 사용자 동의 품질 개선.
  2) 실패-inject 경로 회귀 테스트 추가: 키 주입 실패 시의 롤백 및 에러 핸들링 단위테스트 작성.
  3) Novelty `cwd` 차원 제거 트레이드오프 문서화: 스코프가 pane-only로 확장됨에 따른 영향 정리.
  4) `reject_batch` OpenCode 거절 플로우 연계: bare escape 대신 에이전트별 reject 프로토콜 연동.

[] [Refactor/WorkspacePolicy] Workspace `.schengen/` 정책 신뢰스토어 검증 3종 (#7207 피어리뷰 후속):
  1) INV-WS-3 Origin 게이트 연동: watcher의 INJECTED/EMERGENT origin 생산 연동.
  2) 신뢰 스토어 agent-writable 방어: read-time 위치 파생 `workspace_root` 검증으로 에이전트의 임의 룰 변조 차단.
  3) 경로 포함 exec 프로모션 차단 명문화: 절대경로 거부 동작 문서화.





Small task?
[x] Full screen 에서 item클릭했을때 한 record만 focus해서 더 자세히 볼수있는 뷰
  - 과거에 추가의견에 대해서 보관한 table이 있을텐데 join해서 보여줄수있으면 더 좋음. (AuditDetailModal + get_audit_log_by_id/get_adjudications_for_audit join)
[x] Verdict=ESCALATED시에 Schengen을 통한 추가 처리 상태 ( Approve/Reject/Unanswer/etc
.. ) 를 표시 -> 표시되지 못한다면 tui뿐만 아니고 내부 로직도 확장 (pending_escalations.resolution 컬럼 추가 + record_adjudication/cleanup_escalations에서 APPROVED/REJECTED/UNANSWERED 기록, audit ledger Res 컬럼/상세 resolution 표시)
[x] 내부 답변을 위한 언어에 English/한국어/日本語 를 표시하여 셋중에 하나를 선택할수있는 버튼그룹을 만들고, 선택된 버튼그룹의 언어가 chat화면의 답변으로 렌더링이 "유도"될수있게 prompt를 구성해줘. 단 여기서 주의할점은, 지침이 agent에게 herdr를 통해 전달될때는 반드시 토큰을 아끼기 위해 영어여야된다는 전제를 지켜야 된다는 것이다. (default: 한국어, guard_config.answer_language, herdr english_feedback은 영어 유지)

Epic: 
[x] codex adapter 지원 (PR #106): Codex CLI 승인 모달 파싱(exec/network/edit/stdin/permissions) + 'y' key auto-approve. live 검증 완료. (codex는 untrusted 모드 필요)
[] codex 지원 잔여: network/edit 등 템플릿 live 검증, reject 경로, Ctrl+A fullscreen long-command 경로.
[] 비가역적 상태의 위험성이 있는 command에 대한 research
- make
- kubectl
- magick (ImageMagick): 에셋 생성/변환 활동의 Fast-Track 적합성 분석
  • 기획 분석: 생성 활동(이미지 변환, 리사이징 등)은 기본적으로 생산적이나, 임의 파일 덮어쓰기(Overwrite) 및 델리게이트 취약점(MSL/HTTPS/Ghostscript) 리스크 상존.
  • 권장 방안: 전역 무조건 Fast-Track 대신, (1) 안전 확장자(.png/.webp/.svg 등) 한정 (2) 민감 파일 Denylist(INV-SENS-1/2) 가드 (3) 프로토콜 델리게이트 차단 조건부 패턴 또는 `#7207 Workspace .schengen/` 자동 프로모션 활용.
- 그외에 이런 ruleset을 잘 관리할수있는 별도 파일 포맷으로 체계를 가지고 조사하는게 좋을지 조사- make


[] [EPIC] Fail-open → fail-closed 편향 전환 + 패키지 매니저 인식 (@oracle 검토 verdict: MODIFY)
   - 근본 원인: security_evaluator.py:1163 종료형 `return True, "Safe", FAST_TRACK_AST` catch-all = "denylist만 아니면 허용".
     #1825(단순 read-only `strings|grep`)가 auto-approve된 원인.
   - 방향: "escalate unless proven-safe"로 기본값 역전. 결정 레이어 순서:
     ALLOWLIST(human-persisted) → narrow FAST_TRACK → novelty/history → package 3-tuple → gray-zone → complexity tax → origin-weighted cloud judge → human.
   [non-negotiable 불변식]
   - INV-1: :1163 fail-open catch-all 삭제. 모든 approval_bias 값(permissive 포함)에서 재도입 금지.
   - INV-2: degraded-SAST(:1160-1161)는 narrow allowlist 통과분 외 auto-approve 금지 → escalate/cloud judge.
   [핵심 불변식]
   - INV-3/4: novelty gate의 "승인 이력"은 (a)human APPROVED escalation (b)user_allowlist (c)고신뢰 cloud judge만.
     legacy pattern_stats.auto_approved_count(FAST_TRACK_AST) 상속 금지. 마이그레이션 시 learned-safe 셋 empty.
   - INV-5/6: fast-track auto-approve는 명시적 closed enum(ls/pwd/cat/head/tail/git status·log·diff…) +
     셸 메타문자(| & ; $() backtick <() > >> && ||) 및 forensic/네트워크 primitive(strings xxd base64 curl ssh …) 거부.
     #1825가 fast-track set에 절대 미포함되도록 단위테스트.
   - INV-7: normalize_command canonical화(순서안정 토큰, 버전→<VER> 폴딩, 플래그 정규화) + 순수함수 테스트표:
     foo==2.31.0 ≡ foo==2.31.1(동일키), brew install foo ≠ brew install bar(상이키), bare brew upgrade는 별개키.
   - INV-8..11: 패키지 classifier가 (manager, action_class, package_list) 반환. action_class ∈ {MUTATING, READ_ONLY}.
     MUTATING은 기본 escalate(정확 (action,package,version) + human승인 + 세션TTL + 스코프 내에서만 auto-approve).
     무패키지 변이(brew upgrade/npm ci/brew bundle/apt upgrade)는 무조건 escalate.
     npm ci·pip uninstall·brew uninstall·apt purge는 MUTATING(파괴). 미등록 매니저는 escalate(fail-closed).
     gray_zone_evaluator.py:379-380에서 brew/pip/apt가 HEAVY_EXEC 누락으로 READ→ALLOW 되는 갭도 수정.
   - INV-12: origin 임계값은 watcher가 생산한 단일 Origin enum만 사용. INJECTED/EMERGENT는 hard-escalate.
     Origin.HUMAN은 agent_kind=="human"일 때만 부여(테스트 보장). origin weighting은 마지막 안전 레버로 구현(스푸핑 위험).
   - INV-13: anti-fatigue(배치 집계 + scope+TTL 캐싱 + one-key approve)는 novelty gate와 동시 ship. 필수 전제.
   [configurability]
   - guard_config에 approval_bias ∈ {conservative(default), balanced, permissive} (TUI 버튼, human-only write).
     각 레이어 override(novelty_gate_enabled, cloud_judge_min_confidence, package_approve_ttl_seconds, fast_track_mode)가 진실공급원.
   - guardrail: (1)catch-all 제거 unconditional (2)활성 bias를 audit row+배너 기록 (3)human-only 쓰기+변경 audit
     (4)fail-open tripwire: permissive에서 human승인 0건 fast-track auto-approve 비율 임계 초과 시 경고 (5)default conservative.
   [edge cases (§6) — 구현 전 스펙 필요]
   - npm install(무패키지)·pip install -r/-e .·--cask 네임스페이스 충돌·multi-package·brew bundle·npm ci·
     버전 문법(@latest/^/>=)·sudo-prefixed install(스트립 금지)·brew update/cleanup·npm audit vs audit fix·
     미등록 매니저(yarn/pnpm/bun/nix/go install)·READ 쿼리 네트워크(brew search/npm view) 라우팅.
     [milestone 순서]
      1) [x] narrow AST + catch-all 제거 (PR #126) 2) [x] novelty/history gate + scope/TTL (PR #128) 3) [x] complexity (PR #139)
      4) [x] package manager (PR #131) 5) [x] origin weighting (PR #140) 6) [x] cloud judge confidence (PR #143)
      7) [x] anti-fatigue batch 집계 + one-key approve + novelty cwd fix (PR #144 완료 — M1~M7 전면 완결)


TASKS:
[] context compact 구현
[] test code를 source code와 동일한 folder구조를 가지거나, (Most recommanded) Python 관례상 가장 best practice가 되도록 테스트 코드 위치가 수정되도록 refactor
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

[] [Task/UX] TUI 토글/설정 옵션 전용 윈도우(Settings Modal) 분리 및 사이드바 상태 카드 위젯(Status Card Widget) 도입
   - Context & Problem:
     - 기능 확장(Guard 토글, Controller/Observer 모드, 승인/거절 지침 토글, 다국어 선택, Approval Bias, Fast-Track 모드 등)에 따라 메인 TUI 화면에 토글 버튼이 과도하게 증식하여 화면이 복잡해지고 시인성이 저하됨.
   - Solution & Architecture:
     1. 사이드 패널(Radar Column) 상태 요약 카드 위젯 (Status Card Widget) 배치:
        - 메인 채팅 영역을 전혀 침범하지 않고, 우측 사이드 패널 상단에 정돈된 구조화 미니 카드(Info Box) 위젯 배치:
          ```text
          ┌─ System Status ──────────┐
          │ Mode  : Controller (👑)  │
          │ Guard : ACTIVE (🛡️)      │
          │ Bias  : Conservative     │
          │ Lang  : Korean (KO)      │
          │ Instr : Reject-only      │
          └──────────────────────────┘
          ```
     2. 전용 설정 모달 서브 윈도우(SettingsModal) 도입:
        - 진입 방법: 단축키 `^s` (Settings), `F2`, 설정 버튼 클릭, 또는 Slash Command `/config`, `/settings`
        - 모달 내부 카테고리별 정돈된 편집 UI 제공:
          • [운영 모드]: Guard Daemon ON/OFF, Controller vs Observer Leader 선택
          • [지침 주입]: 승인(Approve) 시 지침 전달 ON/OFF, 거절(Reject) 시 지침 전달 ON/OFF
          • [로컬라이제이션]: Gatekeeper 응답 언어 선택 (한국어 / English / 日本語)
          • [보안 정책]: Approval Bias (Conservative / Balanced / Permissive), Fast-Track 모드 토글
        - 설정 모달 내 변경 사항 즉시 SQLite `guard_config` 영속화 및 우측 상태 카드에 실시간 동기화.

[] [Task/UX] 에스컬레이션 배너/메시지 타이밍 및 상태 전이 명확화: 자율 판정 완료 후 '인간 개입 필요(Action Required)' 진한 강조 노출
   - Context & Problem:
     - 현재 Inspector가 자율 조사를 진행 중인 상태임에도 `Gray-zone deferred to human` 및 `⚠ Not in fast-track allowlist` 문구가 미리 화면에 노출되어, 인간 지휘관 입장에서 "지금 개입해야 하는지, AI 판단을 기다려야 하는지" 혼란을 초래함.
   - Solution & State Machine UX Design:
     1. [Phase 1: 자율 조사 진행 중 (In-Flight Autonomous Inspection)]:
        - TUI 배너/상태: `[dim]⚡ Autonomous inspection in progress...[/]` (은은한 진행 표시만 유지)
        - `deferred to human` 경고문구, 경고음(Alert Sound), 개입 유도 메시지 일체 노출 금지.
     2. [Phase 2: 자율 판정 종료 & 인간 승인 필요 확정 (Action Required)]:
        - Inspector/Judge가 자체 해결 불가(Gray-Zone / Fail-Closed Denylist)로 최종 결론을 내렸을 때만 전환.
        - 화면에 **진한 굵은 강조(Bold Highlight)** 및 명확한 액션 유도 메시지 노출:
          `🚨 [bold red]▶ Action Required: Gray-zone deferred to Human Review[/]`
          `   [bold white]Cmd:[/] <command>`
          `   [bold yellow]Reason:[/] <최종 자율 판정 실패 및 인간 검토 필요 사유>`
     3. [Phase 3: 자율 판정 통과 시 (Auto-Approved)]:
        - 인간 화면에 어떤 방해/경고도 남기지 않고 조용히 `[green]✔ Auto-Approved[/]` 처리 후 큐 클리어.

[x] [Bug/Audit] 승인 주체(Approver Provenance) 오귀속 수정: 시스템/Gatekeeper LLM 자동 승인과 인간 직접 승인(Human TUI) 엄격 분리 (PR #147 완료, INV-AP-1..6):
   - 해결: `adjudication_log.action` 및 `pending_escalations.approver`에 `⚡ GATEKEEPER` vs `👤 HUMAN` vs `🤖 MACHINE` vs `❓ OTHER` 명확 분리 및 신뢰 프로모션 불변식 확립.

[] [Task/UX] Gatekeeper 인간 승인 요청 메시지 포매팅 및 카피라이팅 혁신 (Designer & Marketer Persona 협업)
   - Context & Problem (사례: OpenCode 대기 중 TUI 모호성 방치 등):
     - 동일 탭 내에서 대상 Pane(OpenCode w1D:p1)은 permission 대기 상태로 멈춰 있는데, TUI는 명시적으로 인간의 승인을 구하지 않고 모호하게 대기하여 인간 지휘관이 "지금 내가 개입해야 하는지, AI가 계속 조사 중인지" 전혀 알 수 없는 심각한 UX 마찰 발생.
   - Designer & Marketer Persona 통합 3단 패널 시각적 연동 설계:
     1. 🚩 [Top Global Banner: 긴급도 즉시 전달]
        - 자율 조사 중: `[dim]⚡ Autonomous inspection in progress...[/]`
        - 인간 개입 필수 확정 시: `🚨 [bold red blink]▶ ACTION REQUIRED: Escalation #<id> Awaiting Commander Decision[/]` (붉은색 강조)
     2. 📡 [Radar Side Panel (Live State Card)]
        - 우측 상단 상태 카드에 실시간 차단 상태 및 대기 주체 명확 표기:
          `Blocked Pane : w1D:p1 (opencode)`
          `Awaiting     : 👤 HUMAN INTERVENTION REQUIRED`
     3. 💬 [Main Chat Area: 구조화된 결재 카드 (Decision Card)]
        - 터미널 채팅 영역 내 명확한 시각적 구분을 위한 박스형 카드 프레임(`╭─`, `│`, `╰─`) 적용.
        - 정보 3단계 청킹(Chunking):
          • 헤더: `🚨 [ESCALATION #<id>] Commander Authorization Required` (경고색/강조 배지)
          • 본문: 타겟 Pane/Agent + 정돈된 실행 명령 스니펫 + 1줄 판정 유보 사유(Gray-zone/Denylist 근거)
          • 액션 바: 승인(Green) vs 거절(Rose) vs 영속허용(Cyan)의 시각적 분리
     4. ⌨️ [Prompt Bar & Quick Action 연동 (Zero-Friction CTA)]
        - 인간 개입 상태 진입 시 TUI 하단 입력창 플레이스홀더 또는 프롬프트에 `/approve <id>` 자동 완성 유도.
        - 지휘관의 결정을 명확히 촉구하는 능동적 카피:
          *"Commander, autonomous inspection cannot guarantee safety. Your authorization is mandatory to resume w1D:p1."*
     5. 📐 [최종 출력 렌더링 목업 (Rich Markdown / ANSI Card)]:
        ```text
        ╭── 🚨 ACTION REQUIRED ────────────────── Escalation #7494 ──╮
        │ 🌐 Target   : w1D:p1 (opencode)                             │
        │ 💻 Command  : git show --stat HEAD | head -12 && ...        │
        │ ⚠️ Reason   : Not in fast-track allowlist (Fail-Closed)     │
        ├─────────────────────────────────────────────────────────────┤
        │ 💡 Gatekeeper Assessment:                                   │
        │   - Complex compound pipeline with mutation risk.           │
        │   - Autonomous clearance impossible; human decision needed. │
        ├─────────────────────────────────────────────────────────────┤
        │ 👉 MANDATORY ACTION (Type to execute):                      │
        │   [✔ Approve]       : /approve 7494                         │
        │   [✖ Reject]        : /reject 7494 [reason]                 │
        │   [🔒 Always Allow] : /allow 7494                           │
        ╰─────────────────────────────────────────────────────────────╯
        ```
     6. Implementation Points:
        - `scripts/tools/schengen_agent_llm.py` 시스템 프롬프트에 위임 시 위 카드 포맷 생성 강제.
        - TUI 채팅 렌더러(`_write_markdown`), 상단 배너 및 사이드 패널의 상태 머신 실시간 동기화.


[x] [Task/Feature] AGY 장문/생략 명령(⋯ lines hidden) 발생 시 `ctrl+g` 전개 및 OpenCode `ctrl+f` 풀스크린 전개 자율 검증 (PR #152 완료, INV-EX-1..5):
   - 해결: `adapter.expand_dialog` 인터페이스를 통해 AGY(`ctrl+g`), OpenCode(`ctrl+f`), Codex(`ctrl+a`) 전개 ➔ 100% 전문 AST 검증 및 자율 승인 완료.












