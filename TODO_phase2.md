## Handoff — Next Pick (맥락 보존 우선순위)
> 세션이 길어 handoff가 필요하므로, 맥락(불변식·@oracle verdict·어댑터 세부)이 보존되어야 더 잘
> 진행되는 이슈를 아래 순서로 picking. 각 항목에 필요한 맥락을 요약해두었다.

1. [Epic 잔여 — 최고 맥락] Fail-closed 편향 전환 M5/M7 (M3 complexity tax 완료 PR #139)
   - M5 origin weighting(INV-12: Origin enum 단일 사용, INJECTED/EMERGENT hard-escalate), M7 anti-fatigue(INV-13).
   - 맥락: INV-1..13 불변식 + @oracle verdict(MODIFY) + 결정 레이어 순서(security_evaluator.py `_audit_static_shell_command`).
   - M3 non-blocking 후속: (1) `2>&1` over-count('&' separator) (2) herestring(`<<<`) under-count (3) 산술확장 over-count (4) `get_complexity_tax_config()` 비-allowlist 명령마다 DB 2회 조회 → read-once 캐시 (5) `complexity_mode='judge'` dead-config(M6 예약).
2. [#137 후속] Stale-event 회귀 테스트(CHANNEL_TTL 3600 + 수술적 `_norm_req_cmd` 안전성 고정)
   - 맥락: opencode.py `_norm_req_cmd`(선행 `$` + 공백 축소만, normalize_command 금지) + `inject_approval` fail-closed.
3. [피어리뷰 후속] #17 footer_is_live / #52 codex 파서 / #45 runtime-path / #33 eviction
   - 맥락: base.py `footer_is_live`, codex.py `Destination`/`File` regex, watcher `_inject_runtime_path`.
4. [Architecture] Persistent Allowlist CUD(#91) + Test Runner Fast-Track(#137 item 3, 이번 세션 구현 중)
   - 맥락: fail-closed allowlist(fast-track closed enum) + TUI /allow /revoke + INV-PL-1..3.
5. [저맥락 — handoff 후에도 무난] Inspector 병렬성(Concurrency 10), UX 상태전이, 카피라이팅, 설정 모달 등.

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
[] Codex `edit_file` 실제 승인(Pane 직접 입력 'y' 또는 TUI /approve) 완료 후에도 Pending에 잔류하는 현상 수정:
  - 현상 및 원인:
    • Codex 모달에서 `Would you like to make the following edits?` 파싱 후 승인(`y` 전송 또는 TUI 승인)이 실행되어 파일 편집이 완료되었음에도, 터미널 뷰포트/스크롤백에 과거 프롬프트 문구가 잔류하거나 다이얼로그 종료 상태가 감지되지 않아 `pending_escalations` 큐에서 RESOLVED로 처리되지 않고 잔류.
  - 해결 방향:
    • `codex_adapter`의 프롬프트 활성 상태 검사 강화: "Would you like..." 문구뿐 아니라 실제 하단 활성 선택지(`› 1. Yes, proceed` 또는 `Confirm: y/n`) 존재 여부를 앵커링하여 이미 완료된 과거 스크롤백 텍스트 오인식 방지.
    • TUI `/approve` 및 pane 직접 `y` 키 입력 후 다이얼로그 해제 감지 시 `resolve_escalation(pane_id, approver=...)` 호출 즉시 보장.
[] [Refactor/Adapter] `footer_is_live` 공용 유틸 안정화 및 엣지케이스 대응 3종 (#17 피어리뷰 후속):
  1) tail window 동적/유연화: `tail_lines=8` 고정값으로 인해 긴 다이얼로그/스피너/줄바꿈 발생 시 실제 live 다이얼로그를 stale로 오판(over-block)하는 갭 해소 (가변 window 또는 footer 역방향 탐색 검토).
  2) marker 잔류 오인식 방지: 종료된 다이얼로그의 footer marker가 8줄 뷰포트에 잔류할 때 여전히 live 상태로 오판하는 이슈 방지 정밀화.
  3) tail window 경계 단위테스트: footer 위치(8줄 vs 9줄 등)에 따른 경계 조건 테스트케이스 추가.

[x] [Bug/Approval] Escalation #1910 & #2339 승인 발화 성공 후 실제 Pane(OpenCode w1D:p1) 명령 미승인 현상 (PR #137 완료):
  - 해결: (1) `approve_escalation` inject-first / record-after 트랜잭션 순서 확립 (2) `inject_approval` unknown-stage fail-closed (3) `_norm_req_cmd` 수술적 정규화 + CHANNEL_TTL 30s→3600s 확장 (4) defer vs hard-failure 에러 구분.
[] [Refactor/Channel] OpenCode 권한 채널 및 테스트 러너 Fast-Track 후속 3종 (#137 피어리뷰 후속):
  1) Stale event 회귀 테스트: '다른 ask 발생, 동일 command string' 상황에서 CHANNEL_TTL 3600 안전성 고정 단위테스트 추가.
  2) `_norm_req_cmd` 공백 붕괴 유의: soft-wrap으로 path/token이 newline 분할될 때의 동작 정합성 및 향후 렌더러 변경 시 주의점 문서화.
  3) Test Runner Fast-Track 허용: `python3 -m unittest` 등 로컬 테스트 러너의 false-positive 과에스컬레이션 방지를 위해 `opencode.jsonc` 좁은 allow 규칙 또는 watcher allowlist 등록.
[] [Task/Allowlist] 단독 실행 읽기 전용 sed(`sed -n '<range>p' <file>`) Fast-Track Allowlist 등록 (#6935 등 Codex 다빈도 패턴):
  - 현상 및 원인:
    • Codex 에이전트가 파일/스킬 문서 열람을 위해 `sed -n '1,260p' /path/to/file`을 빈번히 실행하나, 현재 `security_evaluator.py`의 `READONLY_PIPELINE_COMMANDS`에는 `sed`가 포함되어 있으나 단독 명령 allowlist인 `FAST_TRACK_SAFE_COMMANDS`에는 `sed`가 누락되어 있어 파이프라인(`|`) 없는 단독 `sed -n`이 `NOT_ALLOWLISTED`로 fail-closed 에스컬레이션됨.
  - 안전성 검증 및 Allowlist 등록 조건:
    1) `-n` 플래그 및 `...p` 출력 패턴 확인 (인-플레이스 수정 `-i`, `--in-place` 절대 금지).
    2) 리다이렉트(`>`, `>>`) 및 치환 쓰기 배제 확인.
    3) Sensitive File Denylist (`.env*`, `~/.ssh/*`, `*.key` 등) 및 광범위 와일드카드(`~`, `/`) 차단 불변식(INV-SENS-1/2) 통과 전제.
  - 해결 방안:
    • `security_evaluator.py`의 단독 명령 판정 로직에 읽기 전용 `sed` 패턴(`^sed\s+-n\s+['"][^'"]*p['"]\s+\S+`) 또는 `FAST_TRACK_SAFE_COMMANDS` + in-place 가드 추가.



[] [Task/Architecture] Pane 직접 승인(Pane-Direct Adjudication) 실시간 감지 및 Stale Escalation 자동 해제(Auto-Eviction) 아키텍처 구현:

  - Context & Problem (사례: #2108 등):
    • 사용자가 TUI를 거치지 않고 대상 Pane(AGY/OpenCode/Codex)에서 직접 `1. Yes`나 `y`를 입력하여 승인·진행했음에도, Daemon과 TUI가 이를 실시간으로 감지하지 못해 수 분 동안 `pending_escalations` 큐에 Stale 상태로 잔류하는 현상 발생.
  - Architecture & Solution Design:
    1. Daemon 감시 루프 실시간 상태 검증(Live Revalidation):
       - Herdr `state_change_seq` 변경 또는 매 폴링 시 활성 에스컬레이션 대상 Pane의 실시간 다이얼로그 존재 여부 즉시 재확인.
       - 프롬프트 텍스트가 사라졌거나 에이전트 상태가 `blocked` → `working` / `idle`로 전이된 경우, 즉시 `resolve_escalation(pane_id, resolution="APPROVED", approver="pane-direct")` 호출.
    2. TUI 화면 렌더링 전 Live Slot 검증(Pre-Render Slot Validation):
       - TUI가 인간에게 새 에스컬레이션 모달/배너를 띄우기 직전, 해당 Pane의 실제 다이얼로그 생존 여부를 1회 즉시 조회.
       - 이미 Pane에서 처리되어 사라진 경우, 사용자 화면에 알림을 띄우지 않고 큐에서 즉시 자동 퇴출(Silent Eviction).
    3. Event-Driven State Channel (선택):
       - Herdr 에이전트 상태 이벤트(Status Change Notification)를 리스닝하여 폴링 타이머 대기 없이 즉각적인 큐 클리어 트리거.
[] [Refactor/Eviction] Stale Escalation Eviction 로직 정밀화 3종 (#33 피어리뷰 후속):
  1) 에이전트 상태 문자열 대소문자 무시: `_should_evict_stale_escalation`의 `blocked` vs `working/idle/done` 매칭에 `.lower()` 또는 공용 상태 상수 적용 (Herdr 상태 케이싱 차이로 인한 eviction 누락 방지).
  2) 해소 상태값 표준화 및 검증: `resolve_escalation`의 `RESOLVED` vs `CANCELLED` 처리 경로 일관성 점검 및 `approver="pane-direct"` 다운스트림 정상 연동 확인.
  3) 명령 일치성(Command-Match) 검사 추가: `pane_id` 단독 키 매칭 외에 `raw_command` 동일성 확인을 추가하여, 다이얼로그 내용이 다른 미승인 명령으로 교체된 경우의 오퇴출 방지.
[x] [Bug/SAST] Daemon 실행 환경 PATH 누락으로 인한 SAST(shellcheck/semgrep) Degraded 과에스컬레이션 버그 (PR #132): `_inject_runtime_path()`로 런타임 bin 디렉터리 주입 완료.

[x] [Bug/Adapter] Codex Adapter edit-dialog 포맷 불일치(`Destination:` vs `*** Update File:`)로 인한 Fail-closed 오차단 버그 (PR #133): `Destination:` 및 `File:` 정규식 템플릿 지원 완료.
[] [Refactor/Codex] Codex edit-dialog 파서 정밀화 3종 (#52 피어리뷰 후속):
  1) `Destination:` 우선 요구 및 `File:` 과포괄(다이얼로그 내 임의의 File: 라인 캡처) 방지 정밀 매칭.
  2) `re.IGNORECASE` 적용: 소문자 `destination:` / `file:` 매칭 누락으로 인한 오차단(over-block) 방지.
  3) `edit_file {dests[0].strip()}`의 중복 `.strip()` 제거 정리.
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
     4) [x] package manager (PR #131) 5) [ ] origin weighting(마지막) 6) [ ] cloud judge confidence 상향
    7) [ ] anti-fatigue batch 집계 (INV-13 잔여, 2b)

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

Idea / Research:
[] [Idea] TUI 런타임 핫 리로드(Hot-reloadable) Persistent Allowlist & 동적 Policy CUD 생명주기 관리
   - Context & Problem:
     - 현재 fail-closed 강화(INV-1/2)로 인해 안전하고 반복적인 명령/파일 작업(예: Codex `edit_file`, 워크스페이스 내 빌드·테스트 스크립트 등)도 매번 에스컬레이션되어 에이전트의 자율성(Autonomy) 및 작업 지속성이 저해됨.
     - 특히 Codex `edit_file` 등은 세션 인메모리(transient)에서만 승인되고, 영속적(Persistent) 관점의 룰 관리가 부재함.
     - 인간이 TUI 화면(승인 전/중) 또는 Gatekeeper Tool Call 인터페이스를 통해 영속적 allowlist를 동적으로 정의하고, 데몬 재시작 없이 런타임에 핫 리로드(Hot-reload)할 수 있는 체계가 필요함.
     - 동시에 False Positive로 잘못 승인된 룰을 철회(Revoke)하거나 Stale 룰을 정리할 수 있는 완전한 CUD(Create, Update, Delete) 사이클이 요구됨.
   - Architecture & Key Requirements:
     1. Hot-Reloadable Config & Tool Call Surface:
        - TUI UX: 승인 모달에서 "Always Allow & Persist", 전용 Policy 관리 모달, 또는 Gatekeeper LLM Tool Call(`add_allowlist_rule`, `update_allowlist_rule`, `revoke_allowlist_rule`)을 통해 동적 반영.
        - Runtime Sync: SQLite/JSON 설정 변경 시 Inotify/Watcher 또는 config 버저닝을 통해 데몬/Watcher에 무중단 핫 리로드.
     2. Policy Schema & CUD Lifecycle:
        - Rule Schema: `{ id, pattern/AST, target_agent (all|codex|opencode|agy), scope (repo|cwd|pane|global), action_type (exec|edit_file|network), ttl/expiry, status (ACTIVE|REVOKED), created_by (human-tui|tool), reason, created_at }`
        - Create: 인간 승인 또는 Gatekeeper의 타당성 검증을 거친 영속 룰 생성.
        - Update: 적용 스코프(세션 → repo 전체 등) 확장 또는 조건 조정.
        - Delete / Revoke: False Positive 발생 시 즉시 상태를 REVOKED로 전환하여 fail-closed 에스컬레이션으로 즉시 원복.
     3. Codex `edit_file` & Safe File Mutations 전용 연계:
        - 저장소 내부 안전한 파일 수정 패턴(예: `TODO_*.md`, `docs/*`, 테스트 대상 소스 경로 등)에 대해 AST/경로 검증 후 영속 allowlist 매칭 지원.
     4. Fail-Closed 불변식 (Invariants):
        - INV-PL-1 (Human Provenance): 오직 인간 TUI 입력 또는 인간이 승인한 Gatekeeper Tool Call에 의해서만 영속 룰 CUD 가능 (Untrusted 피감시 에이전트의 임의 룰 주입 원천 차단).
        - INV-PL-2 (Revocation Immediacy): REVOKED 처리된 룰은 모든 캐시/메모리에서 즉시 무효화되어 fallback fail-closed 경로로 진입.
        - INV-PL-3 (Audit Trail): 모든 CUD 변경 이력은 `audit_log` 및 `adjudication_log`에 영구 기록.

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

[] [Task/Architecture] Inspector 비동기 평가 병렬성(Concurrency 10) 확장 & 인간 승인 순차(Sequential) 단일 큐 분리
   - Context & User Observation:
     - [기존 문제점]: 현재 Inspector가 평가를 시작하기만 해도 TUI에 `▶ Escalation Intercepted` 알림/사운드가 발생하여 인간의 작업 흐름을 방해함.
     - 또한 `schengen_watcher` 메인 루프의 순차 동기 처리로 인해 여러 Pane의 평가가 직렬화(Serialization)되어 지연 병목 발생.
   - User Expected UX & Design Requirements:
     1. [Silent Background Inspection]:
        - 명령 인터셉트 시 즉시 TUI에 알림을 띄우지 않고, 백그라운드에서 최대 10개까지 병렬(`ThreadPoolExecutor(max_workers=10)` / `asyncio.Semaphore(10)`)로 AST/SAST/Cloud Inspector 평가 수행.
        - 자율 판정 결과 `AUTO_APPROVED` (Fast-Track / Allowlist / Cloud Safe)인 경우, 인간 개입 없이 즉시 승인 키 전송 및 `audit_log` 기록 (사용자 화면 방해 Zero).
     2. [Sequential Single-Slot Human Adjudication (단일 순차 승인 큐)]:
        - 오직 Gatekeeper/Inspector가 "자체 판정 불가 / 인간 검토 필수(Gray-Zone / Fail-Closed Denylist / Uncertain)"로 최종 결론 내린 건에 한해서만 인간 승인 대기열(`pending_escalations`)로 이관.
        - TUI 화면에는 동시에 여러 알림이 난립하지 않고 **오직 1개의 활성 에스컬레이션 메세지/모달만 순차적(FIFO)**으로 노출.
        - 인간이 현재 노출된 건을 승인/거절 완료하면, 백그라운드 큐/버퍼에 대기 중이던 다음 인간 검토 대상 건이 즉시 화면에 이어서 나타남.
     3. Invariants & Guardrails:
        - INV-CONC-1 (Per-Pane In-Flight Lock): 동일 Pane에 대해 중복/경합 평가 방지.
        - INV-CONC-2 (Silent Autonomous Execution): 자율 승인 가능한 건은 인간 UI(채팅창, 사운드, 모달)에 일체 인터럽트 금지.
        - INV-CONC-3 (Sequential Screen Slot): 화면 활성 승인 프롬프트는 항상 단일 슬롯(Single Slot) 유지, 후속 건은 버퍼 큐에서 대기.
        - INV-CONC-4 (Stale Eviction): 인간이 화면에서 승인하기 전 대상 Pane에서 유저가 직접 처리하거나 상태가 해제된 경우 큐에서 자동 제거.

[] [Task/UX] TUI 채팅 발화 주체 명확화: 시스템 자동 트리거(System/SmartGate)와 인간 지휘관(Commander/User) 프롬프트 분리
   - Context & Problem:
     - 현재 에스컬레이션 발생 시 TUI 내부에서 LLM 조사를 위해 주입하는 합성 프롬프트(`New escalation intercepted...`)가 `👤 You:`로 출력되어, 마치 인간 사용자가 직접 타이핑한 발화처럼 오인되는 UX 혼선 발생.
   - Solution & Design:
     1. 발화 주체(Role) 분리:
        - [인간 입력 (Human Command)]: `21:39:24 👤 Commander:` 또는 `21:39:24 👤 User:` (실제 TUI 인풋 박스에서 엔터로 제출한 경우만)
        - [시스템 내부 트리거 (System Event)]: `21:39:24 ⚡ [System / SmartGate Trigger]:` 또는 내부 합성 프롬프트는 채팅 텍스트로 노출하지 않고 `⚡ Investigating Escalation #XXXX with tools...` 형태의 dim status/badge로만 간결하게 표시.
     2. Implementation Point:
        - `process_user_chat(msg, is_system_trigger=False, origin="commander")` 인자 추가.
        - `is_system_trigger=True`일 때는 `👤 You:` 출력 스킵 혹은 `⚡ [System]:` 전용 스타일 렌더링.

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

[] [Bug/Audit] 승인 주체(Approver Provenance) 오귀속 수정: 시스템/Gatekeeper LLM 자동 승인과 인간 직접 승인(Human TUI) 엄격 분리
   - Context & Problem:
     - PR #125 구현에서 Gatekeeper LLM의 Tool Call에 의한 자동 승인과 인간의 TUI 직접 입력(`/approve`)이 둘 다 `human-tui`로 묶여 기록됨.
     - 이로 인해 실제 인간이 승인하지 않은 시스템/AI 자율 승인 건조차 로그/UI에 `👤 human-tui`로 표기되어 감사 신뢰도 및 상황 파악에 심각한 왜곡 발생.
   - Solution & Provenance Classification:
     1. 세분화된 Provenance 분류 체계:
        - `👤 human` (또는 `human-tui`): 인간 사용자가 TUI 인풋 창에서 직접 `/approve`를 입력하거나 버튼을 클릭한 경우에만 엄격 한정.
        - `⚡ gatekeeper-llm` (또는 `system-agent`): TUI 내 Gatekeeper LLM이 Tool Call(`approve_escalation`)을 통해 자율적으로 승인한 경우.
        - `🤖 machine-guard` (또는 `system-ast`): Watcher 데몬이 Fast-Track AST/Allowlist로 자동 승인한 경우.
        - `❓ other`: PTY 직접 입력 등 출처 불명인 잔여 경로.
     2. Implementation Points:
        - `adjudication_log.action` 및 `pending_escalations.approver` 컬럼에 `gatekeeper-llm` vs `human` 명시적 구분자 저장.
        - TUI Audit Ledger 테이블 및 Detail 모달 배지 갱신:
          • 👤 `HUMAN`
          • ⚡ `GATEKEEPER`
          • 🤖 `MACHINE`
          • ❓ `OTHER`

[] [Task/UX] Gatekeeper 인간 승인 요청 메시지 포매팅 및 카피라이팅 혁신 (Designer & Marketer Persona 협업)
   - Context & Problem (사례: #2348 등):
     - Gatekeeper가 인간 지휘관에게 승인/거절 판단을 요청할 때, 메시지가 평이한 텍스트로 흘러가거나 승인 요청이라는 긴급성과 결정 옵션이 한눈에 들어오지 않음.
   - Designer & Marketer Persona 통합 기획:
     1. 🎨 [Designer Persona: 시각적 계층화 및 박스형 카드 레이아웃]
        - 터미널 채팅 영역 내 명확한 시각적 구분을 위한 박스형 카드 프레임(`╭─`, `│`, `╰─`) 적용.
        - 정보 3단계 청킹(Chunking):
          • 헤더: `🚨 [ESCALATION #2348] Commander Decision Required` (경고색/강조 배지)
          • 본문: 타겟 Pane/Agent + 정돈된 실행 명령 스니펫 + 1줄 판정 유보 사유(Gray-zone/Denylist 근거)
          • 액션 바: 승인(Green) vs 거절(Rose) vs 영속허용(Cyan)의 시각적 분리
     2. 📣 [Marketer Persona: 능동적 카피라이팅 & Zero-Friction CTA]
        - 수동적 서술("조사 완료") 제거 → 지휘관의 결정을 명확히 촉구하는 액션 중심 카피:
          *"Commander, autonomous inspection cannot guarantee safety for this command. Your authorization is required."*
        - 즉시 복사/실행 가능한 간결한 단축 명령어(CTA) 제시:
          • `[✔ Approve]` 👉 `/approve 2348` (또는 `/a 2348`)
          • `[✖ Reject]` 👉 `/reject 2348 [reason]` (또는 `/r 2348 [reason]`)
          • `[🔒 Always Allow]` 👉 `/allow 2348` (영속 allowlist 등록)
     3. 📐 [최종 출력 렌더링 목업 (Rich Markdown / ANSI Card)]:
        ```text
        ╭── 🚨 DECISION REQUIRED ──────────────── Escalation #2348 ──╮
        │ 🌐 Target   : w1D:p5X (agy)                                 │
        │ 💻 Command  : python3 -c "import sqlite3..."                 │
        │ ⚠️ Reason   : Read-only SQLite query on sensitive DB file   │
        ├─────────────────────────────────────────────────────────────┤
        │ 💡 Gatekeeper Assessment:                                   │
        │   - Safe SELECT query observed, but fail-closed on DB file. │
        │   - Zero filesystem mutation risk.                          │
        ├─────────────────────────────────────────────────────────────┤
        │ 👉 TAKE ACTION:                                             │
        │   [✔ Approve]       : /approve 2348                         │
        │   [✖ Reject]        : /reject 2348 [reason]                 │
        │   [🔒 Always Allow] : /allow 2348                           │
        ╰─────────────────────────────────────────────────────────────╯
        ```
     4. Implementation Points:
        - `scripts/tools/schengen_agent_llm.py` 시스템 프롬프트에 승인 요청 시 위 카드 포맷 생성 강제.
        - TUI 채팅 렌더러(`_write_markdown`)에서 카드 테두리 및 액션 바 ANSI 하이라이팅 지원.

[] [Task/Feature] AGY 장문/생략 명령(⋯ lines hidden) 발생 시 `ctrl+g` 전개(Expand)를 통한 전문 자율 검증 체계 구현
   - Context & Problem (사례: #2099 등):
     - AGY 다이얼로그에서 긴 스크립트(`python3 -c ...` 등)가 실행될 때 `⋯ (14 lines hidden)` 형태로 축약되어 표시됨.
     - Gatekeeper/Inspector가 축약된 본문을 다 보지 못해 "Hidden lines were not fully verifiable" 사유로 불필요하게 인간에게 에스컬레이션하거나 전문 확인을 요청함.
   - Key Insight & Architecture:
     1. AGY `ctrl+g` 단축키 자율 전개:
        - AGY 승인 모달은 `ctrl+g` 키를 통해 전체 스크립트를 에디터/전개 모드로 열람 가능.
        - Gatekeeper/Inspector가 `⋯ lines hidden` 감지 시, `herdr agent send-keys <pane_id> ctrl+g`를 자율 호출하여 전체 원문을 읽어오고 파싱.
     2. 완전한 AST/보안 검사 후 자율 승인:
        - 전개된 100% 원문 전체에 대해 AST 파싱, 민감 파일 접근, 위험 명령어 검사를 완결.
        - 안전성이 입증되면 인간 개입 없이 `AUTO_APPROVED` 자율 승인 완료 (에디터 모드 해제 후 `1. Yes` 전송).
     3. Invariants:
        - INV-AGY-1: 축약된 생략 줄(`⋯ lines hidden`)이 존재하는 상태에서 내용 미확인 채로 임의 통과(Fail-Open) 금지.
        - INV-AGY-2: `ctrl+g` 전개 실패 또는 원문 읽기 불가 시에만 안전하게 Fail-Closed 에스컬레이션.










