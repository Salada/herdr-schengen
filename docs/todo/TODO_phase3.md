# Herdr-Schengen Phase 3: Active Execution Roadmap & Backlog

> 본 문서는 Phase 2에서 완결된 마일스톤(PR #126~PR #153)에 이어, 활성 실행 대상인 잔여 과제 및 4-Sprint 로드맵을 관리하는 공식 백로그입니다.

## Handoff — Next Pick (맥락 보존 우선순위)
> 세션이 길어 handoff가 필요하므로, 맥락(불변식·@oracle verdict·어댑터 세부)이 보존되어야 더 잘
> 진행되는 이슈를 아래 순서로 picking. 각 항목에 필요한 맥락을 요약해두었다.
> **🎉 Sprint 1 (P0 버그 일괄), Sprint 2 (관측성 & 인터랙션 극대화), Sprint 3 (코드베이스 위생/테스트 수렴) 전면 완료**
> **👉 [Next Active Pick — 최우선 착수] #3670 Read-Only 체인 진단 명령 Fast-Track 확장 (Narrow Carve-out) / Sprint 4 (대형 동시성 엔진)**

### 🎯 확정된 4-Sprint 진행 로드맵

1. 🎉 **[Sprint 1 — P0 긴급 버그 일괄]** Liveness/Auto-Eviction 정밀화 & OpenCode 다이얼로그 주입 회복 (PR #172 완료 — 628 tests OK / 3 skipped)
   - [x] 1a) `#7771` (AGY) & `#7938` (Codex ppt space) (보안 회귀 최우선, 완료): 어댑터별 `dialog_is_live()` 앵커/가변 윈도우 보강 + TUI pre-render 즉시 승인 방지(Debounce/프로세스 상태전이 가드) ➔ 가짜 `pane-direct` 승인 박멸 (`INV-PD-4/5`, 단위테스트 검증 완료).
   - [x] 1b) `#2800` (블로킹 해소, 완료): TUI pre-render `is_question` 예외 제거 + Watcher QUESTION 소멸 시 auto-evict (`resolution="ANSWERED"`, `sweep_answered_questions` / `test_question_eviction` 10종 검증 완료).
   - [x] 1c) `#3689, #3615, #3623, #3636~#3638` (OpenCode 블로커, PR #172 완료): Dialog Trampoline / TOCTOU 불일치 해소를 위한 Auto-Advance 엔진(`scripts/adapters/auto_advance.py`, `INV-AA-1..9`) 구현 완료 (비동기 지침 큐/디바운스/배치 디퍼 안내 등 보조 UX는 Deferred 백로그로 분리).

2. 🎉 **[Sprint 2 — 관측성 & 인터랙션 극대화]** Gatekeeper 사전 브리핑·동반자적 심의(Disagree & Commit) + Action Required 3단 패널 (PR #178 + PR #179 완료 — 653 tests OK)
   - [x] 2a) **Gatekeeper 사전 복잡도/위험 세그먼트 브리핑 & Disagree & Commit 프롬프팅 (#3864, PR #179 완료)**: 질문 전 복잡도 유발 요인 사전 분해, 단순 질문에 성급한 승인 굴복 방지, 대등한 전문 조언자 스탠스 확립 (`INV-GK-1..8`, 단위테스트 8개 추가).
   - [x] 2b) **Action Required 3단 패널 (PR #178 완료)**: Top Banner(붉은 점멸) + Radar 3-tier 상태 카드(LIVE ESCALATION / GATEKEEPER / BACKGROUND RADAR) + TUI 실시간 연동.

3. 🎉 **[Sprint 3 — 코드베이스 위생 & 테스트 수렴]** 피어리뷰 후속 일괄 수렴 (PR #171 완료 — 606 ran, 3 skipped (미커밋 트리 무결성 게이트 1건은 커밋 후 해소))
   - #139 Complexity / #2555 TestRunner / M6 CloudJudge / #33 Eviction / #45 SAST / #146 Adapter / M7 AntiFatigue / #7207 WorkspacePolicy 전면 완료.
4. ⚙️ **[Sprint 4 — 대형 동시성 엔진]** [EPIC] Parallel Silent Inspection & Single-Slot Deferred UI
   - M1(WAL/Lock) ➔ M2(ThreadPool 10) ➔ M3(DeferredHumanQueue) ➔ M4(Pre-Display Purge).


---

## 🎯 Active Execution Backlog

[x] [P0/Docs] 전체 문서 전수조사, ADR Superseded 표기 및 `docs/index.md` 마스터 색인 체계 구축 (Issue #166, PR #169 + commit 7a9e860 완료):
  - Forgejo Issue: [Issue #166](http://192.168.10.102:3000/InhouseOriented/herdr-schengen/issues/166)
  - 완료 내역: PR #169(디렉터리 5개 서브폴더 재구성, README 다이어트, docs/index.md 마스터 색인 체계, ADR 상태 메타데이터) + commit `7a9e860`(ADR-014 master index 누락 보강).






[x] [Bug/Question] Pane 질문(decision_layer='QUESTION') 답변 완료 후에도 TUI 상단 배너 및 Pending 큐에 영구 잔류하는 현상 수정 (사례: #2800, PR #146 등 구현·테스트 완료):

  - 대원칙: **Question에는 명령과 같은 '승인/거절(resolve)' 상태가 없음** (단순히 인간이 Pane에서 직접 타이핑/엔터하여 다이얼로그가 사라지면 큐에서 자동 제거/소멸되어야 하는 대상).
  - 현상 및 원인 (사례: Escalation #2800 Codex 질문 등):
    • 에이전트가 사용자에게 질문(`Question 1/1 ...`)을 하여 `decision_layer='QUESTION'`으로 에스컬레이션된 후, 사용자가 해당 Pane에서 직접 답변을 완료했음에도 TUI 상단 배너와 `pending_escalations` 큐에서 제거되지 않고 계속 Pending 상태로 고착됨.
    • 근본 원인:
      1) `schengen_tui.py`: `pre-render slot validation`에서 `if not is_question`으로 `QUESTION` 레이어를 의도적으로 제외하여, TUI 렌더링 시 다이얼로그 소멸 검사 및 Auto-Eviction이 전혀 발동하지 않음.
      2) `schengen_watcher.py`: `pane_direct_maybe_evict`가 `not is_safe`인 UNSAFE 에스컬레이션만 검사(`is_safe=True`인 QUESTION은 제외)하여 데몬 루프에서도 소멸 감지 누락.
      3) Cross-Workspace/Idle 감시 갭: 감시 대상이 아닌 워크스페이스/Pane이거나 답변 후 에이전트가 즉시 다음 작업/idle로 전이될 때 `not req_cmd` 트리거가 유실됨.
  - 조치 및 검증 상태:
    • `sweep_answered_questions`, `resolve_cleared_dialog`, 어댑터별 `question_is_live` 구현 및 `tests/test_question_eviction.py` (INV-Q-1..5) 10종 단위테스트 검증 완료.
  - 해결 방향 (최저 난이도 / 최소 변경):
      1) `schengen_watcher.py`: `decision_layer == "QUESTION"` 에스컬레이션에 대해 어댑터의 질문 다이얼로그(header/footer)가 소멸되었거나 에이전트가 `blocked`를 벗어난 경우 즉시 큐에서 해소/제거(`resolve_escalation` 또는 `status=RESOLVED, approver="pane-direct"` / `resolution="ANSWERED"`).
      2) `schengen_tui.py`: `pre-render slot validation`에서 `is_question` 예외를 제거하고, `adapter.dialog_is_live(pane_text) == False`일 때 즉시 큐에서 자동 퇴출(Silent Eviction)하여 상단 배너 고착 해소.



[] [Bug/OpenCode] OpenCode 승인 시 `_norm_req_cmd` 불일치(뷰포트 절단 및 access_directory 경로 차이)로 인한 키 주입 실패 & DB 상태 불일치 (사례: #3143, #3219 — OPEN 유지):
  - 현상 및 원인 (사례: Escalation #3143 Git 커밋 & Escalation #3219 `access_directory`):
    • Gatekeeper LLM이 승인(`APPROVE`)하여 DB 상에는 `status='RESOLVED', resolution='APPROVED', approver='gatekeeper'`로 기록되었으나, 실제 OpenCode 터미널은 `Permission required` 모달 상태로 계속 멈춰 있어 승인이 해소되지 않는 현상 반복 발생.
    • 근본 원인 (2가지 불일치 유형):
      1) **사례 #3143 (장문 커밋 절단)**: 원문 `req_cmd`는 다줄 Heredoc 전체(~800자)이나, 터미널 뷰포트에서는 화면 크기 한계로 커밋 본문 중간이 잘린 채 렌더링되어 `live_req`가 절단된 문자열로 추출됨.
      2) **사례 #3219 (구조화 이벤트 vs 시각 다이얼로그 경로 표현 차이)**: 구조화 채널 `req_cmd`는 파일 절대경로(`/path/to/scripts/cmd/schengen_tui.py`)인 반면, 터미널 화면상 `live_req`는 상위 디렉터리(`~/code/.../scripts/cmd` 또는 glob `.../scripts/cmd/*`)로 렌더링되어 문자열 불일치 발생.
      3) **결과**: `_norm_req_cmd` 비교 실패로 `inject_approval`이 `(False, INJECT_SKIP_CHANGED)`를 반환하고 실제 `enter` 키를 전송하지 못함. 그럼에도 상위 승인 로직은 DB를 `RESOLVED`로 전이시켜 심각한 상태 불일치 초래.
  - 해결 방안:
    1) Prefix 및 상위/하위 경로 포괄 매칭: `live_req`가 `req_cmd`의 Prefix이거나, `access_directory`의 경우 파일 경로의 상위 디렉터리와 매칭 시 동일 요청으로 인정.
    2) `ctrl+f` 풀스크린 전개 연동 (PR #152 `expand_dialog` 활용): 절단 의심 시 `ctrl+f`로 전개 후 재비교.

[x] [P0 Blocker/OpenCode] OpenCode 연쇄 명령 다이얼로그 전이(Dialog Trampoline) 및 Auto-Advance 회복 (사례: #3615, #3623, #3636~#3638, #3689, PR #172 완료):
  - 현상 및 원인 (사례: #3615, #3623, #3636~#3638, #3689):
    • Gatekeeper/TUI에서 승인 판정(`APPROVE`)을 내렸음에도 OpenCode 터미널 화면이 후속 명령 다이얼로그로 즉시 전이되면서 키 입력이 유실/불일치(`INJECT_SKIP_CHANGED`)되어 에이전트 오케스트레이션 루프가 멈추는 현상 발생.
  - 해결 및 검증 (PR #172):
    • `scripts/adapters/auto_advance.py` 신규 모듈 및 `INV-AA-1..9` 불변식 체계 구축 완료.
    • 전체 evaluator(AST/denylist/gray-zone/SAST) 재평가, prior-approval 상속 금지, max hop/deadline 바운드, provenance=`machine/auto-advance`, watcher 감사트루스(`INV-AA-8`: verified inject 후에만 `AUTO_APPROVED`, deferral은 `AUTO_DEFERRED`). (628 tests OK / 3 skipped)

[] [Deferred/OpenCode] OpenCode 보조 지침 전달 큐, 다이얼로그 디바운스 및 배치 Defer UX 개선 (#3615/#3623/#3636 후속):
  - 1) **지침 전달 큐 (Instruction Queue)**: Bubble Tea 모달 상태에서 `send-text` 무효화 대응을 위해 모달 닫힘 이후(실행 재개/명령 완료 시점) 지침 주입 비동기 딜레이 큐 연동.
  - 2) **플러그인 IPC 확장**: OpenCode 플러그인 레벨에서의 지침 전달 채널 확장 (`opencode_permissions` IPC 연계).
  - 3) **다이얼로그 디바운스**: 연쇄 명령 다이얼로그 연속 발생 시 뷰포트 안정화 디바운스.
  - 4) **Batch Approval Defer 가이드 & Sweeper 로그**: `/approve-batch` 실행 시 화면 전이로 인해 `deferred`된 ID에 대한 친절 안내 문구 및 백그라운드 Sweeper(`pane-direct`) 전이 로그 가시화.





[x] [Provenance] human opinion vs gatekeeper adjudication 분리 (PR #177 완료, 857965b; TUI 표시 회귀 핫픽스 PR #181, PR #182 완료):
  - 대원칙 & 해결 상태:
    • `adjudication_log` 테이블에 `approver` 및 `human_note` 컬럼 가법 마이그레이션 적용.
    • `record_human_opinion`, `has_human_opinion`, `get_adjudication_exchange` 신규 API 추가.
    • `/approve`, `/reject` 시 인간 의견(opinion-first) 분리 기록 및 배치 승인 시 `human_note` 보존.
    • `AuditFullscreenModal` 내 인간 의견-Gatekeeper 판정 교환(Exchange) 표시 연동.
    • `INV-HO-1..6` 불변식 확립 및 12개 단위테스트 추가 (총 646 tests OK, 3 skipped).
    • **TUI 표시 회귀 2건 핫픽스 완료 (#181, #182)**:
      1) `#181`: `AuditDetailModal` 결재 내역 `[by {...}]` malformed Rich markup (`MarkupError`)을 plain `"by "`로 수정.
      2) `#182`: `rich_escape`의 bare 대괄호/백슬래시 파싱 결함 수정 (전체 `[` 이스케이프 + 백슬래시 이중화 제거).
      3) 회귀 단위테스트 3종 추가 검증 완료 (`test_adjudication_exchange_line_plain_by_prefix`, `test_rich_escape_escapes_bare_brackets`, `test_rich_escape_preserves_backslashes`).


[] [Deferred/Provenance] `get_adjudication_exchange` / `has_human_opinion` 프로덕션 모달 전면 연동 (PR #177 후속):
  - Context: PR #177에서 정의·테스트된 신규 exchange 조회 헬퍼가 현재 프로덕션 모달의 `get_adjudications_for_audit`와 부분 분리되어 있음.
  - Solution: future-facing 주석 처리 또는 프로덕션 감사 모달 전체를 exchange 뷰로 일원화 전환 검토. (Non-blocking Deferred)

[x] [Bug/DB] `enqueue_pending_escalation` ON CONFLICT 시 `resolution` 및 `approver` 미초기화 버그 (사례: #3159, PR #175 완료):
  - 현상 및 원인 (사례: Escalation #3159 Codex `w1N:p1` 빌드 명령):
    • 동일 Pane에서 과거에 승인된 동일 명령이 재실행되어 에스컬레이션될 때, DB 레코드가 `status='PENDING'`으로 갱신되면서도 이전 승인 이력인 `resolution='APPROVED', approver='pane-direct'`가 `NULL`로 리셋되지 않고 그대로 잔류.
  - 해결 및 검증 (PR #175):
    • `enqueue_pending_escalation`의 `ON CONFLICT(pane_id, command_hash) DO UPDATE SET` 구문에 `resolution = NULL, approver = NULL, delivered_at = NULL` 명시적 초기화 추가.
    • 회귀 단위테스트 `test_re_enqueue_resets_resolution_approver` 추가 (총 634 tests OK, 3 skipped).



[x] [Idea/Architecture] Question 분리 처리: 커맨드 에스컬레이션 큐 비차단(Non-blocking) & 사이드바/힌트 버튼 기반 Pane 점프 분리 (기구현 검증 완료):
  - 대원칙 & 해결 상태:
    • Question은 TUI에서 승인/거절할 수 없고 사용자가 해당 Pane에서 직접 입력해야 하므로 커맨드 결재 슬롯을 비차단(Non-blocking) 격리.
    • `INV-QN-1/2` 불변식: Question 에스컬레이션은 메인 결재 슬롯을 점유하지 않고 백그라운드 힌트/Radar 배지로 표시.
    • 사이드바 힌트 배지 + `/jump <pane_id>` 및 마우스 클릭 포커스 전환 연동.
    • 사용자가 해당 Pane에서 답변 시 `sweep_answered_questions` / `dialog_is_live == False` 감지를 통해 무음 자동 소멸.

[x] [Refactor/Adapters] Codex 및 AGY 다이얼로그 앵커 liveness 한정 주석 명시 2종 (#146 피어리뷰 후속, PR #171 완료):
  1) Codex 앵커(digit) 확대는 liveness-only 전용: 향후 옵션 번호 -> 승인/거절 매핑 시 '1=Yes' 가정 금지 주의.
  2) AGY 앵커(digit) liveness-only 주석 명시: liveness 검사 외 다른 용도로의 전용 방지.

[x] [Refactor/Eviction] Stale Escalation Eviction 로직 정밀화 3종 (#33 피어리뷰 후속, PR #171 완료):
  1) 에이전트 상태 문자열 대소문자 무시: `_should_evict_stale_escalation`의 `blocked` vs `working/idle/done` 매칭에 `.lower()` 또는 공용 상태 상수 적용 (Herdr 상태 케이싱 차이로 인한 eviction 누락 방지).
  2) 해소 상태값 표준화 및 검증: `resolve_escalation`의 `RESOLVED` vs `CANCELLED` 처리 경로 일관성 점검 및 `approver="pane-direct"` 다운스트림 정상 연동 확인.
  3) 명령 일치성(Command-Match) 검사 추가: `pane_id` 단독 키 매칭 외에 `raw_command` 동일성 확인을 추가하여, 다이얼로그 내용이 다른 미승인 명령으로 교체된 경우의 오퇴출 방지.

[x] [Task/Dependency] semgrep 필수 디펜던시(Required Dependency) 체계적 관리 및 자동화 완결 (PR #174 완료, e61187f + 7abf941):
  - 완료 내역:
    1) `pyproject.toml`에 `semgrep>=1.70.0` 명시적 필수 디펜던시 선언.
    2) `scripts/core/security_evaluator.py`: Host Runtime Gate에서 semgrep 부재 시 fail-closed hard-fail(`INV-2`) 및 설치 가이드 안내.
    3) `.forgejo/workflows/` CI 테스트 환경에 semgrep 설치 단계 공식화.
    4) 단위테스트 환경 독립성 확보: `test_opencode_plugin_gating` mock 보강 (총 630 tests OK).


[x] [Refactor/SAST] `_inject_runtime_path()` 및 Host Runtime Gate 안정화 4종 (#45 피어리뷰 후속, PR #171 완료):
  1) `_inject_runtime_path()` 선행순서 버그 수정: `parts.insert(0, d)` 반복으로 `~/.local/bin`이 최우선순위가 되어 Homebrew 바이너리를 섀도잉(shadow)할 위험 해소 (reverse iteration 또는 시스템/Homebrew 우선순위 보존).
  2) 빈 PATH 항목(`.`) 처리: `os.environ["PATH"].split(":")` 필터 시 빈 항목 drop 동작 정리 및 명시적 문서화.
  3) 플랫폼 가드: `_RUNTIME_BIN_DIRS`에 macOS 전용(`/opt/homebrew`, `/usr/local`) 외 `sys.platform` 분기 및 Linux 경로 지원.
  4) 실행 순서 최적화: `SAST telemetry print`가 host-runtime gate 검증 완료 후 출력되도록 순서 조정.

[x] [Refactor/Complexity] Complexity Tax 정밀화 및 DB 쿼리 최적화 5종 (#139 피어리뷰 후속, PR #171 완료):
  1) `2>&1` over-count 보정: `&`가 분리자로 취급되어 `ls 2>&1`이 3점으로 과계산되는 엣지케이스(`n>&m` 리다이렉션 특수처리) 보정.
  2) Herestring(`<<<`) under-count 보강: `_COMPLEXITY_REDIR_RE`에 `<<<` 리다이렉션 패턴 추가.
  3) 산술확장(`$((...))`) vs 커맨드 치환(`$(...)`): 산술확장이 커맨드 치환으로 오인식되어 과계산되는 갭 정밀화 (fail-closed 무해).
  4) `get_complexity_tax_config()` in-memory 캐싱: 비-allowlist 명령마다 SQLite `init_db` 및 `SELECT` 2회 반복 조회를 1회 캐시/read-once로 최적화.
  5) `complexity_mode='judge'` 모드 M6 Cloud Judge 라우팅 연계 완료.

[x] [Refactor/CloudJudge] Cloud Judge Confidence & Complexity Mode 안정화 4종 (M6 피어리뷰 후속, PR #171 완료):
  1) Judge 모드 gray-zone guidance(`format_decision_guidance`) 유실 방지: judge-mode context 병합 검토.
  2) Cloud-Judge 캐시 키에 `confidence_threshold` 포함: 런타임 threshold 변경 시 TTL 만료 전까지 스테일되는 현상 방지.
  3) `set_cloud_judge_config` clamp 하한선 상향: 0.5 하한이 약하므로 0.7 상향 검토.
  4) LLM Inspector(`audit_dynamic_substitution_with_llm`)의 의도적 confidence 무-게이트 범위 명문화.

[x] [Refactor/TestRunner] Test Runner 파이프라인 정규식 대칭화 2종 (#2555 피어리뷰 후속, PR #171 완료):
  1) fd-redirect 스트립 대칭화: `2>&1` 외 `1>&2`, `&>` 미커버 갭 해소.
  2) 공백 포함 엣지케이스: `2 >&1` 등 스페이스 포함 시 미스트립(over-block) 방어.
  3) **[보안 갭 폐쇄 (INV-5/6)]**: Test Runner 체인 정규식 대칭화 과정에서 `pytest 2>&1 && rm -rf /`와 같은 메타문자 체인이 fast-track으로 빠져나가던 기존 보안 갭을 완전 차단.

[] [Refactor/TestRunner] 안전한 read-only 체인 진단 명령 Fast-Track 확장 (사례: #3670 후속 백로그):
  - 현상 및 요구사항:
    • 에이전트들의 일상적인 검증/진단용 안전 체인 명령(`cd <worktree> && python3 -m unittest discover -s tests 2>&1 | tail -30`, `git status --short && echo "..." && git diff --stat`)이 `NOT_ALLOWLISTED`로 인간 승인을 매번 요구하여 피로도 유발.
    • `cd <safe_dir> && <safe_runner>` 결합 체인 및 `| tail -N` / `| head -N` 안전 파이프라인의 Fast-Track / Test-Runner 인정 규칙 정밀화.
  - **[INV-5/6 긴장 명시 및 Narrow Carve-out 요건]**:
    • 주의: INV-5/6 불변식은 Fast-Track에서 셸 메타문자(`|`, `&`, `;`, `&&`, `||`)를 원칙적으로 거부함. #2555(item 3)에서 `pytest 2>&1 && rm -rf /` 우회 갭을 fail-closed로 엄격 차단한 보안 원칙과 정면 충돌하지 않아야 함.
    • 따라서 단순 메타문자 허용이 아닌, **"모든 세그먼트가 엄격히 검증된 read-only 체인인 경우에만 한정 허용 + sensitive path 및 변이(mutating) 세그먼트 즉시 재거부"**하는 좁은 예외(Narrow Carve-out) 모델만 적용.
    • 구현 힌트: `security_evaluator.py:1118` `_is_read_only_pipeline` 확장 검토 (read-only 세그먼트만 파싱·검증, `&& rm -rf` 등 변이 세그먼트 탐지 시 fail-closed 에스컬레이션).


[x] [Refactor/AntiFatigue] Anti-Fatigue 배치 집계 및 동의 품질 개선 4종 (M7 피어리뷰 후속, PR #171 완료):
  1) 배치 배너 raw 명령 목록 표시: quoted string/path 축약 패턴 대신 실제 raw 명령 목록을 표시하여 사용자 동의 품질 개선.
  2) 실패-inject 경로 회귀 테스트 추가: 키 주입 실패 시의 롤백 및 에러 핸들링 단위테스트 작성.
  3) Novelty `cwd` 차원 제거 트레이드오프 문서화: 스코프가 pane-only로 확장됨에 따른 영향 정리.
  4) `reject_batch` OpenCode 거절 플로우 연계: bare escape 대신 에이전트별 reject 프로토콜 연동.

[x] [Refactor/WorkspacePolicy] Workspace `.schengen/` 정책 신뢰스토어 검증 3종 (#7207 피어리뷰 후속, PR #171 완료):
  1) INV-WS-3 Origin 게이트 연동: watcher의 INJECTED/EMERGENT origin 생산 연동.
  2) 신뢰 스토어 agent-writable 방어: read-time 위치 파생 `workspace_root` 검증으로 에이전트의 임의 룰 변조 차단.
  3) 경로 포함 exec 프로모션 차단 명문화: 절대경로 거부 동작 문서화.

[] [Deferred/ConfigCache] `get_complexity_tax_config()` 프로세스-로컬 캐시 무효화 및 런타임 동기화 (#171 후속 피어리뷰 제안):
  - Context: PR #171에서 적용된 read-once 메모리 캐시는 프로세스 단위로 동작하여, TUI에서 임계치(Threshold)를 변경하더라도 Watcher 데몬 프로세스가 SIGHUP 리로드 전까지 변경사항을 즉시 인지하지 못함.
  - Solution: 짧은 TTL (예: 5~10s) 도입, SIGHUP/인메모리 invalidate 연동 또는 동기화 문서화. (Non-blocking Deferred)

[] [Idea/Complexity] 단순 체인 길이/구문 횟수 기반을 넘어선 현실적·시맨틱 복잡도(Semantic Risk & Multi-Factor Complexity) 산정 체계 연구 및 재설계:
  - Context & Core Problem:
    • 현재 `Complexity Tax`는 연산자 수(`&&`, `|`, `;`), 서브쉘, 리다이렉션(`2>&1`) 등의 **구문적 토큰 개수(Syntactic Count)**만 단순 합산하여 복잡도 점수(`complexity score`)를 매김.
    • 이로 인해 실제로는 극히 안전한 진단/조회 체인(`git checkout && git pull --ff-only && git log && echo "..." && shasum ...`)이 토큰 수 누적으로 과도한 패널티(`complexity=19 > 6`)를 받아 불필요하게 에스컬레이션됨.
    • 반면, 길이는 짧으나 시스템 변이 위험이 치명적인 명령(`sudo dd ...` 또는 `rm -rf /dir && curl ... | sh`)은 구문 점수 자체는 낮게 계산될 수 있는 구조적 맹점 상존.
  - Reality-Based Complexity Multi-Factor Model (현실적 복잡도 다차원 모델):
    1. **세그먼트별 시맨틱 변이 가중치 (Segment Mutation Weighting)**:
       - 단순 연결자(`&&`, `|`) 횟수 1:1 선형 가산 대신, 체인을 이루는 각 세그먼트의 본질적 행위(Verb / Action)에 따른 차등 가중치:
         • Read-Only / Diagnostic (`git status/log/diff`, `cd`, `echo`, `shasum`, `tail`): 가중치 0 ~ 0.5 (복잡도 기여 극소화).
         • Non-destructive VCS Sync (`git checkout`, `git pull --ff-only`): 가중치 1.0.
         • Mutating / Destructive (`rm`, `rsync`, `worktree remove`, `kill`, `chmod`): 가중치 3.0 ~ 5.0 (위험 변이 집중 부과).
    2. **컨텍스트 독립성 및 파이프라인 안전성 (Pipeline Safety Context)**:
       - 출력 제어용 꼬리 파이프(`| tail -N`, `| head -N`, `| grep pattern`, `2>&1`)는 복잡도 가산 면제 또는 감면.
       - 반복문(`for ...; do ...; done`) 및 임의 문자열 치환(`eval`, `xargs`) 등 비결정적 흐름 제어 구문에만 고위험 복잡도 부여.
    3. **복잡도 임계치 다단계화 (Tiered Complexity & Routing)**:
       - 단순 `score > threshold` -> 즉시 Human Escalation 대신:
         • Low-risk Read Chain (누적 점수 높아도 변이 세그먼트 0건): Cloud Judge 또는 Fast-Track 경로로 흡수.
         • High-risk Compound Chain (변이 세그먼트 포함 + 높은 구문 결합도): 인간 에스컬레이션 및 사전 브리핑 강화.
  - Action Items:
    • `scripts/core/security_evaluator.py` 내 `calculate_complexity_score`의 가중치 테이블 및 AST 세그먼트 분류 로직 PoC/벤치마크 설계.



[] codex 지원 잔여: network/edit 등 템플릿 live 검증, reject 경로, Ctrl+A fullscreen long-command 경로.

[] 비가역적 상태의 위험성이 있는 command에 대한 research
- make
- kubectl
- magick (ImageMagick): 에셋 생성/변환 활동의 Fast-Track 적합성 분석
  • 기획 분석: 생성 활동(이미지 변환, 리사이징 등)은 기본적으로 생산적이나, 임의 파일 덮어쓰기(Overwrite) 및 델리게이트 취약점(MSL/HTTPS/Ghostscript) 리스크 상존.
  • 권장 방안: 전역 무조건 Fast-Track 대신, (1) 안전 확장자(.png/.webp/.svg 등) 한정 (2) 민감 파일 Denylist(INV-SENS-1/2) 가드 (3) 프로토콜 델리게이트 차단 조건부 패턴 또는 `#7207 Workspace .schengen/` 자동 프로모션 활용.
- 그외에 이런 ruleset을 잘 관리할수있는 별도 파일 포맷으로 체계를 가지고 조사하는게 좋을지 조사- make

[x] [EPIC] Fail-open → fail-closed 편향 전환 + 패키지 매니저 인식 (@oracle 검토 verdict: MODIFY — M1~M7 전면 완결, PR #126~#144)
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

[] context compact 구현

[] test code를 source code와 동일한 folder구조를 가지거나, (Most recommanded) Python 관례상 가장 best practice가 되도록 테스트 코드 위치가 수정되도록 refactor

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

[x] [Task/UX] TUI 토글/설정 옵션 전용 윈도우(Settings Modal) 분리 및 첫 화면(Main/Sidebar) 핵심 상태 직관화 (PR #173 완료, 91bb4d2):
   - 완료 내역:
     1) 첫 화면 정리: `Guard Daemon` 및 `Leader Mode` 핵심 2개만 노출하여 메인 뷰포트 시각적 노이즈 최소화.
     2) `SettingsModal` 분리: `Instruction Delivery`, `Answer Language`, `Channel Approve` 이전 및 `Automation` 그룹(Batch, Origin Weighting, Pane-Direct) 토글 신설.
     3) 진입 경로: `^s` 단축키, `[⚙ Settings]` 버튼, `/settings`, `/config` 슬래시 커맨드.
   - 주의/후속: `Approval Bias` 및 `Fast-Track Mode`는 `guard_config` 키 부재로 1차 미포함 ➔ 아래 후속 백로그로 관리.

[] [Deferred/TUI] `SettingsModal` 내 `Approval Bias` 및 `Fast-Track Mode` 설정 토글 연동:
   - Context: `guard_config` 테이블 내 bias/fast-track 전용 키 선행 정의 후 `SettingsModal` 라디오/스위치 연동.



[x] [Task/UX] 에스컬레이션 배너/메시지 타이밍 및 상태 전이 명확화: Phase-1 In-flight IPC & Phase 2b 인간 개입 gating 완결 (PR #161 & PR #167 완료, INV-PH1-1..6 / INV-HR-1..6):
   - 해결 (PR #161 & PR #167):
     1) **Phase-1 in-flight IPC**: inspector 평가 진행 중(escalation 전) 상태를 JSON 상태파일(`in_flight_state.json`, 단일 writer 원자적 쓰기 + STALE_TTL 30s)로 TUI에 노출 (PR #161).
     2) **2단계 Phase 구분**: `🔍 Inspector: checking`(dim, 결정론적 AST ms 단위) vs `🤖 Gatekeeper: judging`(dim magenta, LLM/cloud-judge 초 단위) 시각 분리 (PR #161).
     3) **Phase 2b 인간 개입 확정 시만 카드 노출**: Human Authorization Required 카드가 judge(게이트키퍼 LLM) 조사 완료 후 인간 개입이 정말 필요한 최종 단계에서만 노출되도록 gating (`INV-HR-1/2`, PR #167).
     4) **시스템 라벨 정돈**: judge 호출 프롬프트가 "You:"가 아닌 "Inspector -> Gatekeeper:" 시스템 라벨로 명확화 (`INV-HR-3`, PR #167).
     5) **Flat 텍스트 복사성 개선**: Decision card가 command/reason을 손쉽게 copy-paste 가능한 flat 텍스트로 재설계(박스 테두리 제거) (`INV-HR-6`, PR #167).
     6) **불변식 & 테스트**: INV-PH1-1..6 및 INV-HR-1..6 불변식 확립, 단위테스트 14종 추가 (총 560 OK).




[x] [Task/UX] Gatekeeper 인간 승인 요청 메시지 포매팅, 사전 복잡도 설명 및 동반자적 심의(Disagree & Commit) 프롬프팅 혁신 (사례: #3864, PR #178, PR #179, PR #180 완료):
   - 해결 및 검증 (PR #178 + PR #179 + PR #180):
     1) **2a (#3864, PR #179 & PR #180)**:
        - 질문 전 복잡도 유발 요인 사전 분해 및 브리핑 (`STEP 0` 무조건 실행).
        - `guard_config.approve_advisory` 옵션화 (default: `false`, human-only write):
          • `false`(기본값): `STEP 3 HUMAN DIRECTIVE` (인간 `/approve` 즉시 집행, direct mandate).
          • `true`: `STEP 3 DISAGREE & COMMIT` (인간 `/approve` 조언적 수용, Gatekeeper 소신 거절 권고 가능).
        - 불변식 `INV-GK-1..8` 및 `set_approve_advisory_config` API 구축.
     2) **2b (PR #178 & 486832d)**:
        - Top Banner(붉은 점멸) + Radar 3-tier 상태 카드(LIVE ESCALATION / GATEKEEPER / BACKGROUND RADAR).
        - 맥락별 라벨 정밀화: tier-1 `Inspecting Pane` (PR #178), tier-2 `Judging Pane` (commit 486832d).
     3) **거버넌스 & 아키텍처 문서화**: 승인 시맨틱스(/approve vs /approve-batch) 및 session-pattern 제거 fail-closed 의도 문서화 완료.

[] [Deferred/TUI] `SettingsModal` (Automation 카테고리) 내 `approve_advisory` 토글 스위치 연동 (PR #180 후속):
   - Context: PR #180에서 `set_approve_advisory_config` 백엔드 API 및 DB 저장이 완료되었으나, TUI `SettingsModal` Automation 섹션에 UI 토글 스위치 미연결 상태.
   - Solution: SettingsModal Automation 카테고리에 `Approve Advisory Mode` On/Off 토글 추가.



