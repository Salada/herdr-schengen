# Herdr-Schengen Phase 3: Active Execution Roadmap & Backlog

> 본 문서는 Phase 2에서 완결된 마일스톤(PR #126~PR #153)에 이어, 활성 실행 대상인 잔여 과제 및 4-Sprint 로드맵을 관리하는 공식 백로그입니다.

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

## 🎯 Active Execution Backlog (24 Items)

[] [P0/Docs] 전체 문서 전수조사, ADR Superseded 표기 및 `docs/index.md` 마스터 색인 체계 구축 (Issue #166, OpenCode 위임):
  - Forgejo Issue: [Issue #166](http://192.168.10.102:3000/InhouseOriented/herdr-schengen/issues/166)
  - 상세 실행 지침:
    1) 디렉터리 재배치: `docs/adr/`, `docs/guides/`, `docs/archive/` 생성, 모든 `docs/adr-*.md` 이동, `TODO.md` -> `docs/archive/TODO_phase1.md`, `bloat_message_opencode.md` 이동, `docs/setup*.md` 및 `github-mirror.md` -> `docs/guides/` 이동.
    2) ADR 전수조사: 13개 ADR 상단에 상태 메타데이터(`Active` vs `Superseded / Evolved`: ADR-006, ADR-011) 명시 및 상대 경로 일괄 보정.
    3) `docs/index.md` 마스터 색인 작성: 4대 카테고리 매트릭스, 1줄 핵심 요약, 관련 소스코드 경로 색인으로 LLM 탐색 토큰 소모 최소화.
    4) 테스트: `HERDR_ENV=1 python -m unittest discover -s tests` 통과 확인 후 PR 발행.

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
      1) `schengen_watcher.py`: `decision_layer == "QUESTION"` 에스컬레이션에 대해 어댑터의 질문 다이얼로그(header/footer)가 소멸되었거나 에이전트가 `blocked`를 벗어난 경우 즉시 큐에서 해소/제거(`resolve_escalation` 또는 `status=RESOLVED, approver="pane-direct"` / `resolution="ANSWERED"`).
      2) `schengen_tui.py`: `pre-render slot validation`에서 `is_question` 예외를 제거하고, `adapter.dialog_is_live(pane_text) == False`일 때 즉시 큐에서 자동 퇴출(Silent Eviction)하여 상단 배너 고착 해소.


[] [Bug/OpenCode] OpenCode 승인 시 `_norm_req_cmd` 불일치(뷰포트 절단 및 access_directory 경로 차이)로 인한 키 주입 실패 & DB 상태 불일치 (사례: #3143, #3219):
  - 현상 및 원인 (사례: Escalation #3143 Git 커밋 & Escalation #3219 `access_directory`):
    • Gatekeeper LLM이 승인(`APPROVE`)하여 DB 상에는 `status='RESOLVED', resolution='APPROVED', approver='gatekeeper'`로 기록되었으나, 실제 OpenCode 터미널은 `Permission required` 모달 상태로 계속 멈춰 있어 승인이 해소되지 않는 현상 반복 발생.
    • 근본 원인 (2가지 불일치 유형):
      1) **사례 #3143 (장문 커밋 절단)**: 원문 `req_cmd`는 다줄 Heredoc 전체(~800자)이나, 터미널 뷰포트에서는 화면 크기 한계로 커밋 본문 중간이 잘린 채 렌더링되어 `live_req`가 절단된 문자열로 추출됨.
      2) **사례 #3219 (구조화 이벤트 vs 시각 다이얼로그 경로 표현 차이)**: 구조화 채널 `req_cmd`는 파일 절대경로(`/path/to/scripts/cmd/schengen_tui.py`)인 반면, 터미널 화면상 `live_req`는 상위 디렉터리(`~/code/.../scripts/cmd` 또는 glob `.../scripts/cmd/*`)로 렌더링되어 문자열 불일치 발생.
      3) **결과**: `_norm_req_cmd` 비교 실패로 `inject_approval`이 `(False, INJECT_SKIP_CHANGED)`를 반환하고 실제 `enter` 키를 전송하지 못함. 그럼에도 상위 승인 로직은 DB를 `RESOLVED`로 전이시켜 심각한 상태 불일치 초래.
  - 해결 방안:
    1) Prefix 및 상위/하위 경로 포괄 매칭: `live_req`가 `req_cmd`의 Prefix이거나, `access_directory`의 경우 파일 경로의 상위 디렉터리와 매칭 시 동일 요청으로 인정.
    2) `ctrl+f` 풀스크린 전개 연동 (PR #152 `expand_dialog` 활용): 절단 의심 시 `ctrl+f`로 전개 후 재비교.
[] [Bug/DB] `enqueue_pending_escalation` ON CONFLICT 시 `resolution` 및 `approver` 미초기화 버그 (사례: #3159):
  - 현상 및 원인 (사례: Escalation #3159 Codex `w1N:p1` 빌드 명령):
    • 동일 Pane에서 과거에 승인된 동일 명령이 재실행되어 에스컬레이션될 때, DB 레코드가 `status='PENDING'`으로 갱신되면서도 이전 승인 이력인 `resolution='APPROVED', approver='pane-direct'`가 `NULL`로 리셋되지 않고 그대로 잔류.
    • 이로 인해 TUI와 DB 상에서 "Pending 대기 상태인데 Resolution은 이미 Approved로 표기"되는 기괴한 데이터 불일치 및 관측 혼란 발생.
  - 해결 방안:
    • `enqueue_pending_escalation`의 `ON CONFLICT(pane_id, command_hash) DO UPDATE SET` 구문에 `resolution = NULL, approver = NULL, delivered_at = NULL` 명시적 초기화 추가.

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

[] [Refactor/Adapters] Codex 및 AGY 다이얼로그 앵커 liveness 한정 주석 명시 2종 (#146 피어리뷰 후속):
  1) Codex 앵커(digit) 확대는 liveness-only 전용: 향후 옵션 번호 -> 승인/거절 매핑 시 '1=Yes' 가정 금지 주의.
  2) AGY 앵커(digit) liveness-only 주석 명시: liveness 검사 외 다른 용도로의 전용 방지.

[] [Refactor/Eviction] Stale Escalation Eviction 로직 정밀화 3종 (#33 피어리뷰 후속):

  1) 에이전트 상태 문자열 대소문자 무시: `_should_evict_stale_escalation`의 `blocked` vs `working/idle/done` 매칭에 `.lower()` 또는 공용 상태 상수 적용 (Herdr 상태 케이싱 차이로 인한 eviction 누락 방지).
  2) 해소 상태값 표준화 및 검증: `resolve_escalation`의 `RESOLVED` vs `CANCELLED` 처리 경로 일관성 점검 및 `approver="pane-direct"` 다운스트림 정상 연동 확인.
  3) 명령 일치성(Command-Match) 검사 추가: `pane_id` 단독 키 매칭 외에 `raw_command` 동일성 확인을 추가하여, 다이얼로그 내용이 다른 미승인 명령으로 교체된 경우의 오퇴출 방지.

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

[] [Task/UX] TUI 토글/설정 옵션 전용 윈도우(Settings Modal) 분리 및 첫 화면(Main/Sidebar) 핵심 상태 직관화
   - Context & Feedback:
     - 기능 확장(Guard 토글, Controller/Observer 모드, 승인/거절 지침 토글, 다국어 선택, Approval Bias, Fast-Track 모드 등)에 따라 메인 TUI 화면에 토글 버튼이 과도하게 증식하여 화면이 복잡해지는 문제 해소.
     - **사용자 핵심 피드백**:
       1) **첫 화면 상시 노출**: 가장 자주 확인하고 조작하는 `Guard daemon (ACTIVE/INACTIVE)` 및 `Mode (Controller/Observer)` 2개만 첫 화면(상단 헤더 또는 우측 사이드바 최상단)에 간결하게 상시 노출.
       2) **첫 화면에서 제거 (Settings 모달로 격리)**: 현재 첫 화면과 Settings에 중복 노출되고 있는 `Instruction Delivery (지침 주입 토글)` 및 `Answer Language (다국어 선택 버튼그룹)`는 **첫 화면에서 완전히 제거**하고 전용 Settings 모달 내부로만 일원화하여 메인 뷰포트의 시각적 노이즈 최소화.
   - Solution & Architecture:
     1. 첫 화면(Main Header / Sidebar Top): `Guard Daemon` 및 `Leader Mode` 2대 핵심 상태만 노출.
     2. 전용 설정 모달(SettingsModal):
        - 진입 방법: 단축키 `^s` (Settings), `F2`, 설정 버튼 클릭, 또는 Slash Command `/config`, `/settings`
        - 모달 내부로 격리/일원화: Instruction Delivery(승인/거절 지침), Answer Language(KO/EN/JA), Approval Bias, Fast-Track 모드.


[x] [Task/UX] 에스컬레이션 배너/메시지 타이밍 및 상태 전이 명확화: Phase-1 In-flight IPC 기반 조사 중 vs 인간 개입 필수 색상·시각적 분리 (PR #161 완료, INV-PH1-1..6):
   - 해결:
     1) **Phase-1 in-flight IPC**: inspector 평가 진행 중(escalation 전) 상태를 JSON 상태파일(`in_flight_state.json`, 단일 writer 원자적 쓰기 + STALE_TTL 30s)로 TUI에 노출.
     2) **2단계 Phase 구분**: `🔍 Inspector: checking`(dim, 결정론적 AST ms 단위) vs `🤖 Gatekeeper: judging`(dim magenta, LLM/cloud-judge 초 단위) 시각 분리.
     3) **인간 개입 필수 시각화**: PENDING(인간 개입 필수 확정)일 때만 `🚨 Human Action Required`(bold red) 배너 노출하여 #3363 인지 혼선 완벽 해소.
     4) **불변식 & 테스트**: INV-PH1-1..6 불변식 확립, 단위테스트 14종 추가 (총 560 OK).



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
