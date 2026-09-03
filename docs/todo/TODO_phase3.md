# Herdr-Schengen Phase 3: Archive of Completed Milestones

> **🎉 Phase 3 완료 (Completed)**: Phase 3의 모든 스프린트(Sprint 1, Sprint 2, Sprint 3) 및 핵심 버그/아키텍처 수렴이 100% 완료되었습니다 (총 653+ tests OK).
> **👉 활성 잔여 백로그 이관 안내**: 미완료 백로그 및 Phase 4 4대 실행 트랙(Sprint 4 대형 동시성 엔진 등)은 [`docs/todo/TODO_phase4.md`](TODO_phase4.md)로 전면 이관되어 관리됩니다.

---

## 🎯 Phase 3 마일스톤 완결 요약 (Completed Sprints)

1. 🎉 **[Sprint 1 — P0 긴급 버그 일괄]** Liveness/Auto-Eviction 정밀화 & OpenCode 다이얼로그 주입 회복 (PR #172 완료 — 628 tests OK / 3 skipped)
   - [x] 1a) `#7771` (AGY) & `#7938` (Codex ppt space): 어댑터별 `dialog_is_live()` 앵커/가변 윈도우 보강 + TUI pre-render 즉시 승인 방지(Debounce/프로세스 상태전이 가드) ➔ 가짜 `pane-direct` 승인 박멸 (`INV-PD-4/5`, 단위테스트 검증 완료).
   - [x] 1b) `#2800`: TUI pre-render `is_question` 예외 제거 + Watcher QUESTION 소멸 시 auto-evict (`resolution="ANSWERED"`, `sweep_answered_questions` / `test_question_eviction` 10종 검증 완료).
   - [x] 1c) `#3689, #3615, #3623, #3636~#3638`: Dialog Trampoline / TOCTOU 불일치 해소를 위한 Auto-Advance 엔진(`scripts/adapters/auto_advance.py`, `INV-AA-1..9`) 구현 완료.

2. 🎉 **[Sprint 2 — 관측성 & 인터랙션 극대화]** Gatekeeper 사전 브리핑·동반자적 심의(Disagree & Commit) + Action Required 3단 패널 (PR #178 + PR #179 + PR #180 완료 — 653 tests OK)
   - [x] 2a) **Gatekeeper 사전 복잡도/위험 세그먼트 브리핑 & Disagree & Commit 프롬프팅 (#3864, PR #179 & PR #180 완료)**: 질문 전 복잡도 유발 요인 사전 분해, `guard_config.approve_advisory` 옵션화 (`INV-GK-1..8`, 단위테스트 8개 추가).
   - [x] 2b) **Action Required 3단 패널 (PR #178 & commit 486832d 완료)**: Top Banner(붉은 점멸) + Radar 3-tier 상태 카드(Inspecting Pane / Judging Pane / BACKGROUND RADAR) + TUI 실시간 연동.

3. 🎉 **[Sprint 3 — 코드베이스 위생 & 테스트 수렴]** 피어리뷰 후속 일괄 수렴 (PR #171 완료 — 606 ran, 3 skipped)
   - [x] #139 Complexity / #2555 TestRunner (INV-5/6 bypass 차단) / M6 CloudJudge / #33 Eviction / #45 SAST / #146 Adapter / M7 AntiFatigue / #7207 WorkspacePolicy 전면 완료.

---

## 📜 Phase 3 Completed Backlog Record (완료 내역 보존 기록)

[x] [P0/Docs] 전체 문서 전수조사, ADR Superseded 표기 및 `docs/index.md` 마스터 색인 체계 구축 (Issue #166, PR #169 + commit 7a9e860 완료):
  - Forgejo Issue: [Issue #166](http://192.168.10.102:3000/InhouseOriented/herdr-schengen/issues/166)
  - 완료 내역: PR #169(디렉터리 5개 서브폴더 재구성, README 다이어트, docs/index.md 마스터 색인 체계, ADR 상태 메타데이터) + commit `7a9e860`(ADR-014 master index 누락 보강).

[x] [Bug/Question] Pane 질문(decision_layer='QUESTION') 답변 완료 후에도 TUI 상단 배너 및 Pending 큐에 영구 잔류하는 현상 수정 (사례: #2800, PR #146 등 구현·테스트 완료):
  - 조치 및 검증 상태: `sweep_answered_questions`, `resolve_cleared_dialog`, 어댑터별 `question_is_live` 구현 및 `tests/test_question_eviction.py` (INV-Q-1..5) 10종 단위테스트 검증 완료.

[x] [P0 Blocker/OpenCode] OpenCode 연쇄 명령 다이얼로그 전이(Dialog Trampoline) 및 Auto-Advance 회복 (사례: #3615, #3623, #3636~#3638, #3689, PR #172 완료):
  - 해결 및 검증 (PR #172): `scripts/adapters/auto_advance.py` 신규 모듈 및 `INV-AA-1..9` 불변식 체계 구축 완료.

[x] [Provenance] human opinion vs gatekeeper adjudication 분리 (PR #177 완료, 857965b; TUI 표시 회귀 핫픽스 PR #181, PR #182 완료):
  - `adjudication_log` 테이블에 `approver` 및 `human_note` 컬럼 가법 마이그레이션 적용.
  - `record_human_opinion`, `has_human_opinion`, `get_adjudication_exchange` 신규 API 추가.
  - TUI 표시 회귀 핫픽스(#181 Rich markup by prefix, #182 rich_escape bare bracket) 및 회귀테스트 3종 완료.

[x] [Bug/DB] `enqueue_pending_escalation` ON CONFLICT 시 `resolution` 및 `approver` 미초기화 버그 (사례: #3159, PR #175 완료):
  - `enqueue_pending_escalation`의 `ON CONFLICT(pane_id, command_hash) DO UPDATE SET` 구문에 `resolution = NULL, approver = NULL, delivered_at = NULL` 명시적 초기화 추가 (634 tests OK).

[x] [Idea/Architecture] Question 분리 처리: 커맨드 에스컬레이션 큐 비차단(Non-blocking) & 사이드바/힌트 버튼 기반 Pane 점프 분리 (기구현 검증 완료):
  - `INV-QN-1/2` 불변식: Question 에스컬레이션은 메인 결재 슬롯을 점유하지 않고 백그라운드 힌트/Radar 배지로 표시.

[x] [Refactor/Adapters] Codex 및 AGY 다이얼로그 앵커 liveness 한정 주석 명시 2종 (#146 피어리뷰 후속, PR #171 완료).

[x] [Refactor/Eviction] Stale Escalation Eviction 로직 정밀화 3종 (#33 피어리뷰 후속, PR #171 완료).

[x] [Task/Dependency] semgrep 필수 디펜던시(Required Dependency) 체계적 관리 및 자동화 완결 (PR #174 완료, e61187f + 7abf941):
  - `pyproject.toml`에 `semgrep>=1.70.0` 필수 디펜던시 선언, Host Runtime Gate hard-fail(`INV-2`), CI 테스트 환경 설치 공식화.

[x] [Refactor/SAST] `_inject_runtime_path()` 및 Host Runtime Gate 안정화 4종 (#45 피어리뷰 후속, PR #171 완료).

[x] [Refactor/Complexity] Complexity Tax 정밀화 및 DB 쿼리 최적화 5종 (#139 피어리뷰 후속, PR #171 완료).

[x] [Refactor/CloudJudge] Cloud Judge Confidence & Complexity Mode 안정화 4종 (M6 피어리뷰 후속, PR #171 완료).

[x] [Refactor/TestRunner] Test Runner 파이프라인 정규식 대칭화 2종 (#2555 피어리뷰 후속, PR #171 완료).

[x] [Refactor/AntiFatigue] Anti-Fatigue 배치 집계 및 동의 품질 개선 4종 (M7 피어리뷰 후속, PR #171 완료).

[x] [Refactor/WorkspacePolicy] Workspace `.schengen/` 정책 신뢰스토어 검증 3종 (#7207 피어리뷰 후속, PR #171 완료).

[x] [EPIC] Fail-open → fail-closed 편향 전환 + 패키지 매니저 인식 (M1~M7 전면 완결, PR #126~#144).

[x] [Task/UX] TUI 토글/설정 옵션 전용 윈도우(Settings Modal) 분리 및 첫 화면(Main/Sidebar) 핵심 상태 직관화 (PR #173 완료, 91bb4d2).

[x] [Task/UX] 에스컬레이션 배너/메시지 타이밍 및 상태 전이 명확화: Phase-1 In-flight IPC & Phase 2b 인간 개입 gating 완결 (PR #161 & PR #167 완료, INV-PH1-1..6 / INV-HR-1..6).

[x] [Task/UX] Gatekeeper 인간 승인 요청 메시지 포매팅, 사전 복잡도 설명 및 동반자적 심의(Disagree & Commit) 프롬프팅 혁신 (사례: #3864, PR #178, PR #179, PR #180 완료).

---

> 📌 **이관 안내**: 상기 완료된 19개 항목 외의 모든 미완료 백로그(16개 항목)는 [`docs/todo/TODO_phase4.md`](TODO_phase4.md)로 이관되었습니다.
