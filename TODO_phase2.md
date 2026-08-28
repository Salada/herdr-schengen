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

Small task?
[x] Full screen 에서 item클릭했을때 한 record만 focus해서 더 자세히 볼수있는 뷰
  - 과거에 추가의견에 대해서 보관한 table이 있을텐데 join해서 보여줄수있으면 더 좋음. (AuditDetailModal + get_audit_log_by_id/get_adjudications_for_audit join)
[x] Verdict=ESCALATED시에 Schengen을 통한 추가 처리 상태 ( Approve/Reject/Unanswer/etc
.. ) 를 표시 -> 표시되지 못한다면 tui뿐만 아니고 내부 로직도 확장 (pending_escalations.resolution 컬럼 추가 + record_adjudication/cleanup_escalations에서 APPROVED/REJECTED/UNANSWERED 기록, audit ledger Res 컬럼/상세 resolution 표시)
[x] 내부 답변을 위한 언어에 English/한국어/日本語 를 표시하여 셋중에 하나를 선택할수있는 버튼그룹을 만들고, 선택된 버튼그룹의 언어가 chat화면의 답변으로 렌더링이 "유도"될수있게 prompt를 구성해줘. 단 여기서 주의할점은, 지침이 agent에게 herdr를 통해 전달될때는 반드시 토큰을 아끼기 위해 영어여야된다는 전제를 지켜야 된다는 것이다. (default: 한국어, guard_config.answer_language, herdr english_feedback은 영어 유지)

Epic: 
[] codex 지원
