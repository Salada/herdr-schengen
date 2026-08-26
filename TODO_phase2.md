Small task?
[] Full screen 에서 item클릭했을때 한 record만 focus해서 더 자세히 볼수있는 뷰
  - 과거에 추가의견에 대해서 보관한 table이 있을텐데 join해서 보여줄수있으면 더 좋음.
[] Verdict=ESCALATED시에 Schengen을 통한 추가 처리 상태 ( Approve/Reject/Unanswer/etc
.. ) 를 표시 -> 표시되지 못한다면 tui뿐만 아니고 내부 로직도 확장 
[x] 내부 답변을 위한 언어에 English/한국어/日本語 를 표시하여 셋중에 하나를 선택할수있는 버튼그룹을 만들고, 선택된 버튼그룹의 언어가 chat화면의 답변으로 렌더링이 "유도"될수있게 prompt를 구성해줘. 단 여기서 주의할점은, 지침이 agent에게 herdr를 통해 전달될때는 반드시 토큰을 아끼기 위해 영어여야된다는 전제를 지켜야 된다는 것이다. (default: 한국어, guard_config.answer_language, herdr english_feedback은 영어 유지)

Epic: 
[] codex 지원
