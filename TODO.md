Strong requirement
[x] Session의 memory를 inspector 호출 전에 참고하여 만약 session내에서 approve가 발생해도 좋으면 그냥 진행할것. 다만 pane별로 별도의 기억룰을 가질것 (PR #63)
[x] input command 창에서 word-wrap안되는거 해결 (PR #64)
[x] command pallete 삭제 (PR #64)
[x] type command 창 multiline시 자동으로 늘어나도록 하기 (PR #64) 
[x] 세션내 유사패턴인 경우 inspector호출 전에 gatekeeper의 자체판단 가능한지 패턴 분석할것 (PR #65)
[x] Inspector Network/API Error시에 adaptive retry, retry 횟수는 maximum 10회. 적절한 timeout ( TCP ACK 없을 경우 ) (PR #66)
[x] queueing 된 메세지가 나중에 갈수있게 위에 뜨게하고, 하나하나씩 메세지 전송이 가능했을때 보내기 ? 또는 아예 메세지가 전송되지 않아서 type command에 기존 명령어 내용을 채워넣기? (PR #67)
[x] chat view에 대해서 mouse scroll 으로 scroll가능하도록 (PR #67)
[x] inflight 시에 메세지가 유실 되는게 아니라 type command에 기존 명령어 내용을 채워넣어서 자연스러운 재시도가 가능하게 하기 (PR #67)
[x] chat view에 대해서 focus 가능해서 pgup,pgen 가능하도록 (PR #67)
[x] chat view의 오른쪽에 스크롤의 경우에 좀 더 좁은 모양으로 출력가능한지 확인. 너무 넓어서 시인성 떨어짐 (PR #67)
[x] chat view에서 select가능하도록 ( clipboard에 copy하기 위함임 ) (PR #67)
[x] 외부에서 daemon이 kill당했을때 agent 상태가 갱신되지 않는 버그 수정 필요 (PR #68)
[x] agy only -> herdr pane에서 읽을떄 ctrl+g 를 통해 script전체를 읽어서 판단해도됨 ( input token이 매우 싸기때문임 ) (PR #69)
[x] Gatekeeper 응답 시 DeepSeek DSML 및 깨진 XML 태그 누출 방지 필터링 (PR #70) 

Refactor
[x] 현재 folder 구조가 adapter말고 flat하기 때문에, core, tool, cmd 등이 분리되는게 좋겠음. 적절한 방법에 대해서 고민 후 진행 (PR #72, ADR-010) 

[x] 위에까지 하고 PR review를 2번 herdr tab에서 남기고 있으니, 서로 대화하고 PR message를 보면서 PR리뷰 하고 전부 merge할것, 각 PR리뷰시 conflict 해소하고 지속적인 QA를 통해 품질 보증할것. CI에 대한 확인은 필수 (PR #61~#72 Merged to main) 
Design
[x] json_data_beautify.md 구현 (PR #71) 


QA
[x] Controller/Observer mode 잘 동작하는지 확인해야함. (PR #73) 
[x] /feature 잘되는지 확인필요.. (PR #74)
[x] chat view mouse selection 안되기때문에 적용후 사람에게 확인받고 qa반복하기 기존 PR이 머지되는거랑 상관없음. (PR #74)



Idea
[x] /interrupt 로 기존 llm call을 강제중단시키고 메세지를 보내는 기능 구현 (PR #75)
[x] recent audits 의 scroll 비활성화 시킬것 ( fullscreen의 경우에는 chat view처럼 시인성있는 scrollview로 교체할것 (PR #76)
[x] chat view에서 기존 llm call중단 시킬떄 esc를 특정 간격으로 두번누르면 중단되게 ( 단 recent audits fullscreen을 끌떄 esc는 이벤트에 쌓이면 안됨 ) (PR #75)
[x] command 창이 new line이 넓어지면 자동으로 up방향으로 panel크기를 증가시켜서 최대한 전체 prompt가 보이게 할것. ( max-height는 맡기지만 기존 chat view에 overlap되어도됨 ) (PR #77)
[x] observer mode일 경우에는 Ask gatekeeper... UI element 를 아예 비활성화 상태로 만들어버리기 (PR #77)
[x] dotfile에 있는 redact관련 executable을 file read시에 읽게하여 비의도적 PII/Secret 누출 방지를 위해 최선을 다할것. 다만 redact는 dotfiles의 것을 사용하는게 아니라 가능하면 해당 레포에 가져와서 래핑하고 embeddable가능한 구조로 관리할것 (PR #78)



Round 2 - Opencode 

[x] (PR #80) access_directory TOCTOU → stale OPENCODE_FAILSAFE escalation으로 FIFO deadlock. inject_approval이 dialog command 변경 시 skip(INJECT_SKIP_CHANGED)하도록 수정. (원인: [지침] 3단계 선택지 에러가 계속 opencode에 전달되는 버그)
[x] (PR #80) CI 실패 원인: Alpine host runner에 textual/rich/httpx 미설치 → ModuleNotFoundError('rich'). workflow에 venv+pip install 단계 추가.
[x] (PR #80, PR #73 close) PR #73(AGY QA test)는 이미 PR #74로 main 병합된 중복 → close 처리.
[x] recent audits 마우스 클릭 → fullscreen 전환: NoPixelMouseDriver로 1016h(pixel mouse)/2048h(in-band resize) 무효화해 SGR 좌표를 cell로 해석. (Textual이 2048 지원 감지 후 1016 활성화 → Herdr 터미널이 CELL 좌표를 보내는데 PIXEL로 나눠 좌표 축소)
[x] Question 다이얼로그: command/approve/reject 전송 없이 미대응 종료 (watcher에서 "question" sentinel skip — 유저가 pane에서 주관식 대응).
[x] 승인/거절 지침전달 toggle: TUI 버튼(Approve/Reject Instr) + SQLite guard_config + CLI args(--send/--no-send-*). default: approve=false, reject=true.
[x] 승인/deny 지침·논의를 SQLite adjudication_log table로 기록 (record_adjudication).
[x] bloat_message 방지: approve 지침전달 기본 false로 opencode 승인 시 피드백 주입 중단.
[] default-model을 gpt-5.6-luna 로, default-reasoning을 (설정가능하다면 ) low로 해줘. 정확히는 deekseek에 관련된 설정을 일부러 모든 코드에서 없애고 싶어. 다른게 아니라 내가 활동하는 회사에서 중국모델에 대한 거부감이 있어서. 이후 설정은 가능하게하더라도 기본 코드에는 노출하고 싶지않다. 
