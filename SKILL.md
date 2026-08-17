---
name: herdr-agent-guard
description: Herdr 패널에서 실행 중인 에이전트(AGY, Hermes, Codex 등)를 모니터링하고, AST 정적 분석 및 Dual-LLM Guardrail을 통해 안전한 명령(Forgejo GET/Issues, PATH 등)은 5초 주기로 자동 승인하며 위험/모호한 동작(시크릿 노출, Hermes Sandbox 쓰기 등)은 사용자에게 위임하는 실시간 보안 감시 스킬.
---

# Herdr Agent Guard 🛡️

`herdr-agent-guard`는 **Herdr 터미널 멀티플렉서** 환경에서 백그라운드로 실행 중인 코딩 에이전트(AGY, Hermes, Codex 등)의 권한 요청(Approval Prompt)을 주기적으로 감시하고, **Python AST 정적 분석, 시크릿 노출 방지, Hermes Sandbox 쓰기 차단, 사설 SCM(Forgejo) 화이트리스트 룰, 그리고 SQLite3 기반 영속 감사/패턴 분석**을 지원하는 실시간 보안 가드레일 스킬입니다.

---

## 🚀 빠른 실행 (Quick Start)

### 1. 특정 패널 5초 주기 감시 (기본)
```bash
python3 ~/.gemini/skills/herdr-agent-guard/scripts/guard_watcher.py --target wP:p2 --interval 5
```

### 2. 모든 활성 에이전트 자동 감지 및 감시 (Auto Target)
```bash
python3 ~/.gemini/skills/herdr-agent-guard/scripts/guard_watcher.py --target auto
```

### 3. 축적된 승인 패턴 및 빈도 통계 조회 (Human Review Board)
```bash
python3 ~/.gemini/skills/herdr-agent-guard/scripts/guard_watcher.py --stats
```

---

## 🛡️ 정밀 보안 검증 정책 (Security Evaluation Policies)

| 영역 | 자동 승인 대상 (`SAFE`) | 사용자 위임/차단 대상 (`DANGEROUS`) |
| :--- | :--- | :--- |
| **Forgejo (192.168.10.102:3000)** | 1. `GET` 요청 전체 허용<br>2. `/issues/...` 엔드포인트 상호작용 (POST, PATCH, PUT) 허용 | `DELETE` 요청 전체 (`-X DELETE`, `method='DELETE'`) 차단 |
| **Environment** | `export PATH="/opt/homebrew/bin:/usr/bin:/bin"` 등 PATH 환경변수 설정 허용 | `/etc`, `/System`, `/usr/bin` 등 시스템 디렉터리 직접 조작/삭제 (`rm`, `chmod`) |
| **Shell Commands** | `git status/diff/add/commit`, `mkdir`, `cd`, `ls`, 문서 생성/편집 | `rm -rf`, `sudo`, `su`, `chmod`, `chown`, `git push`, `git reset --hard` |
| **Hermes Sandbox** | 샌드박스 내부 단순 조회/읽기 (`cat / ls` 등) | 샌드박스 경로 대상 쓰기 (`> .hermes/sandboxes/...`, `cp/mv`, `touch`, `rsync`) |
| **Secrets** | `.env.example` 등 템플릿 파일 다루기 | `cat .env`, `grep KEY .env`, `id_rsa`, `~/.aws`, `~/.config/gh/hosts.yml` 접근 |
| **Python AST** | 데이터 가공, 린터/테스트(`pytest`), 허용된 Forgejo API 호출 | `requests`/`socket` 외부 인터넷 통신, `eval()`, `exec()`, 샌드박스 파일 쓰기 |

---

## 🗄️ SQLite3 영속 데이터 모델

- **DB 경로**: `~/.local/state/herdr-agent-guard/guard_history.db`
- **테이블 구성**:
  1. `audit_logs`: 모든 권한 요청, 정규화된 템플릿, 판정 결과, 타임스탬프, 에이전트 종류 기록.
  2. `pattern_stats`: 정규화된 명령어 패턴별 누적 발생 횟수, 자동 승인 횟수, 위임 횟수 집계.
  3. `user_allowlist`: 사용자가 직접 리뷰하고 영속화한 커스텀 화이트리스트 정규식 규칙.
