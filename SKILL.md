---
name: herdr-agent-guard
description: Herdr 패널에서 실행 중인 에이전트(AGY, Hermes, Codex 등)를 모니터링하고, AST 정적 분석 및 GPT-OSS 120B Private Subagent를 통해 안전한 명령은 5초 주기로 자동 승인하며 위험/모호한 동작은 사용자에게 위임하는 실시간 보안 감시 스킬.
---

# Herdr Agent Guard 🛡️

`herdr-agent-guard`는 **Herdr 터미널 멀티플렉서** 환경에서 백그라운드로 실행 중인 코딩 에이전트(AGY, Hermes, Codex 등)의 권한 요청(Approval Prompt)을 주기적으로 감시하고, **Python AST 정적 분석, 시크릿 노출 방지, Hermes Sandbox 쓰기 차단, 사설 SCM(Forgejo) 화이트리스트 룰, 그리고 GPT-OSS 120B 기반 프라이빗 시맨틱 감사**를 지원하는 실시간 보안 가드레일 스킬입니다.

---

## 🧭 핵심 철학: 인간 중심 통제 & 싱글톤 무결성 (Human-in-the-Loop & Singleton Lock)

1. **인간 중심 통제 (No Silent LaunchAgents)**:
   - OS 레벨에서 백그라운드에 숨어 무조건 실행되는 백그라운드 데몬(LaunchAgent)을 배제합니다.
   - 사용자가 Herdr 워크스페이스에서 **직접 눈으로 보며 필요할 때 명시적으로 실행**하고, 언제든 중단(`--stop`)하거나 직접 결재할 수 있는 가시성을 보장합니다.
2. **엄격한 싱글톤 락 (Strict Singleton FileLock)**:
   - `~/.local/state/herdr-agent-guard/guard.lock`에 `fcntl.flock`을 체결하여, 중복 인스턴스가 실행될 경우 Race Condition이나 키 중복 주입을 방지하고 즉시 안전하게 종료됩니다.
3. **가변 Reasoning Effort 제어 (Default: `medium`, Option: `low` / `off`)**:
   - 기본값은 안정적인 **`medium`**으로 동작하며, 빠른 초저지연을 원할 경우 **`--reasoning low`** 또는 **`--reasoning off`**로 즉시 전환할 수 있습니다.
4. **Google One 쿼터 보존 (Zero Quota Consumption)**:
   - 보안 심사는 프라이빗 인프라(GPT-OSS 120B)로 분리 라우팅되어 메인 Gemini 3.7의 개발 쿼터를 단 1토큰도 소모하지 않습니다.

---

## 🚀 빠른 실행 (Quick Start)

### 1. 전역 모든 활성 에이전트 자동 감지 및 감시 (기본: Reasoning Medium)
```bash
python3 ~/.gemini/skills/herdr-agent-guard/scripts/guard_watcher.py --target auto
```

### 2. 초저지연 모드 (Reasoning Low + GPT-OSS 120B)
```bash
python3 ~/.gemini/skills/herdr-agent-guard/scripts/guard_watcher.py --target auto --use-gpt-oss --reasoning low
```

### 3. 특정 패널 5초 주기 감시
```bash
python3 ~/.gemini/skills/herdr-agent-guard/scripts/guard_watcher.py --target wP:p2 --interval 5
```

### 4. 실행 중인 가드 프로세스 안전 중단 (Stop Singleton)
```bash
python3 ~/.gemini/skills/herdr-agent-guard/scripts/guard_watcher.py --stop
```

### 5. 축적된 승인 패턴 및 빈도 통계 조회 (Human Review Board)
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
