---
name: herdr-agent-guard
description: Herdr 패널에서 실행 중인 AGY 에이전트를 모니터링하고, AST 정적 분석 및 GPT-OSS 120B Private Subagent를 통해 안전한 명령은 5초 주기로 자동 승인하며 위험/모호한 동작은 사용자에게 위임하는 실시간 보안 감시 스킬. Hermes는 기본적으로 엄격히 배제됩니다.
---

# Herdr Agent Guard 🛡️

`herdr-agent-guard`는 **Herdr 터미널 멀티플렉서** 환경에서 백그라운드로 실행 중인 **AGY 에이전트 전용** 권한 요청(Approval Prompt) 감시 스킬입니다. **Hermes 등 타 에이전트는 기본적으로 100% 대상에서 배제**되며 오직 AGY 세션에 대해서만 안전한 자동 승인 및 보안 심사를 수행합니다.

---

## 🧭 핵심 철학: AGY 전용 격리 & 인간 중심 통제

1. **AGY 전용 격리 (Hermes 100% 배제)**:
   - `--agent-filter agy`가 기본값으로 적용되어, Hermes(`wP:p1` 등)나 기타 CLI 패널의 프롬프트에는 **절대로 키 주입이나 자동 승인이 개입하지 않습니다**.
2. **에이전트 세션과 가드 세션의 Reasoning 분리**:
   - **메인 AGY 코딩 세션**: 사용자가 설정한 기존 세션 모델 및 `medium` 이상의 깊은 추론력을 온전히 유지.
   - **Guard Watcher (보안 심사관)**: 기본값(Default)을 초저지연 **`reasoning: low`**로 동작시켜 200~300ms 이내에 즉각 판정.
3. **스크립트 사전 실행 승인 (Pre-approval) 완벽 포착**:
   - `python3 - <<'EOF'` 인라인 스크립트, 다단계 Bash 블록, `[y/N]`, `1. Yes` 번호 선택 메뉴 등 실행 전 승인을 기다리는 모든 대기 패턴을 정밀 추출하여 사전에 안전성을 검사하고 승인.
4. **엄격한 싱글톤 락 (Strict Singleton FileLock)**:
   - `~/.local/state/herdr-agent-guard/guard.lock`을 통해 중복 실행을 100% 방지.

---

## 🚀 빠른 실행 (Quick Start)

### 1. 전역 모든 AGY 세션 자동 감지 및 감시 (Hermes 완전 제외)
```bash
python3 ~/.gemini/skills/herdr-agent-guard/scripts/guard_watcher.py --target auto
```

### 2. GPT-OSS 120B 프라이빗 시맨틱 감사관 활성화 (Google One 쿼터 소모 0)
```bash
python3 ~/.gemini/skills/herdr-agent-guard/scripts/guard_watcher.py --target auto --use-gpt-oss
```

### 3. 특정 AGY 패널만 명시적으로 감시
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
| **대상 에이전트** | **AGY (`agent: "agy"`) 세션 전용** | Hermes, 기타 CLI 에이전트는 무조건 스킵 / 제외 |
| **Forgejo (192.168.10.102:3000)** | 1. `GET` 요청 전체 허용<br>2. `/issues/...` 엔드포인트 상호작용 (POST, PATCH, PUT) 허용 | `DELETE` 요청 전체 (`-X DELETE`, `method='DELETE'`) 차단 |
| **Environment** | `export PATH="/opt/homebrew/bin:/usr/bin:/bin"` 등 PATH 환경변수 설정 허용 | `/etc`, `/System`, `/usr/bin` 등 시스템 디렉터리 직접 조작/삭제 (`rm`, `chmod`) |
| **Shell Commands** | `git status/diff/add/commit`, `mkdir`, `cd`, `ls`, 문서 생성/편집 | `rm -rf`, `sudo`, `su`, `chmod`, `chown`, `git push`, `git reset --hard` |
| **Hermes Sandbox** | 샌드박스 내부 단순 조회/읽기 (`cat / ls` 등) | 샌드박스 경로 대상 쓰기 (`> .hermes/sandboxes/...`, `cp/mv`, `touch`, `rsync`) |
| **Secrets** | `.env.example` 등 템플릿 파일 다루기 | `cat .env`, `grep KEY .env`, `id_rsa`, `~/.aws`, `~/.config/gh/hosts.yml` 접근 |
| **Python AST** | 데이터 가공, 린터/테스트(`pytest`), 허용된 Forgejo API 호출 | `requests`/`socket` 외부 인터넷 통신, `eval()`, `exec()`, 샌드박스 파일 쓰기 |
