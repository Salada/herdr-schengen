---
name: herdr-agent-guard
description: Herdr 패널에서 실행 중인 AGY 에이전트를 모니터링하고, AST 정적 분석 및 GPT-OSS 120B Private Subagent를 통해 안전한 명령은 5초 주기로 자동 승인하며 위험/모호한 동작은 사용자에게 위임하는 실시간 보안 감시 스킬. Hermes 및 가드 실행 패널(Self-Caller)은 엄격히 배제됩니다.
---

# Herdr Agent Guard 🛡️

`herdr-agent-guard`는 **Herdr 터미널 멀티플렉서** 환경에서 백그라운드로 실행 중인 **AGY 에이전트 전용** 권한 요청(Approval Prompt) 감시 스킬입니다. **Hermes 등 타 에이전트는 물론 가드를 실행한 자기 자신 패널(Self-Caller)도 100% 대상에서 배제**되어 자가 승인(Self-Recursive Approval) 루프를 원천 차단합니다.

---

## 🧭 핵심 철학: AGY 전용 격리, 자기 배제(Self-Exclusion) & 싱글톤 무결성

1. **자가 승인 원천 차단 (Self-Exclusion Policy)**:
   - 가드 워처가 실행되고 있는 현재 패널(`HERDR_PANE_ID` or `--exclude-pane`)은 **타겟 목록에서 무조건 자동 제외**됩니다. 이로써 가드가 자신의 프롬프트를 자가 승인하는 보안 모순을 방지합니다.
2. **AGY 전용 격리 (Hermes 100% 배제)**:
   - `--agent-filter agy`가 기본값으로 적용되어, Hermes(`wP:p1` 등)나 기타 CLI 패널의 프롬프트에는 **절대로 키 주입이나 자동 승인이 개입하지 않습니다**.
3. **에이전트 세션과 가드 세션의 Reasoning 분리**:
   - **메인 AGY 코딩 세션**: 사용자가 설정한 기존 세션 모델 및 `medium` 이상의 깊은 추론력을 온전히 유지.
   - **Guard Watcher (보안 심사관)**: 기본값(Default)을 초저지연 **`reasoning: low`**로 동작시켜 200~300ms 이내에 즉각 판정.
4. **엄격한 싱글톤 락 (Strict Singleton FileLock)**:
   - `~/.local/state/herdr-agent-guard/guard.lock`을 통해 중복 실행을 100% 방지.

---

## 🚀 빠른 실행 (Quick Start)

### 1. 전역 모든 AGY 세션 자동 감지 및 감시 (Hermes & 자기 자신 완전 제외)
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
