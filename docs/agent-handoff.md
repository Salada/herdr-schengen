# Agent Handoff — Machine-Specific Conventions

> 보조 파일(Supplementary). 커밋되는 범용 가이드 `AGENTS.md`를 보완하는,
> **이 머신(Mac mini) + herdr-schengen 세션**에 한정된 운영 컨벤션을 담는다.
> AGENTS.md는 포터블·범용 원칙만 유지하고, 머신 특정 내용은 이 파일로 분리한다.

## Bot Identity & Git Attribution

- Author: `bot-opencode-default <bot-opencode-default@salada.mail.home.arpa>`
- Trailers (필수):

```
Co-authored-by: OpenCode (DeepSeek V4 Pro) <bot-opencode-default@salada.mail.home.arpa>
Agent: opencode (deepseek-v4-pro)
Profile: default
Op: feat|fix|docs|refactor|test|chore
```

## Test Command

```bash
HERDR_ENV=1 ~/.local/share/herdr-schengen-tui-venv/bin/python3 -m unittest discover -s tests
```

## Forgejo Workflow (Salada-Git)

1. Issue-first → worktree 격리(`~/code/herdr-schengen-worktrees/<name>`) → topic branch(`feat|fix/<slug>`) → push → PR.
2. Server-side merge (Forgejo REST API `POST /api/v1/repos/InhouseOriented/herdr-schengen/pulls/{n}/merge`), main 직접 푸시 금지.
3. GitHub(`github.com/Salada/herdr-schengen`)은 단방향 스냅샷 미러: `git push github main:main`.

## Runtime Skill Mirror

```bash
rsync -a scripts/ ~/.agents/skills/herdr-schengen/scripts/
rsync -a docs/    ~/.agents/skills/herdr-schengen/docs/
rsync -a scripts/ ~/.gemini/skills/herdr-schengen/scripts/
rsync -a docs/    ~/.gemini/skills/herdr-schengen/docs/
```

## TUI / 프롬프트 변경 반영

- `Ctrl+T` 재시작 필요 (SIGHUP `--reload`는 `guard_db`/`gray_zone_evaluator`/`security_evaluator` 3개 모듈만 리로드).

## ⚠️ 게이트키퍼 체인 거절 주의

- `git commit && git push && rsync`를 하나의 `&&` 체인으로 실행하면 게이트키퍼가
  "chained egress + mutation"으로 거절할 수 있음 → **단계별로 분리 실행**할 것.
