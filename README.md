# Herdr Agent Guard 🛡️

Real-time security guardrail and auto-approval daemon for coding agents (AGY, Hermes, Codex) running in Herdr multiplexer.

## Features
- **5s Polling & Blocked State Detection**: Watches Herdr panes for agent approval prompts.
- **Python AST Static Analysis**: Detects dangerous imports (`socket`, `requests`), code execution (`eval`, `exec`), and sensitive file opens.
- **Hermes Sandbox Write Protection**: Prohibits writes/mutations targeting `~/.hermes/sandboxes/`.
- **Secret Exfiltration Defense**: Blocks reading `.env`, `id_rsa`, tokens, and credentials.
- **SQLite3 Persistence & Pattern Analytics**: Normalized command templates stored in `~/.local/state/herdr-agent-guard/guard_history.db`.
- **Human Review Board**: Review stats and persist verified patterns to `user_allowlist`.

## Usage
```bash
# Watch specific pane
python3 scripts/guard_watcher.py --target wP:p2 --interval 5

# Auto-detect all active coding agent panes
python3 scripts/guard_watcher.py --target auto

# View pattern statistics
python3 scripts/guard_watcher.py --stats
```
