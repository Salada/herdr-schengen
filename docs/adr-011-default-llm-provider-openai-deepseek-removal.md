# ADR-011: Default LLM Provider — OpenAI (GPT) with DeepSeek Removal from Defaults

## Status
**Accepted**

## Context

`herdr-schengen` (SmartGate) uses an LLM in two distinct roles:

1. **Cloud Judge** (`core/cloud_judge.py`) — the deterministic AST/SAST fallback
   that decides whether a command is safe or must be deferred to a human.
2. **TUI Inspector/Judge** (`tools/schengen_agent_llm.py`) — the dual-model
   (Inspector tool-calling + Judge adjudication) pipeline inside the Textual TUI.

The author develops SmartGate at home against **DeepSeek** (cheap, fast), but the
company where this tool is operated has an **organizational aversion to Chinese
models** and will not permit DeepSeek credentials or defaults in code. Leaving
DeepSeek as the baked-in default (or hard-coding its env vars / endpoint) would
make the tool unusable in the corporate environment and expose a provider the
organization has rejected.

## Decision

1. **Default provider is OpenAI.** All model defaults become `gpt-5.6-luna`
   (`GUARD_LLM_MODEL`, `SCHENGEN_INSPECTOR_MODEL`, `SCHENGEN_JUDGE_MODEL`,
   `resolve_subagent_model`).
2. **DeepSeek defaults and strings are removed** from code, docs, env allowlists,
   and UI chrome:
   - `_SHARED_KEY`/`_SHARED_URL` now resolve OpenAI-standard
     `OPENAI_API_KEY` / `OPENAI_BASE_URL` (default `https://api.openai.com/v1`).
   - `DEEPSEEK_API_KEY`, `DEEPSEEK_BASE_URL`, `OPENCODE_DEEPSEEK_API_KEY`,
     `deepseek-chat`, and the "(DeepSeek Flash)" TUI title are removed.
   - The plugin env allowlist no longer forwards `DEEPSEEK_API_KEY`.
3. **DeepSeek remains reachable as an opt-in override** for home use, via the
   OpenAI-compatible escape hatch — no DeepSeek-specific code:
   ```bash
   export OPENAI_BASE_URL="https://api.deepseek.com/v1"
   export OPENAI_API_KEY="<deepseek-key>"
   ```
4. **Default reasoning effort stays `low`** (`GUARD_REASONING_EFFORT=low`), the
   cheapest tier, consistent with a price-sensitive default.

## Alternatives Considered

- **deepseek-v4-flash (cloud)** — the best price/performance cloud model for
  home use. Rejected as the *default* for the corporate reason above, but it is
  the recommended home override via `OPENAI_BASE_URL`.
- **gpt-oss-120b (local)** — a private, self-hosted 120B model. This is the
  **safest** option (no third-party data egress) and is already exposed through
  the watcher's `--use-gpt-oss` flag for the semantic judge. Not the *default*
  because it requires local GPU capacity that a stock workstation may lack.
- **Keeping DeepSeek as default with a company toggle** — rejected: the company
  environment must never see DeepSeek in defaults or code, per the organizational
  policy.

## Consequences

- **Positive**: `herdr-schengen` runs out-of-the-box in the corporate environment
  against OpenAI with no DeepSeek surface area. Home users can still point the
  generic OpenAI-compatible client at DeepSeek via two env vars.
- **Negative**: home users lose the DeepSeek convenience default and must set
  `OPENAI_BASE_URL`/`OPENAI_API_KEY` explicitly to keep using it. Model string
  identifiers in docs/tests are now GPT-centric.
- **Neutral**: `cloud_judge.py` already followed this pattern (issue #33); this
  ADR extends the same policy to the TUI Inspector/Judge and the host plugin.
