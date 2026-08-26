# 🎨 Design Specification: Inspector Tool Calling & JSON Data Beautification

## 1. Executive Summary
During autonomous security adjudication, the Inspector Agent dynamically invokes tools (`investigate_path_details`, `investigate_pane_history`, `read_file_snippet`, `approve_escalation`, `reject_escalation`).
Previously, these invocations were rendered as raw indented JSON blocks (`{"target_path": "..."}`), consuming excessive vertical space and cluttering the TUI chat log.

This specification introduces **Semantic Tool Badges & Compact Visual Cards** designed for high legibility, token efficiency, and clean terminal aesthetics.

---

## 2. Visual Formatting Matrix by Tool Schema

| Tool Name | Visual Icon & Badge | Compact Single-Line Format | Expanded Details (if multi-param) |
| :--- | :--- | :--- | :--- |
| `investigate_path_details` | `🔍 [Path Check]` | `🔍 [Path Check]  `~/code/project/file.py`` | `Target: ~/path (VCS committed)` |
| `investigate_pane_history` | `📜 [Pane Buffer]` | `📜 [Pane Buffer]  `w1D:p1` (100 lines · scrollback)` | `Pane: w1D:p1 · Lines: 100 · Full Dump: Yes` |
| `read_file_snippet` | `📄 [File Read]` | `📄 [File Read]  `scripts/security_evaluator.py`` | `Reading 8KB header snippet` |
| `approve_escalation` | `✅ [Auto Approve]` | `✅ [Auto Approve]  Escalation #123` | `Feedback: Approved. Zero risk verified.` |
| `reject_escalation` | `🛑 [Action Reject]` | `🛑 [Action Reject]  Escalation #123` | `Feedback: Denied per critical denylist.` |
| `create_feature_request` | `💡 [Feature Backlog]` | `💡 [Feature Backlog]  #42: Add word-wrap` | `Priority: HIGH · Category: UI` |
| `search_feature_requests` | `🔎 [FTS Search]` | `🔎 [FTS Search]  "input word-wrap"` | `Limit: 5 · Trigram CJK FTS5` |

---

## 3. Implementation Blueprint in `schengen_agent_llm.py`

### 3.1. `format_tool_call_beautified(fn_name: str, fn_args: dict) -> str`
```python
def format_tool_call_beautified(fn_name: str, fn_args: Dict[str, Any]) -> str:
    """Format Inspector tool invocation into a high-visibility semantic badge."""
    if fn_name == "investigate_path_details":
        target = fn_args.get("target_path", "")
        return f"🔍 **[Path Check]**: `{target}`"

    elif fn_name == "investigate_pane_history":
        pane = fn_args.get("pane_id", "")
        lines = fn_args.get("lines", 100)
        dump = " · scrollback" if fn_args.get("full_dump") else ""
        return f"📜 **[Pane Buffer]**: `{pane}` ({lines} lines{dump})"

    elif fn_name == "read_file_snippet":
        target = fn_args.get("target_path", "")
        return f"📄 **[File Read]**: `{target}`"

    elif fn_name == "approve_escalation":
        esc_id = fn_args.get("escalation_id", "")
        note = fn_args.get("english_feedback", "")
        note_short = f" — *{note[:60]}…*" if len(note) > 60 else f" — *{note}*"
        return f"✅ **[Auto Approve]**: Escalation `#{esc_id}`{note_short}"

    elif fn_name == "reject_escalation":
        esc_id = fn_args.get("escalation_id", "")
        reason = fn_args.get("english_feedback", "")
        return f"🛑 **[Action Reject]**: Escalation `#{esc_id}` — *{reason}*"

    elif fn_name == "create_feature_request":
        title = fn_args.get("title", "")
        prio = fn_args.get("priority", "NORMAL")
        return f"💡 **[Feature Queued]**: `{title}` *(Priority: {prio})*"

    elif fn_name == "search_feature_requests":
        query = fn_args.get("query", "")
        return f"🔎 **[Backlog Search]**: *\"{query}\"*"

    # Fallback generic compact JSON
    raw = json.dumps(fn_args, ensure_ascii=False)
    return f"⚙️ **[Inspector]**: `{fn_name}` `{raw}`"
```

---

## 4. TUI Visual Harmony
- **No unnecessary multi-line JSON dumps** taking up half the chat screen.
- **Color-coded emoji markers** (`🔍`, `📜`, `📄`, `✅`, `🛑`, `💡`, `🔎`) for instant cognitive recognition.
- **Accurate truncation** on lengthy arguments (paths, notes) preventing horizontal wrapping issues.
