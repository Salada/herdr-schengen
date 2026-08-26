#!/usr/bin/env python3
"""Dedicated Security Inspector Harness for Herdr Schengen (ADR-002 / ADR-004).

Role: Fact-Finder / Context Investigator (Non-Judging).
Duties:
1. Herdr Pane Context Investigation: Reads previous conversation/terminal lines to determine agent intent.
2. Filesystem & Backup State Investigation: Inspects actual paths, file sizes, git tracking, and backup existence.
3. Dynamic Payload Pre-Expansion: Resolves $(cat ...), $(< ...) within ADR-002 5-layer guardrails.
4. Generates a concise, structured 'Inspector Fact Sheet' for the Judge & Human.
"""

import os
import re
import shlex
import stat
import subprocess
import sys
from pathlib import Path
from typing import Any, Dict, List, Optional

SCRIPT_DIR = Path(__file__).resolve().parent
if str(SCRIPT_DIR) not in sys.path:
    sys.path.insert(0, str(SCRIPT_DIR))

from gray_zone_evaluator import (
    ResourceTier,
    OperationType,
    IrreversibilityGrade,
    canonicalize_path,
    classify_operation,
    classify_resource_tier,
    evaluate_gray_zone_operation,
    is_inside_git_work_tree,
    is_git_clean_and_committed,
)
from herdr_client import get_pane_text


def investigate_pane_intent(pane_id: str, lines: int = 25) -> str:
    """Extract preceding worker context to uncover why this command was invoked."""
    try:
        raw_text = get_pane_text(pane_id, lines=lines)
        if not raw_text:
            return "No terminal buffer accessible for target pane."

        # Filter out empty lines and trailing prompts
        text_lines = [l.strip() for l in raw_text.splitlines() if l.strip()]
        
        # Look for recent user prompts or agent thoughts
        recent_context = []
        for line in text_lines[-15:]:
            # Clean prompt symbols
            clean = re.sub(r"^[❯$>#]\s*", "", line)
            if clean and not clean.startswith("Requesting permission"):
                recent_context.append(clean[:80])

        if recent_context:
            return " | ".join(recent_context[-3:])
        return "Context summary unavailable from visible lines."
    except Exception as e:
        return f"Context retrieval failed: {e}"


def investigate_filesystem_state(raw_path: str) -> Dict[str, Any]:
    """Perform in-depth, read-only inspection of the target path and its environment."""
    result: Dict[str, Any] = {
        "raw_path": raw_path,
        "resolved_path": "",
        "exists": False,
        "is_dir": False,
        "is_file": False,
        "size_human": "0B",
        "git_tracked": False,
        "git_clean": False,
        "sibling_backups": [],
        "risk_highlights": [],
    }

    if not raw_path or raw_path in ("unknown_target", "none"):
        return result

    try:
        p = canonicalize_path(raw_path)
        result["resolved_path"] = str(p)
        result["exists"] = p.exists()

        if result["exists"]:
            st = p.stat()
            result["is_dir"] = p.is_dir()
            result["is_file"] = p.is_file()
            
            # Human readable size
            size = st.st_size
            for unit in ['B', 'KB', 'MB', 'GB']:
                if size < 1024.0:
                    result["size_human"] = f"{size:.1f}{unit}"
                    break
                size /= 1024.0

            # Check Git Status
            result["git_tracked"] = is_inside_git_work_tree(p)
            if result["git_tracked"]:
                result["git_clean"] = is_git_clean_and_committed(p)

            # Check Sibling Backups (.bak, .old, .tmp, .sql.bak)
            parent = p.parent if p.is_file() else p
            if parent.exists() and parent.is_dir():
                stem = p.name
                backups = []
                for child in parent.iterdir():
                    if child.name != stem and (stem in child.name or child.name.endswith(('.bak', '.old', '.backup', '.tmp'))):
                        backups.append(child.name)
                result["sibling_backups"] = backups[:5]

        else:
            # Check if parent exists
            parent = p.parent
            if parent.exists():
                # Check for similar or backup files in parent
                stem = p.name
                backups = []
                for child in parent.iterdir():
                    if stem in child.name or child.name.endswith(('.bak', '.old', '.backup', '.tmp')):
                        backups.append(child.name)
                result["sibling_backups"] = backups[:5]

    except Exception as e:
        result["risk_highlights"].append(f"Inspection error: {e}")

    return result


def generate_inspector_fact_sheet(
    pane_id: str,
    raw_cmd: str,
    decision_layer: str,
    safety_reason: str,
    agent_kind: str = "agent"
) -> Dict[str, Any]:
    """Build a comprehensive, objective Security Fact Sheet."""
    
    # 1. Pipeline Evaluator Classification
    op_type, detected_target = classify_operation(raw_cmd)
    target_str = detected_target or "unknown_target"
    verdict, eval_reason, guidance = evaluate_gray_zone_operation(raw_cmd)
    
    # 2. Worker Pane Intent Investigation
    intent_summary = investigate_pane_intent(pane_id, lines=25)

    # 3. Filesystem & Backup State Investigation
    fs_state = investigate_filesystem_state(target_str)

    # 4. Synthesize Fact Sheet
    fact_sheet = {
        "target_pane": f"{pane_id} ({agent_kind})",
        "command": raw_cmd,
        "decision_layer": decision_layer,
        "intercept_reason": safety_reason,
        "worker_intent_context": intent_summary,
        "target_path": fs_state["resolved_path"] or target_str,
        "path_exists": fs_state["exists"],
        "target_type": "Directory" if fs_state["is_dir"] else ("File" if fs_state["is_file"] else "Non-existent / Glob"),
        "size": fs_state["size_human"],
        "git_protected": fs_state["git_tracked"],
        "sibling_backups_found": fs_state["sibling_backups"],
        "evaluator_verdict": verdict.value if hasattr(verdict, "value") else str(verdict),
        "resource_tier": guidance.tier.value if guidance else "UNKNOWN",
        "irreversibility": f"{guidance.irreversibility.value} ({guidance.irreversibility.name})" if guidance else "UNKNOWN",
        "blast_radius": guidance.blast_radius if guidance else "Local mutation",
        "remediation_advice": guidance.pre_alternative if guidance and guidance.pre_alternative else (guidance.recovery_path if guidance else "No specific remediation"),
    }

    return fact_sheet


def format_fact_sheet_for_prompt(fs: Dict[str, Any]) -> str:
    """Format Fact Sheet into high-density, token-efficient context for the Judge LLM."""
    backups_str = ", ".join(fs["sibling_backups_found"]) if fs["sibling_backups_found"] else "None found"
    
    lines = [
        f"• Intercepted Target: {fs['target_pane']} | Command: `{fs['command']}`",
        f"• Worker Intent Context: {fs['worker_intent_context']}",
        f"• Target Filesystem State: Exists={fs['path_exists']} | Type={fs['target_type']} | Size={fs['size']} | GitProtected={fs['git_protected']}",
        f"• Backup Status: {backups_str}",
        f"• Security Tier & Irreversibility: Tier={fs['resource_tier']} | Grade={fs['irreversibility']}",
        f"• Evaluator Warning: {fs['intercept_reason']}",
        f"• Recommended Safe Alternative: {fs['remediation_advice']}",
    ]
    return "\n  ".join(lines)


if __name__ == "__main__":
    test_cmd = "rm -rf /Users/kyjbusan/.local/share/database_backups_test_temp2"
    sheet = generate_inspector_fact_sheet("w1D:p1", test_cmd, "GRAY_ZONE_MATRIX", "Non-VCS Gray-Zone Guard [BLOCK]", "agy")
    print(format_fact_sheet_for_prompt(sheet))
