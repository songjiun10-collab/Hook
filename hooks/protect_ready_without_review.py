#!/usr/bin/env python3
"""PreToolUse hook (matcher: mcp__github__update_pull_request) enforcing
"don't skip the final whole-branch review."

Blocks marking a pull request ready-for-review (draft: false) unless
record_whole_branch_review.py's sentinel shows a whole-branch-review-type
Agent dispatch happened at the CURRENT git HEAD - any commit since the
last recorded review invalidates it, since a "whole-branch review" is
only meaningful against the branch's actual current state.

**HIGH severity, override available.** Denies by default. Override via
the same sentinel-file mechanism as the other guards - write
`<hooks dir>/.pending_override.json` with `{"rule":
"protect_ready_without_review", "target": "<owner>/<repo>#<pullNumber>",
"reason": "<reason>", "timestamp": <time.time()>}`. Note this uses a
DIFFERENT sentinel file than the whole-branch-review-happened sentinel
below (`.last_whole_branch_review_sha`) - one records "a review occurred",
the other records "skip the review-occurred check this once,
deliberately"."""
import json
import subprocess
import sys
from pathlib import Path

from _hook_common import (allow, allow_with_override, high_tier_decision,
                           require_decision_or_deny, sentinel_override)

HOOK_NAME = "protect_ready_without_review"
SEVERITY = "HIGH"

_SENTINEL = Path(__file__).parent / ".last_whole_branch_review_sha"


def read_input():
    return json.load(sys.stdin)


def current_head_sha():
    try:
        out = subprocess.run(["git", "rev-parse", "HEAD"], capture_output=True,
                              text=True, timeout=10, cwd=Path(__file__).parent)
        return out.stdout.strip() if out.returncode == 0 else None
    except Exception:
        return None


def main():
    data = read_input()
    ti = data.get("tool_input") or {}
    if ti.get("draft") is not False:
        allow()  # not a ready-for-review transition
        return

    reviewed_sha = _SENTINEL.read_text().strip() if _SENTINEL.exists() else None
    current_sha = current_head_sha()

    if reviewed_sha and current_sha and reviewed_sha == current_sha:
        allow()
        return

    if reviewed_sha and current_sha and reviewed_sha != current_sha:
        detail = (f"last whole-branch review was at {reviewed_sha[:7]}, "
                   f"current HEAD is {current_sha[:7]} - new commits landed since")
    else:
        detail = "no whole-branch review has been dispatched in this session"

    target = f"{ti.get('owner', '?')}/{ti.get('repo', '?')}#{ti.get('pullNumber', '?')}"
    decision = require_decision_or_deny(HOOK_NAME, SEVERITY, target, f"Blocking draft->ready ({detail}).")
    if decision is None:
        return

    override_reason = sentinel_override(HOOK_NAME, target)
    if override_reason:
        allow_with_override(HOOK_NAME, SEVERITY, HOOK_NAME, target, override_reason,
                             decision=decision)
        return

    high_tier_decision(
        HOOK_NAME, SEVERITY,
        "Don't skip the final whole-branch review - it catches bugs a "
        f"per-task review misses. Blocking draft->ready ({detail}). Dispatch "
        "a final whole-branch review Agent (mentioning \"whole-branch "
        "review\" in the prompt) against the current HEAD before marking "
        f'this PR ready. To override: write '
        f'hooks/.pending_override.json with {{"rule": "{HOOK_NAME}", '
        f'"target": "{target}", "reason": "<reason>", "timestamp": '
        "<time.time()>}, then retry immediately.",
        data, target=target, decision=decision,
    )


if __name__ == "__main__":
    main()
