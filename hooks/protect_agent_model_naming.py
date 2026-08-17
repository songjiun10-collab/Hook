#!/usr/bin/env python3
"""PreToolUse hook (matcher: Agent) enforcing "always name the model"
(omitting it inherits the session's, usually the priciest; sonnet default,
opus only for architecture/final review, skip haiku on multi-step work).

Flags an Agent dispatch that omits `model` entirely, or sets it to a
haiku variant. This hook can't judge whether sonnet vs opus is the right
call for a given task - it only catches the two mechanically-checkable
violations: no model named at all, and haiku.

**LOW severity, log-only.** A missing/haiku model is a cost-efficiency
nit, not a correctness or safety issue - it just logs to
violations_log.jsonl (visible to a human reviewing later) and always
allows, no interruption, no override dance needed."""
import json
import re
import sys

from _hook_common import allow, log_and_allow

HOOK_NAME = "protect_agent_model_naming"
SEVERITY = "LOW"

_HAIKU_RE = re.compile(r"haiku", re.IGNORECASE)


def read_input():
    return json.load(sys.stdin)


def main():
    data = read_input()
    if data.get("tool_name") != "Agent":
        allow()
        return
    ti = data.get("tool_input") or {}
    model = ti.get("model")
    # Agent dispatches have no file_path - reuse `description` as the
    # decision-record target, same as protect_reviewer_prejudging.py does
    # for the same matcher shape.
    target = str(ti.get("description", "")) or None

    if not model:
        log_and_allow(
            HOOK_NAME, SEVERITY,
            "Always name the model (omitting it inherits the session's, "
            "usually the priciest). This dispatch has no `model` field. "
            "Set model explicitly - `sonnet` by default, `opus` only for "
            "architecture/final whole-branch review.",
            target=target,
        )
        return

    if _HAIKU_RE.search(str(model)):
        log_and_allow(
            HOOK_NAME, SEVERITY,
            "Skip haiku - its extra turns on multi-step work cost more than "
            f"the tokens it saves. This dispatch names model={model!r}. Use "
            "`sonnet` (default) or `opus` (architecture/final whole-branch "
            "review only).",
            target=target,
        )
        return

    allow()


if __name__ == "__main__":
    main()
