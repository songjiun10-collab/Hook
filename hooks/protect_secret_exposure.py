#!/usr/bin/env python3
"""PreToolUse hook (matcher: Edit|Write|MultiEdit, Bash), HIGH severity.
Scans the content about to be written/committed for text that looks like a
live credential - an AWS access key ID, a GitHub token, a private key
header, or a Slack token - and blocks before it lands in a file or a Bash
command.

Edit/Write/MultiEdit: scans `content` (Write) / `new_string` (Edit) /
each edit's `new_string` (MultiEdit). Bash: scans `command`.

**Known limitation**: pattern matching only, no entropy/"does this look
real" heuristic - a placeholder value that happens to match one of these
four shapes (`AKIAABCDEFGHIJKLMNOP` in a comment, a fake `ghp_...` in a
docstring) is indistinguishable from a live key. High-entropy heuristics
were deliberately left out of v1 - `protect_push_safety.py`'s regex has
already been revised twice over false positives/bypasses, and the same
tradeoff applies here.

Override: trailing `# HNCS-OVERRIDE: protect_secret_exposure: <reason>`
comment (Bash), or the same sentinel-file mechanism as the other
Edit/Write/MultiEdit guards (Edit/Write/MultiEdit)."""
import json
import re
import sys

from _hook_common import (allow, allow_with_override, bash_override,
                           high_tier_decision, require_decision_or_deny,
                           sentinel_override)

HOOK_NAME = "protect_secret_exposure"
SEVERITY = "HIGH"

_SECRET_PATTERNS = [
    ("AWS Access Key", re.compile(r"AKIA[0-9A-Z]{16}")),
    ("GitHub Token", re.compile(r"gh[pousr]_[A-Za-z0-9]{36,}")),
    ("Private Key Header", re.compile(r"-----BEGIN (RSA |EC |OPENSSH |)?PRIVATE KEY-----")),
    ("Slack Token", re.compile(r"xox[baprs]-[0-9A-Za-z-]{10,48}")),
]


def read_input():
    return json.load(sys.stdin)


def find_secret_pattern(text):
    """Returns the matched pattern's name if `text` contains something that
    looks like a live credential, else None."""
    if not text:
        return None
    for name, pattern in _SECRET_PATTERNS:
        if pattern.search(text):
            return name
    return None


def _edit_write_content(tool_input):
    edits = tool_input.get("edits")
    if isinstance(edits, list):
        return "\n".join(str(e.get("new_string", "")) for e in edits if isinstance(e, dict))
    if "new_string" in tool_input:
        return str(tool_input.get("new_string", ""))
    return str(tool_input.get("content", ""))


def main():
    data = read_input()
    tool_name = data.get("tool_name")
    ti = data.get("tool_input") or {}

    if tool_name in ("Edit", "Write", "MultiEdit"):
        content = _edit_write_content(ti)
        target = str(ti.get("file_path", ""))
    elif tool_name == "Bash":
        content = str(ti.get("command", ""))
        target = content
    else:
        allow()
        return

    pattern_name = find_secret_pattern(content)
    if pattern_name is None:
        allow()
        return

    decision = require_decision_or_deny(
        HOOK_NAME, SEVERITY, target,
        f"This looks like it contains a live credential (matched: {pattern_name}).")
    if decision is None:
        return

    if tool_name == "Bash":
        override_reason = bash_override(HOOK_NAME, content)
    else:
        override_reason = sentinel_override(HOOK_NAME, target)
    if override_reason:
        allow_with_override(HOOK_NAME, SEVERITY, HOOK_NAME, target, override_reason,
                             decision=decision)
        return

    if tool_name == "Bash":
        override_hint = (f"To override: add a trailing `# HNCS-OVERRIDE: "
                          f"{HOOK_NAME}: <reason>` comment to the command.")
    else:
        override_hint = (f'To override: write hooks/.pending_override.json with '
                          f'{{"rule": "{HOOK_NAME}", "target": "{target}", '
                          '"reason": "<reason>", "timestamp": <time.time()>}, '
                          "then retry immediately.")

    high_tier_decision(
        HOOK_NAME, SEVERITY,
        f"This looks like it contains a live credential (matched: {pattern_name}) - "
        "if this is a real key, rotate it and use a secrets manager/env var "
        f"instead. If it's a placeholder that happens to match the pattern, "
        f"{override_hint}",
        data, target=target, decision=decision,
    )


if __name__ == "__main__":
    main()
