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
    ("AWS Access Key", re.compile(r"(?:AKIA|ASIA)[0-9A-Z]{16}")),
    ("GitHub Token", re.compile(r"gh[pousr]_[A-Za-z0-9]{36,}")),
    ("GitHub Fine-Grained PAT", re.compile(r"github_pat_[A-Za-z0-9_]{20,}")),
    ("Private Key Header", re.compile(r"-----BEGIN (RSA |EC |OPENSSH |)?PRIVATE KEY-----")),
    ("Slack Token", re.compile(r"xox[baprs]-[0-9A-Za-z-]{10,48}")),
    ("Slack App-Level Token", re.compile(r"xapp-[0-9A-Za-z-]{10,}")),
    ("Slack Workflow Token", re.compile(r"xwfp-[0-9A-Za-z-]{10,}")),
    ("Slack Token Exchange", re.compile(r"xoxe[.-][0-9A-Za-z-]{10,}")),
]


def read_input():
    return json.load(sys.stdin)


def find_secret_pattern(text):
    """Returns the matched pattern's name if `text` contains something that
    looks like a live credential, else None."""
    match = _find_secret_match(text)
    return match[0] if match else None


def _find_secret_match(text):
    """Like find_secret_pattern(), but also returns the compiled pattern
    that matched, so callers can redact exactly what was found (see
    redact_secret())."""
    if not text:
        return None
    for name, pattern in _SECRET_PATTERNS:
        if pattern.search(text):
            return name, pattern
    return None


def redact_secret(text, pattern):
    """Replaces every match of `pattern` in `text` with a fixed
    placeholder - used so a Bash command that matched a secret pattern
    never has the live credential copied verbatim into target= (and, via
    that, into violations_log.jsonl/override_audit.jsonl)."""
    return pattern.sub("[REDACTED-SECRET]", text)


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

    match = _find_secret_match(content)
    if match is None:
        allow()
        return
    pattern_name, pattern = match

    if tool_name == "Bash":
        # Redact once here - every downstream call (require_decision_or_deny/
        # bash_override/deny/allow_with_override) must reuse this exact
        # value so the target the deny message advertises is the same one
        # the agent later reuses, and so the live credential never lands in
        # violations_log.jsonl/override_audit.jsonl.
        target = redact_secret(target, pattern)

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
