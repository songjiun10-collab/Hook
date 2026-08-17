#!/usr/bin/env python3
"""PreToolUse hook (matcher: Bash) enforcing two git safety rules:

1. "Push rejected -> git fetch + git rebase, never force." Blocks
   `git push` with a force flag (--force/-f/--force-with-lease) outright.
2. "Every commit: fix authorship or GitHub marks it Unverified." Before
   a `git push`, checks the current HEAD commit's author email matches
   an expected identity - catches the case where a commit was made with
   a stale/human git config and never re-authored.

Text-matching a raw shell command string is inherently approximate, so
this only flags a `git push` that appears as an actual statement start
(after &&, ||, ;, a newline, a pipe, a subshell/backtick, or a shell
keyword like do/then/else - or at the very start of the command), allows
up to 6 recognized global git options (`-c k=v`, `-C dir`, `--long-flag
[=val]`, or a short flag) between `git` and `push`, and only inspects
that invocation's own trailing arguments (up to the next statement
separator) for a force flag - matching `--force`, `-f`, or
`--force-with-lease` with or without a `=<refspec>` suffix. This
deliberately does NOT match "git push" appearing inside a quoted
string/heredoc body/prose - e.g. a commit message or a test payload that
merely *mentions* "git push --force" as text, not as a command to run.
Verified against both a real bypass and that false-positive - none of
this is a substitute for a real shell parser, so this is still a
best-effort net, not a guarantee.

**Severity**: force-push is CRITICAL, with an override available via a
trailing `# HNCS-OVERRIDE: protect_push_safety: <reason>` comment (see
`_hook_common.py`'s module docstring for the tier design). The
authorship-mismatch check has no override - there's no legitimate reason
to push with the wrong author when the fix is one command; it's always
resolvable rather than something to consciously bypass.

Adjust `_CLAUDE_AUTHOR_EMAIL` for your own project's expected commit
author identity if adopting this hook elsewhere."""
import json
import re
import subprocess
import sys

from _hook_common import (allow, allow_with_override, bash_override, deny,
                           is_subagent_call, require_decision_or_deny)

HOOK_NAME = "protect_push_safety"
SEVERITY = "CRITICAL"

_CLAUDE_AUTHOR_EMAIL = "noreply@anthropic.com"

_STMT_START = r"(?:^|&&|\|\||;|\n|\||\(|`|\bdo\b|\bthen\b|\belse\b)\s*"
_GIT_GLOBAL_OPT = r"(?:-c\s+\S+|-C\s+\S+|--\S+(?:=\S+)?|-[A-Za-z])"
_PUSH_INVOCATION_RE = re.compile(
    _STMT_START + r"git(?:\s+" + _GIT_GLOBAL_OPT + r"){0,6}\s+push\b(?P<args>[^\n;&|`]*)"
)
_FORCE_RE = re.compile(r"(^|\s)(--force(-with-lease)?(=\S+)?|-f)(\s|$)")


def read_input():
    return json.load(sys.stdin)


def head_author_email():
    try:
        out = subprocess.run(["git", "log", "-1", "--format=%ae"],
                              capture_output=True, text=True, timeout=10)
        return out.stdout.strip() if out.returncode == 0 else None
    except Exception:
        return None


def main():
    data = read_input()
    if data.get("tool_name") != "Bash":
        allow()
        return
    command = str((data.get("tool_input") or {}).get("command", ""))

    matches = list(_PUSH_INVOCATION_RE.finditer(command))
    if not matches:
        allow()
        return

    for m in matches:
        if _FORCE_RE.search(m.group("args")):
            decision = require_decision_or_deny(
                HOOK_NAME, SEVERITY, command,
                "Push rejected -> git fetch + git rebase, never force. "
                "This command force-pushes.")
            if decision is None:
                return
            if is_subagent_call(data):
                deny(
                    HOOK_NAME,
                    "Push rejected -> git fetch + git rebase, never force. "
                    "This command force-pushes, and this call is "
                    "subagent-originated (agent_id present) - CRITICAL-tier "
                    "override is self-servable via a bash comment the "
                    "subagent itself could write, so force-push from a "
                    "subagent gets no override path at all. Have the "
                    "controller run this directly.",
                    severity=SEVERITY, target=command, decision=decision,
                )
                return
            override_reason = bash_override(HOOK_NAME, command)
            if override_reason:
                allow_with_override(HOOK_NAME, SEVERITY, HOOK_NAME, command, override_reason,
                                     decision=decision)
                return
            deny(
                HOOK_NAME,
                "Push rejected -> git fetch + git rebase, never force. "
                "This command force-pushes. If the remote rejected a push, "
                "fetch and rebase instead - never force, even with "
                "--force-with-lease, unless explicitly authorized. To "
                "override: add a trailing `# HNCS-OVERRIDE: "
                f"{HOOK_NAME}: <reason>` comment to this command.",
                severity=SEVERITY, target=command, decision=decision,
            )
            return

    email = head_author_email()
    if email is not None and email != _CLAUDE_AUTHOR_EMAIL:
        decision = require_decision_or_deny(
            HOOK_NAME, "HIGH", command,
            "Fix authorship or GitHub marks it Unverified. "
            f"HEAD commit's author email is {email!r}.")
        if decision is None:
            return
        deny(
            HOOK_NAME,
            "Fix authorship or GitHub marks it Unverified. "
            f"HEAD commit's author email is {email!r}, not "
            f"{_CLAUDE_AUTHOR_EMAIL!r}. Run `git config user.email "
            f"{_CLAUDE_AUTHOR_EMAIL} && git config user.name Claude` then "
            "re-author HEAD (amend or rebase --exec) before pushing. No "
            "override for this one - just fix it.",
            severity="HIGH", target=command, decision=decision,
        )
        return

    allow()


if __name__ == "__main__":
    main()
