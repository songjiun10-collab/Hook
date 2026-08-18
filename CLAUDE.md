# CLAUDE.md

Severity-tiered Claude Code guard hooks, extracted from
[songjiun10-collab/hncs](https://github.com/songjiun10-collab/hncs) to be
project-agnostic. See `README.md`/`README.ko.md` for what's here and how
to install it.

## Testing

```bash
python3 -m unittest discover -s tests
```

`unittest` only, no pytest. Full suite green before every commit — 182
tests as of the last count, every hook exercised end-to-end via real
`subprocess.run([sys.executable, hook.__file__], ...)` calls, not mocked.
Every test isolates its own log/sentinel files via `HNCS_HOOK_*`
environment variable overrides (see any existing `tests/test_hooks_*.py`
for the pattern) — a test run must never touch this repo's own
`hooks/violations_log.jsonl`/`override_audit.jsonl`.

## `HNCS_HOOK_*` env var names

The env vars (`HNCS_HOOK_VIOLATIONS_LOG`, `HNCS_HOOK_OVERRIDE_SENTINEL`,
etc.) carry the originating project's name. That's cosmetic, not
functional — they're just override keys `_hook_common.py` reads at
import time; nothing about their behavior is Hncs-specific. Don't rename
them "to be generic" — that's a mechanical, high-blast-radius rename
across every hook and every test for zero behavior change.

## MCP tool naming depends on install path — a real gotcha

`must_hook_server.py`'s tool is registered under the key `"must_hook"` in
`.mcp.json`. The **actual tool name Claude Code exposes differs by how
this gets installed**:

- Project-level `.mcp.json` (e.g. a project vendoring this repo's files
  directly, like Hncs did before the plugin cutover): the tool shows up
  as `mcp__must_hook__write_decision_record`.
- Installed as a plugin (`claude plugin install hook@hook`, the intended
  path): Claude Code namespaces it by plugin name, so the tool becomes
  `mcp__plugin_hook_must_hook__write_decision_record` instead — found by
  live-testing a cold-start session on 2026-08-18, not documented
  anywhere obvious beforehand.

Every guard hook's `require_decision_or_deny()` deny message (in
`_hook_common.py`) hardcodes the tool name it tells the agent to call.
**If this plugin is ever installed under a different plugin name than
`hook`** (a marketplace fork, a rename), that hardcoded string goes
stale and the deny message points at a tool that doesn't exist. There's
no way to introspect "what name did Claude Code give me" from inside a
hook script — if you rename the plugin, grep `_hook_common.py` for
`mcp__plugin_hook_must_hook__` and fix every occurrence by hand, and
re-verify live (a stale tool name in a deny message just wastes the
agent's next retry, it doesn't fail loudly).

## `_hook_common.py` is intentionally duplicated, not shared

Hncs kept its own copy of `_hook_common.py` (plus `tools/rotate_hook_logs.py`/
`tools/eval_hook_judgments.py`, which read its local log files) after the
plugin cutover, because its 4 remaining project-specific guards
(`protect_never_touch.py` etc.) import it directly and a live cross-repo
runtime dependency for CRITICAL-tier safety hooks was judged too fragile
(this session hit a GitHub outage, a permission-propagation delay, and a
local cwd bug — any one of which would have left Hncs's own safety net
missing mid-session if it depended on this repo being reachable). If you
fork or vendor these hooks into another project, the same tradeoff
applies: importing this repo's `_hook_common.py` live means your guards
go dark if this repo (or the plugin marketplace) is ever unreachable.
Vendoring your own copy costs a manual sync on updates but never goes
dark.

## Adding a new guard hook

Follow the shape of any existing one in `hooks/`: read stdin JSON, decide
severity, call `require_decision_or_deny()` **before** checking for an
override (the mandatory decision-record gate applies to every
MEDIUM/HIGH/CRITICAL guard, no exceptions), thread the returned
`decision` into whatever `deny()`/`ask()`/`allow_with_override()`/
`high_tier_decision()` call follows. Register it in `hooks/hooks.json`
under the right matcher, and write its test the same way every existing
`tests/test_hooks_*.py` does — isolated env vars, real subprocess calls,
not mocks.
