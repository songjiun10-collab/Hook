# Hook

Severity-tiered PreToolUse/PostToolUse guard hooks for Claude Code — a
project-agnostic extraction of the hook safety framework built in
[songjiun10-collab/hncs](https://github.com/songjiun10-collab/hncs).

## What this is

A Claude Code plugin providing:

- **4-tier severity model** (`hooks/_hook_common.py`): LOW (log-only),
  MEDIUM (higher-agent approval), HIGH (ask a human, or hard-deny from a
  subagent), CRITICAL (deny by default, no override at all from a
  subagent).
- **Override mechanism** — a deliberate, explicitly-declared bypass
  (trailing `# HNCS-OVERRIDE: <rule>: <reason>` bash comment, or a
  sentinel file for Edit/Write/MultiEdit guards) is always honored, but
  every use is logged to `override_audit.jsonl` with the git sha it was
  granted at. Hooks don't substitute for the developer's judgment — they
  only stop an unconscious, silent slide into a dangerous action.
- **Decision Record + must_hook** — before a guarded action, the agent
  can (and, once the mandatory gate applies, must) self-report its own
  risk judgment (severity/confidence/reason/expected_risk) via the
  `mcp__must_hook__write_decision_record` MCP tool. The tool's parameter
  schema (pydantic `Field` constraints) rejects malformed calls before
  they reach any code — no more silently-wrong JSON written by hand. The
  record attaches to whatever log entry the guard hook produces, so
  `tools/eval_hook_judgments.py` can later compare what the agent
  predicted against what actually happened (blocked / a human was asked
  (structurally unobservable) / reverted / not reverted).
- **8 guard hooks**: `protect_destructive` (CRITICAL — `rm -rf`,
  `git reset --hard`, `git clean -f`, `git branch -D`),
  `protect_push_safety` (CRITICAL force-push / HIGH commit authorship),
  `protect_branch` (HIGH — committing/pushing to main/master/detached
  HEAD), `protect_reviewer_prejudging` (HIGH — dispatching a code
  reviewer with pre-judged findings), `protect_ready_without_review`
  (HIGH — marking a PR ready without a recorded whole-branch review),
  `protect_agent_model_naming` (LOW — Agent dispatch missing `model` or
  using haiku), `protect_test_coverage` (HIGH — committing a new source
  file with no test), `protect_secret_exposure` (HIGH — an Edit/Write/
  MultiEdit or Bash call whose content matches an AWS access key, a
  GitHub token, a private key header, or a Slack token).
- **`must_hook_server.py`** — the local MCP server backing the schema
  enforcement above.
- **`tools/rotate_hook_logs.py`** / **`tools/eval_hook_judgments.py`** —
  standalone maintenance scripts (not wired into the hook chain; run
  manually or on a schedule).

## What this is *not*

No guard hook here uses MEDIUM severity — the mechanism
(`allow_with_medium_approval()`, `record_agent_approval.py`,
`deliver_caution.py`) is included and tested so a downstream project can
build its own MEDIUM-tier guard on top of it, but none of the bundled
guards currently need it.

This plugin also doesn't include any project-specific guards. The
originating project (Hncs) keeps three of its own on top of this
framework — a "never touch this shipped artifact" guard, a "don't
hand-edit this generated file" guard, and a "no unbacked numeric claims
in docs" guard — because their triggers (specific file paths, specific
claim patterns) are inherently project-specific. Use this repo's hooks
as the reusable core and write guards like those for your own project's
own invariants.

## Install

```bash
claude plugin marketplace add songjiun10-collab/hook
claude plugin install hook@hook
```

This registers the hooks in `hooks/hooks.json` and the `must_hook` MCP
server in `.mcp.json`, both resolved relative to `${CLAUDE_PLUGIN_ROOT}`.

Requires `mcp==2.0.0` (see `requirements.txt`) for `must_hook_server.py`.

## Adapting for your project

- `protect_push_safety.py`'s `_CLAUDE_AUTHOR_EMAIL` — set to your
  project's expected commit author identity.
- `protect_test_coverage.py`'s `_COVERAGE_EXPECTED_DIR_RE` — set to your
  own source layout (defaults to `tools/`, `brands/`, `core/`,
  `hybrid_engine/` — the originating project's directories).
- Every hook reads its sentinel/log paths from `HNCS_HOOK_*` environment
  variables when set, falling back to files next to the hook script
  itself otherwise (`_hook_common.py`'s module-level `_HOOKS_DIR`). The
  env var names carry the originating project's name; they're just
  strings and don't need renaming to work.
- Override-mechanism prose in `protect_reviewer_prejudging.py` /
  `protect_ready_without_review.py`'s deny messages says
  `hooks/.pending_override.json` — that's relative to wherever the hook
  script itself actually runs from (typically the plugin's installed
  location), not a fixed path.

## Testing

```bash
pip install -r requirements.txt
python3 -m unittest discover -s tests
```

208 tests, all hook logic covered end-to-end via real subprocess
invocation (not mocked) — each test isolates its log/sentinel files via
`HNCS_HOOK_*` environment variable overrides so a test run never touches
this repo's own `hooks/violations_log.jsonl`.

## Known limitations

- **Text/regex matching, not a real shell parser.** The Bash-triggered
  guards (`protect_destructive`, `protect_push_safety`, `protect_branch`,
  `protect_test_coverage`) share a `_STMT_START` + heredoc-stripping
  pattern that closes known false-positive/bypass classes (global git
  options between `git` and `push`, `--force-with-lease=<refspec>`,
  heredoc prose merely *mentioning* a dangerous command) but a
  sufficiently unusual shell construct can still slip through either
  direction.
- **Override is self-servable.** If an agent fabricates a reason (e.g.
  "user approved" when they didn't), no hook here can verify that from
  the conversation it can't see. The design only guarantees a
  *conscious, logged* action — not a *true* one. MEDIUM's opus-only
  approval marker raises the forgery cost one level but doesn't close
  it, since a controller could still write a dispatch prompt that
  demands approval.
- **`ask()`'s real human answer is structurally unobservable.** Claude
  Code's runtime resolves the interactive prompt outside this process,
  after the hook script has already exited — `eval_hook_judgments.py`
  can only ever report `ask_unknown` for that path, never a real
  approved/denied outcome.
- **`ask()` fails open inside a subagent's own turn** — there's no
  interactive surface to render the prompt on. Every guard here checks
  `is_subagent_call()` before choosing `ask()` vs. a hard `deny()`
  specifically because of this; if you build a new guard on this
  framework, do the same.

## License

MIT
