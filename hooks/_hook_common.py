"""Shared allow/deny/override helpers for this project's PreToolUse/
PostToolUse hooks.

## Severity tiers (2026-08 redesign, user-specified)

- LOW: allow, log only (no interruption).
- MID/HIGH/CRITICAL: deny unless a valid override is present (see below).
  Mechanically identical across all three tiers - severity is now purely
  a label/messaging-tone distinction, not a different code path.

**정정(2026-08-15)**: MID originally used `permissionDecision: "ask"`
(falls through to Claude Code's normal interactive permission prompt) on
the theory that a human glance beats a hard block for lower-stakes
findings. Dispatched a real subagent to test whether this hook chain
applies to subagent tool calls at all, and found: Bash-triggered deny
hooks correctly blocked the subagent, but an `ask()`-based hook let the
subagent's Edit through with no prompt and no denial - there's no
interactive surface to render the prompt on inside a subagent's own turn,
so it silently resolved to allow. Since a Controller-dispatches-subagents
workflow is common, `ask()` provided zero protection in exactly that
case. Former `ask()`-using MEDIUM-tier hooks were converted to
deny+override; `ask()` remains defined below (still valid, still used if
some future hook genuinely only ever fires on direct orchestrator calls)
but HIGH tier is the only active user as of this correction. The
`_hook_common.py` git_sha handling below was also never actually a
CRITICAL-only gate - see the note in `_record_override()`.

**추가 재설계 (2026-08-15, 사용자 확정 스펙)**: 4단계를 실제로 다르게
동작시킨다 -

- LOW: `log_and_allow()` - 항상 allow, 로그만(기존 그대로).
- MEDIUM: "상위 에이전트가 허용하면 실행 에이전트가 실행, 단 주의사항
  전달." `record_agent_approval.py`(PostToolUse, Agent matcher)가 실제
  디스패치된 서브에이전트의 응답에서 `MEDIUM-APPROVE: <rule> ::
  <target> :: <caution>` 마커를 파싱하고(모델이 opus일 때만 인정, sonnet도
  불인정) `medium_approval()`로 소비 가능한 승인을 기록한다 - 자기 자신이
  바로 못 쓰고 진짜 Agent 디스패치가 있어야 생기는 sentinel이라
  self-declared override보다 위조 난이도가 한 단계 높다. plain
  self-declared override(bash 주석/sentinel)는 MEDIUM에서 완전히 제거됨
  - MEDIUM-APPROVE와 나란히 열려있으면 컨트롤러가 항상 더 쉬운 override
  쪽만 써서 "상위 에이전트 승인" 경로가 죽은 코드가 되는 문제가 있었다.
  통과시킬 때 caution 문구는 `write_pending_caution()`으로 `tool_use_id`에
  묶어 기록하고, `deliver_caution.py`(PostToolUse, Edit|Write|MultiEdit
  matcher)가 같은 `tool_use_id`로 찾아서 `additionalContext`로 실행
  에이전트한테 전달한다 - PreToolUse의 "allow" 시
  `permissionDecisionReason`은 모델한테 전달 안 된다는 게 문서상 확정이라,
  PostToolUse의 `additionalContext`(같은 툴 결과에 append, 문서상 확정)로
  우회했다.
- HIGH: "사람 승인." `is_subagent_call(data)`로 분기 - 오케스트레이터
  직접 호출(agent_id 없음)이면 `ask()`(실측 확인된 대로 실제 사람
  프롬프트가 뜬다), 서브에이전트발 호출(agent_id 있음)이면 override
  없이는 무조건 deny(ask()가 서브에이전트에서 fail-open이라는 걸 이미
  확인했으므로 - 위 정정 항목 참고). override는 두 경로 모두에서 여전히
  유효한 사전 선언 우회.
- CRITICAL: 서브에이전트발 호출은 override조차 받지 않고 무조건 deny -
  "override는 self-servable"이라는 한계가 가장 치명적인 등급이라,
  서브에이전트가 스스로 bash 주석/sentinel 파일을 써서 통과하는 경로
  자체를 없앴다. 오케스트레이터 직접 호출은 기존 override 메커니즘 그대로.

**추가 (Decision Record 파이프라인)**: 4단계 위에 로깅 전용 레이어 하나를
얹었다 - `write_decision_record()`/`decision_record()` sentinel(에이전트
스스로 위험도를 self-report, `.pending_decision_record.json`)이
`deny()`/`ask()`/`log_and_allow()`/`allow_with_override()`/
`allow_with_medium_approval()` 각각에 `target=`/`decision_id=` 인자로
연결됐다 - 원래는 **allow/deny를 절대 gating하지 않는** 로깅 전용
레이어였다. 매칭되는 fresh 레코드가 있으면 `_log_event()`/
`_record_override()`가 쓰는 항목에 `decision` 키(self_severity/
confidence/reason/expected_risk)로 붙는다. `_log_event()`도 새
`decision_kind` 필드를 받는다 - `deny()`와 `ask()`가 원래 구조적으로
동일한 로그 항목을 써서 사후에 둘을 구분할 방법이 없었는데, `ask()`의
실제 사람 답변은 Claude Code 런타임이 훅 프로세스 밖에서 처리해 이
프로세스에서 영원히 관측 불가능하다는 게 확인돼서(`ask()` 자체 docstring
참고), 최소한 "이건 ask였다"는 구분이라도 남기려고 추가했다.

**정정(같은 날, "그거도 훅 걸어라 강제적훅 예외 없이")**: 로깅 전용이던
게 바뀌었다. organic 테스트(테스트라고 안 밝히고 서브에이전트한테 실제
작업 시킴 - 문서화돼 있고 실제로 읽었는데도 자발적으로 안 씀)로
"문서화만 해두면 쓰이겠지"가 성립 안 한다는 게 확인된 뒤,
`require_decision_or_deny()`(신규)가 MEDIUM/HIGH/CRITICAL 전부에서
override/MEDIUM-APPROVE/ask 판단 **보다 먼저** 실행되는 필수 게이트로
추가됐다 - decision record가 없으면 그 어떤 통과 경로도 안 보고 무조건
deny, 예외 없음(subagent/direct 구분 없음). 이 필수 조회는 1회성
sentinel을 소비하므로, 그 결과(`decision`)를
`deny()`/`ask()`/`allow_with_override()`/`allow_with_medium_approval()`/
`high_tier_decision()` 호출에 `decision=` 인자로 그대로 넘겨야 한다 -
새로 `decision_record()`를 또 조회하면 항상 아무것도 못 찾는다(`_UNSET`
sentinel로 "넘겨받은 값 그대로 써라" vs "네가 알아서 조회해라"를 구분).
LOW 등급은 이 게이트 대상이 아님 - LOW의 "마찰 없음" 설계는 별개로 이미
확정된 결정이라 안 뒤집었다.

**정정(같은 날, must훅 - MCP 툴 스키마 강제)**:
`require_decision_or_deny()`의 deny 메시지가 안내하던 통로가 바뀌었다.
원래는 "Write 툴로 `.pending_decision_record.json`에 이런 모양 JSON을
써라"였는데, 이건 자유 텍스트라 필드 누락/타입 오류/범위 밖 confidence를
막을 수단이 나중에 읽는 `decision_record()`쪽 검증뿐이었다. 이제는
`must_hook_server.py`가 노출하는 `mcp__plugin_hook_must_hook__write_decision_record`
MCP 툴 호출을 안내한다 - 파라미터 타입 힌트 + pydantic `Field` 제약
(severity는 LOW/MEDIUM/HIGH/CRITICAL 패턴, confidence는 0.0-1.0,
reason/expected_risk는 non-empty)이 MCP 프로토콜 단에서 검증돼서,
스키마를 어긴 호출은 이 모듈의 코드에 도달하지도 못한다. 툴 내부는 이
파일의 `write_decision_record()`를 그대로 호출하므로 저장 포맷/
`decision_record()` 읽기 쪽은 전혀 안 바뀌었다 - 단일 소스 유지. Write
툴로 sentinel 파일을 직접 쓰는 옛 경로는 `protect_decision_record_bypass.py`
(override 없음)가 무조건 막아서 MCP 툴이 유일한 통로가 되게 했다.

## Override mechanism

The point: hooks don't substitute for the developer's judgment; they only
stop an unconscious/silent slide into a dangerous action. A deliberate,
explicitly-declared override is always allowed through, but it leaves a
permanent trace of why.

Two ways to declare an override, matching the two hook trigger shapes:

1. **Bash-triggered guards** (destructive ops, push safety): the command
   text itself carries a trailing marker comment -
   `... # HNCS-OVERRIDE: <rule>: <reason>`. Parsed by `bash_override()`.
2. **Edit/Write/MultiEdit-triggered guards**: tool_input has no room for a
   custom field, so the override is declared via a sentinel file written
   *before* the guarded call - `<hooks dir>/.pending_override.json`
   (`{"rule", "target", "reason", "timestamp"}`). Checked (and consumed -
   single use) by `sentinel_override()`.

Every successful override is logged to `override_audit.jsonl` (separate
from `violations_log.jsonl`, which is for calls that were actually
blocked) with `{timestamp, rule, severity, target, reason, git_sha}` -
`git_sha` is always computed here, never taken from the caller, so the
audit trail can't be backdated or spoofed by whatever wrote the marker.

## TOTP added-confirmation step (CRITICAL override only)

**정정(2026-08-18, "설계 굿?" 리뷰)**: 최초 안은 이걸 "물리적 키"로,
"override self-servable 문제를 완화"한다고 프레이밍했는데 과장이었다.
TOTP secret을 `HNCS_HOOK_OVERRIDE_TOTP_SECRET` env var에 두면, 에이전트가
Bash로 `echo $HNCS_HOOK_OVERRIDE_TOTP_SECRET` 한 줄이면 secret을 그대로
읽고 스스로 코드를 계산할 수 있다 - 악의적이거나 판단이 틀린 에이전트를
막는 방어력은 사실상 0. 이 메커니즘이 실제로 막는 건 "에이전트가 사용자
승인 없이 무의식적으로/일상적으로 CRITICAL override를 남발하는 것"뿐이고,
그게 이 파일 상단의 훅 철학("훅은 위험한 행동을 무의식적으로 해버리는
것만 막는다")과 정확히 일치하는 수준의 부주의 방지용 추가 확인 단계
(added friction)다 - 완전한 검증이 아니다. `HNCS_HOOK_OVERRIDE_TOTP_SECRET`은
저장소에 커밋하지 않고 사용자가 환경변수로 직접 설정하며, 인증 앱과 같은
secret을 공유해서 코드는 대화창에서 사용자가 직접 불러주는 방식을
전제로 한다 - 에이전트가 스스로 env를 읽어서 계산하지 않는다는 신뢰가
전제라는 뜻이다.

포맷: `# HNCS-OVERRIDE: <rule>: <reason> key=<6자리 코드>` - 기존
`bash_override()`가 파싱하는 마커에 `key=<code>`를 덧붙인다.
`bash_override()` 자체는 이 기능으로 전혀 안 바뀐다(시그니처/리턴 타입
그대로) - 대신 `bash_override_with_totp()`가 CRITICAL 전용 훅에서만
쓰인다."""
import json
import os
import re
import subprocess
import sys
import time
from datetime import datetime, timezone

import pyotp

_HOOKS_DIR = os.path.dirname(os.path.abspath(__file__))
_LOG_PATH = os.environ.get(
    "HNCS_HOOK_VIOLATIONS_LOG", os.path.join(_HOOKS_DIR, "violations_log.jsonl"))
_OVERRIDE_AUDIT_PATH = os.environ.get(
    "HNCS_HOOK_OVERRIDE_AUDIT_LOG", os.path.join(_HOOKS_DIR, "override_audit.jsonl"))
_SENTINEL_PATH = os.environ.get(
    "HNCS_HOOK_OVERRIDE_SENTINEL", os.path.join(_HOOKS_DIR, ".pending_override.json"))
_MEDIUM_APPROVAL_PATH = os.environ.get(
    "HNCS_HOOK_MEDIUM_APPROVAL_SENTINEL",
    os.path.join(_HOOKS_DIR, ".pending_medium_approval.json"))
_PENDING_CAUTION_PATH = os.environ.get(
    "HNCS_HOOK_PENDING_CAUTION", os.path.join(_HOOKS_DIR, ".pending_caution.json"))
_DECISION_RECORD_PATH = os.environ.get(
    "HNCS_HOOK_DECISION_RECORD_SENTINEL",
    os.path.join(_HOOKS_DIR, ".pending_decision_record.json"))

SEVERITIES = ("LOW", "MEDIUM", "HIGH", "CRITICAL")

_BASH_OVERRIDE_RE = re.compile(
    r"#\s*HNCS-OVERRIDE:\s*(?P<rule>[\w.-]+)\s*:\s*(?P<reason>.+?)\s*$")
_TOTP_KEY_RE = re.compile(r"key=(\d{6})")

# Strips heredoc bodies (`<<EOF ... EOF`) out of a Bash command string
# before other regexes scan it - shared by bash_override() below (so a
# heredoc payload can't smuggle in a fake override marker, see its
# docstring) and by protect_branch.py/protect_test_coverage.py/
# protect_destructive.py, which each stripped their own copy of this
# before matching commit/push/destructive-command patterns.
_HEREDOC_RE = re.compile(r"<<-?\s*[\"']?(\w+)[\"']?.*?\n.*?^\1\b", re.DOTALL | re.MULTILINE)

_SENTINEL_MAX_AGE_SECONDS = 600  # 10min - forces a fresh, deliberate write
_MEDIUM_APPROVAL_MAX_AGE_SECONDS = 600
_DECISION_RECORD_MAX_AGE_SECONDS = 600

# Distinguishes "no decision was passed, look it up yourself" (the default,
# backward-compatible behavior) from "decision=None was passed explicitly,
# meaning the caller already looked and found nothing - don't look again."
# Needed because decision_record()'s sentinel is single-use/consumed on
# read: require_decision_or_deny() below does the one lookup a guard hook
# is allowed to make, and every downstream deny()/ask()/allow_with_*() call
# must reuse that exact result rather than querying the sentinel again.
_UNSET = object()


def allow():
    print(json.dumps({"hookSpecificOutput": {
        "hookEventName": "PreToolUse", "permissionDecision": "allow"}}))


def log_and_allow(hook_name, severity, reason, target=None, decision_id=None, decision=_UNSET):
    """LOW tier: record the finding to violations_log.jsonl (so it's
    visible to a human reviewing the log later) but never interrupt the
    call - no deny, no ask, no override needed. LOW tier is NOT covered by
    the mandatory decision-record gate (require_decision_or_deny()) - that
    would reintroduce exactly the friction LOW was created to remove.

    `target`/`decision_id`: if a fresh, matching decision record exists
    (see write_decision_record()), attach it to the log entry - see
    decision_record()'s docstring for the matching rule. `decision=`: pass
    an already-resolved lookup (e.g. from require_decision_or_deny()) to
    skip the internal lookup - default _UNSET means "look it up yourself"
    (backward compatible)."""
    dr = decision_record(hook_name, target=target, decision_id=decision_id) if decision is _UNSET else decision
    _log_event(hook_name, severity, reason, overridden=False,
               decision_kind="log_and_allow", target=target, decision=dr)
    allow()


def is_subagent_call(data):
    """True if this PreToolUse/PostToolUse hook input came from a
    dispatched subagent's own tool call rather than the direct
    orchestrator - detected via the `agent_id` field, confirmed
    empirically to be present only on subagent-originated calls, absent on
    direct orchestrator calls."""
    return "agent_id" in data


def ask(hook_name, severity, reason, target=None, decision_id=None, decision=_UNSET):
    """HIGH tier's default path for a DIRECT orchestrator call only
    (agent_id absent from the hook input - check with is_subagent_call()
    before calling this). Hands off to Claude Code's own interactive
    permission prompt - human approves/denies, in the moment, through the
    normal UI. Confirmed live to actually surface a real prompt for direct
    calls, both approved and denied independently.

    NEVER call this when is_subagent_call(data) is True: confirmed live
    that ask() silently resolves to allow with no prompt at all inside a
    dispatched subagent's own turn - there's no interactive surface to
    render it on. That fail-open behavior is exactly why the former
    MID-tier ask() users were converted to deny+override; HIGH's use of
    ask() here is safe only because it's gated on agent_id being absent.

    Logged like deny() so violations_log.jsonl carries every HIGH-tier
    trigger, not only the ones a human happened to deny.

    **정정**: the eventual human answer to this prompt is NOT observable
    from anywhere in this process - Claude Code's runtime resolves the
    interactive prompt out-of-process, and this script has already exited
    by the time that happens. `decision_kind="ask"` in the log entry marks
    this explicitly so an eval tool reports `ask_unknown` rather than
    guessing at an outcome it structurally cannot observe.

    `decision=`: pass an already-resolved lookup to skip the internal one
    - default _UNSET looks it up here (backward compatible)."""
    dr = decision_record(hook_name, target=target, decision_id=decision_id) if decision is _UNSET else decision
    _log_event(hook_name, severity, reason, overridden=False,
               decision_kind="ask", target=target, decision=dr)
    print(json.dumps({"hookSpecificOutput": {
        "hookEventName": "PreToolUse", "permissionDecision": "ask",
        "permissionDecisionReason": reason}}))


def high_tier_decision(hook_name, severity, reason, data, target=None, decision_id=None, decision=_UNSET):
    """Shared HIGH-tier default-path decision, used AFTER a caller has
    already checked for and found no override AND already passed the
    mandatory require_decision_or_deny() gate. Branches on
    is_subagent_call(data): a direct orchestrator call gets a real ask()
    prompt; a subagent-originated call gets a hard deny (no ask fallback,
    since ask() fails open there) - the subagent must either have a
    pre-declared override, or the action must be re-run directly by the
    orchestrator where a human can actually be asked.

    `decision=`: the already-resolved lookup from require_decision_or_deny()
    - threaded into whichever of deny()/ask() this picks, so neither one
    re-queries the (already-consumed) sentinel. Default _UNSET preserves
    the old behavior (each callee looks it up itself) for any caller not
    yet updated to the mandatory-gate flow."""
    if is_subagent_call(data):
        deny(
            hook_name,
            reason + " 이 호출은 서브에이전트발이라(agent_id 있음) ask() "
            "프롬프트를 띄울 화면이 없음 - 사람 승인을 받으려면 컨트롤러가 "
            "이 액션을 직접 실행하거나, 디스패치 전에 override를 미리 "
            "declare할 것.",
            severity=severity, target=target, decision_id=decision_id, decision=decision,
        )
    else:
        ask(hook_name, severity, reason, target=target, decision_id=decision_id, decision=decision)


def deny(hook_name, reason, severity="HIGH", target=None, decision_id=None, decision=_UNSET):
    dr = decision_record(hook_name, target=target, decision_id=decision_id) if decision is _UNSET else decision
    _log_event(hook_name, severity, reason, overridden=False,
               decision_kind="deny", target=target, decision=dr)
    print(json.dumps({"hookSpecificOutput": {
        "hookEventName": "PreToolUse", "permissionDecision": "deny",
        "permissionDecisionReason": reason}}))


def allow_with_override(hook_name, severity, rule, target, reason, decision_id=None, decision=_UNSET,
                         totp_verified=None, totp_configured=None):
    """MID/HIGH/CRITICAL tier, override matched: log to both the violations
    log (so the near-miss is visible in the same place as a real deny)
    and the override audit log (so it's separately searchable), then
    allow.

    **정정**: the decision-record lookup happens exactly ONCE here and the
    same result is threaded into both _log_event() and _record_override()
    - decision_record() consumes (deletes) its sentinel on match, so if
    each private logger did its own lookup, the second one would always
    find nothing. Do not "simplify" this into two independent lookups -
    that would silently break enrichment on override_audit.jsonl, the more
    interesting of the two logs for judgment eval.

    **재정정 (mandatory decision-record gate)**: by the time this function
    runs the guard hook has ALREADY confirmed a decision record exists and
    consumed it - pass that resolved value in via `decision=` so this
    doesn't try to look it up again (would find nothing, single-use
    sentinel). Default _UNSET preserves old behavior for any caller not
    yet on the mandatory-gate flow.

    `totp_verified`/`totp_configured`: optional, only set by CRITICAL
    callers using `bash_override_with_totp()` (see its docstring) - passed
    straight through to `_record_override()`, which only adds them to the
    audit entry when not None. Callers not on the TOTP path (i.e.
    everything using plain `bash_override()`) leave these at their None
    default and the audit entry shape is unchanged."""
    dr = decision_record(rule, target=target, decision_id=decision_id) if decision is _UNSET else decision
    note = f"OVERRIDDEN ({severity}, rule={rule}): {reason}"
    _log_event(hook_name, severity, note, overridden=True,
               decision_kind="override", target=target, decision=dr)
    _record_override(rule, severity, target, reason, decision=dr,
                      totp_verified=totp_verified, totp_configured=totp_configured)
    allow()


def bash_override(rule, command):
    """Parses a trailing `# HNCS-OVERRIDE: <rule>: <reason>` marker out of
    a Bash command string. Returns the reason string if present and the
    rule name matches, else None. Does not care where in the command the
    marker appears (checked line by line) - shell comments are valid
    anywhere a new logical line/statement can start.

    Heredoc bodies are stripped first (_HEREDOC_RE) so a marker-shaped
    line inside a heredoc payload (e.g. writing a `.env` file with `#
    HNCS-OVERRIDE: ...` as file *content*, not a real trailing shell
    comment) isn't mistaken for a genuine override."""
    command = _HEREDOC_RE.sub("", command)
    for line in command.splitlines():
        m = _BASH_OVERRIDE_RE.search(line)
        if m and m.group("rule") == rule and m.group("reason").strip():
            return m.group("reason").strip()
    return None


def verify_totp_override_key(code):
    """3-state: `True` if `code` verifies against the TOTP secret in
    `HNCS_HOOK_OVERRIDE_TOTP_SECRET` (base32, `valid_window=1` to tolerate
    normal clock drift across one 30s step either side - also means a code
    is accepted for up to ~90s, which is fine for an added-friction check,
    not a replay-proof one), `False` if it doesn't, `None` if the env var
    isn't set at all (secret not configured - caller decides how to
    fall back, see bash_override_with_totp())."""
    secret = os.environ.get("HNCS_HOOK_OVERRIDE_TOTP_SECRET")
    if not secret:
        return None
    return pyotp.TOTP(secret).verify(code, valid_window=1)


def bash_override_with_totp(rule, command):
    """CRITICAL-only added-confirmation wrapper around `bash_override()` -
    that function itself stays completely unmodified (same signature, same
    return type) so the other 8 guard hooks that call it are untouched by
    this. Only `protect_destructive.py` and `protect_push_safety.py`'s
    force-push branch call this instead.

    Expects the override marker's reason to optionally carry a trailing
    `key=<6-digit code>` (format: `# HNCS-OVERRIDE: <rule>: <reason>
    key=<code>`) and checks it against verify_totp_override_key(). Returns
    `(reason_or_None, totp_configured, totp_verified)`:

    - No `# HNCS-OVERRIDE: <rule>: ...` marker at all (bash_override()
      returns None): `(None, False, False)`.
    - Marker present but no `key=<6 digits>` anywhere in the command, OR a
      key is present but no TOTP secret is configured
      (verify_totp_override_key() returns None): `(reason, False, False)`
      - override still honored (added friction, not a hard gate), just
        flagged in the audit log as "not code-checked".
    - Key present, secret configured, code wrong: the override itself is
      invalidated - `(None, True, False)`.
    - Key present, secret configured, code correct: `(reason, True, True)`.
    """
    reason = bash_override(rule, command)
    if reason is None:
        return None, False, False
    m = _TOTP_KEY_RE.search(command)
    if not m:
        return reason, False, False
    verified = verify_totp_override_key(m.group(1))
    if verified is None:
        return reason, False, False
    if verified is False:
        return None, True, False
    return reason, True, True


def sentinel_override(rule, target):
    """Checks `.pending_override.json` for a fresh (<=10min old), matching
    (same rule + same target) override request, and consumes it (deletes
    the file) if found. Returns the reason string, or None. `target`
    comparison is exact-string - callers should normalize paths the same
    way on both sides (write and check)."""
    if not os.path.exists(_SENTINEL_PATH):
        return None
    try:
        with open(_SENTINEL_PATH, encoding="utf-8") as f:
            data = json.load(f)
    except Exception:
        return None
    try:
        age = time.time() - float(data.get("timestamp", 0))
    except (TypeError, ValueError):
        return None
    if age > _SENTINEL_MAX_AGE_SECONDS:
        return None
    if data.get("rule") != rule or data.get("target") != target:
        return None
    reason = str(data.get("reason") or "").strip()
    if not reason:
        return None
    try:
        os.remove(_SENTINEL_PATH)
    except OSError:
        pass
    return reason


def write_sentinel_override(rule, target, reason):
    """Writes the pending-override sentinel. Called by the agent (via a
    Write tool call to this exact path) immediately before the guarded
    Edit/Write/MultiEdit call it's meant to unblock. Not called by hook
    scripts themselves - this is here so the one write site has a single,
    documented implementation instead of ad-hoc JSON construction."""
    with open(_SENTINEL_PATH, "w", encoding="utf-8") as f:
        json.dump({"rule": rule, "target": target, "reason": reason,
                    "timestamp": time.time()}, f)


def medium_approval(rule, target):
    """MEDIUM tier's "상위 에이전트 승인" path. Checks
    `.pending_medium_approval.json` for a fresh (<=10min), matching (same
    rule + target) approval written by record_agent_approval.py's
    PostToolUse hook after parsing a `MEDIUM-APPROVE: <rule> :: <target>
    :: <caution>` marker out of an actual dispatched subagent's response
    (only recorded if that dispatch used opus specifically - sonnet no
    longer counts). Unlike the plain override sentinel, the calling
    hook/agent can't write this file directly - it only exists after a
    real Agent dispatch produced a matching response, so it's a stronger
    signal than a bare self-declared override, though not proof against a
    controller writing a fake approving dispatch (the "override is
    self-servable" limitation applies here too, just one level removed).

    Returns the caution string, or None. Consumes (deletes) on match."""
    if not os.path.exists(_MEDIUM_APPROVAL_PATH):
        return None
    try:
        with open(_MEDIUM_APPROVAL_PATH, encoding="utf-8") as f:
            data = json.load(f)
    except Exception:
        return None
    try:
        age = time.time() - float(data.get("timestamp", 0))
    except (TypeError, ValueError):
        return None
    if age > _MEDIUM_APPROVAL_MAX_AGE_SECONDS:
        return None
    if data.get("rule") != rule or data.get("target") != target:
        return None
    caution = str(data.get("caution") or "").strip()
    if not caution:
        return None
    try:
        os.remove(_MEDIUM_APPROVAL_PATH)
    except OSError:
        pass
    return caution


def write_medium_approval(rule, target, caution):
    """Called by record_agent_approval.py after parsing a genuine
    MEDIUM-APPROVE marker out of a dispatched subagent's response - not
    called by the guarded hook itself, and not meant to be written
    ad-hoc by an agent the way write_sentinel_override() is."""
    with open(_MEDIUM_APPROVAL_PATH, "w", encoding="utf-8") as f:
        json.dump({"rule": rule, "target": target, "caution": caution,
                    "timestamp": time.time()}, f)


def allow_with_medium_approval(hook_name, severity, rule, target, caution, decision_id=None, decision=_UNSET):
    """MEDIUM tier, higher-agent approval matched (medium_approval()):
    log like an override (visible in violations_log.jsonl next to real
    denials, plus a separate override_audit.jsonl entry tagged with the
    caution text) and allow. Delivering the caution text to the executing
    agent is a separate step (write_pending_caution() + deliver_caution.py)
    - this function only records that the approval was consumed.

    Shares one decision_record() lookup between both loggers - same reason
    as allow_with_override(), see its docstring. `decision=`: pass the
    already-resolved lookup from require_decision_or_deny() - default
    _UNSET preserves the old look-it-up-yourself behavior."""
    dr = decision_record(rule, target=target, decision_id=decision_id) if decision is _UNSET else decision
    note = f"MEDIUM-APPROVED (rule={rule}): {caution}"
    _log_event(hook_name, severity, note, overridden=True,
               decision_kind="medium_approval", target=target, decision=dr)
    _record_override(rule, severity, target, f"[상위 에이전트 승인] {caution}", decision=dr)
    allow()


def write_pending_caution(tool_use_id, caution):
    """Records a caution message for delivery via deliver_caution.py's
    PostToolUse hook once the just-approved call actually completes,
    correlated by tool_use_id - present on both the PreToolUse and
    PostToolUse hook input for the same call. Single-record, like this
    project's other sentinel files: only the most recently written caution
    is deliverable."""
    if not tool_use_id:
        return
    with open(_PENDING_CAUTION_PATH, "w", encoding="utf-8") as f:
        json.dump({"tool_use_id": tool_use_id, "caution": caution,
                    "timestamp": time.time()}, f)


def pop_pending_caution(tool_use_id):
    """Consumes and returns the caution text queued for `tool_use_id` via
    write_pending_caution(), or None if there isn't one."""
    if not tool_use_id or not os.path.exists(_PENDING_CAUTION_PATH):
        return None
    try:
        with open(_PENDING_CAUTION_PATH, encoding="utf-8") as f:
            data = json.load(f)
    except Exception:
        return None
    if data.get("tool_use_id") != tool_use_id:
        return None
    caution = str(data.get("caution") or "").strip()
    try:
        os.remove(_PENDING_CAUTION_PATH)
    except OSError:
        pass
    return caution or None


def write_decision_record(rule, severity, confidence, reason, expected_risk,
                           target=None, decision_id=None):
    """DECISION RECORD: called by must_hook_server.py's MCP tool after its
    parameter schema has already validated the inputs - not meant to be
    called ad-hoc. Records the agent's OWN self-assessed risk judgment for
    a specific guarded-action attempt, attached (if fresh and matching) to
    whatever log entry the guard hook already produces via
    deny()/ask()/log_and_allow()/allow_with_override()/
    allow_with_medium_approval(). `severity` here is the agent's own
    estimate (one of SEVERITIES) and may legitimately differ from the
    guard's fixed SEVERITY constant - that mismatch is exactly what an
    eval tool measures, so it's stored under the log entry's
    `decision.self_severity` key, never conflated with the entry's own
    top-level `severity` field (the guard's fixed tier).

    `target` should match whatever the corresponding guard hook already
    uses as its own override target (file_path/branch/command string - see
    that hook's `allow_with_override()` call). `decision_id` is a free-
    chosen short slug for guards with no clean single target string (e.g.
    Agent-dispatch guards) - either `target` or `decision_id` is required.

    This record is required, not optional - the MEDIUM/HIGH/CRITICAL
    mandatory gate (`require_decision_or_deny()`) denies unconditionally
    when none exists, regardless of override/approval/ask. Remaining
    honest limitation: `decision_id` only helps when the firing rule is
    already known - it does not solve "I don't know which guard will
    fire."

    `confidence` must be a float in [0.0, 1.0] - a malformed call should
    fail loud rather than log garbage silently (the MCP tool's schema
    catches most malformed calls before they reach this function at all;
    this validation is defense in depth)."""
    if target is None and decision_id is None:
        raise ValueError("write_decision_record requires target or decision_id")
    try:
        confidence = float(confidence)
    except (TypeError, ValueError):
        raise ValueError("confidence must be a float in [0.0, 1.0]")
    if not (0.0 <= confidence <= 1.0):
        raise ValueError("confidence must be a float in [0.0, 1.0]")
    with open(_DECISION_RECORD_PATH, "w", encoding="utf-8") as f:
        json.dump({
            "rule": rule, "target": target, "decision_id": decision_id,
            "severity": severity, "confidence": confidence, "reason": reason,
            "expected_risk": expected_risk, "timestamp": time.time(),
        }, f)


def decision_record(rule, target=None, decision_id=None):
    """Checks `.pending_decision_record.json` for a fresh (<=10min),
    matching record and consumes it (deletes the file) if found. Matches
    on `rule` plus EITHER the stored `decision_id` (if the stored record
    has one) OR the stored `target` (if not) - mirrors how the record was
    written, so a caller with only `target` can still match a record that
    was written with the same target, and likewise for decision_id.
    Returns the stored dict, or None. Called internally by deny()/ask()/
    log_and_allow()/high_tier_decision()/allow_with_override()/
    allow_with_medium_approval() - not meant to be called directly by
    guard hooks. Safe to call with target=None, decision_id=None (matches
    nothing, returns None) - used by call sites not yet threaded with a
    target."""
    if target is None and decision_id is None:
        return None
    if not os.path.exists(_DECISION_RECORD_PATH):
        return None
    try:
        with open(_DECISION_RECORD_PATH, encoding="utf-8") as f:
            data = json.load(f)
    except Exception:
        return None
    try:
        age = time.time() - float(data.get("timestamp", 0))
    except (TypeError, ValueError):
        return None
    if age > _DECISION_RECORD_MAX_AGE_SECONDS:
        return None
    if data.get("rule") != rule:
        return None
    stored_decision_id = data.get("decision_id")
    if stored_decision_id:
        if stored_decision_id != decision_id:
            return None
    elif data.get("target") != target:
        return None
    try:
        os.remove(_DECISION_RECORD_PATH)
    except OSError:
        pass
    return data


def require_decision_or_deny(hook_name, severity, target, no_decision_reason, decision_id=None):
    """**MEDIUM/HIGH/CRITICAL 필수 게이트.** organic 테스트(문서화돼 있고
    서브에이전트가 그 문서를 실제로 읽었는데도 자발적으로 안 씀)로
    "문서화만 해두면 쓰이겠지"가 성립 안 한다는 게 확인된 뒤 결정된 사항:
    decision record가 없으면 override/MEDIUM-APPROVE/ask 등 다른 어떤
    통과 경로도 고려하지 않고 **무조건 deny - 예외 없음.**

    가드 훅은 override/승인 체크보다 먼저 이 함수를 호출해야 한다:
      - `None`을 반환하면(=decision record 없음) 이미 deny()를 호출한
        뒤이므로 호출자는 즉시 `return`만 하면 됨 - 추가로 deny를 부를
        필요도, 다른 경로를 시도할 필요도 없음.
      - dict를 반환하면(decision record 있음) 그 값을 그대로
        `decision=<그 값>`으로 override/MEDIUM-APPROVE/ask 판단 끝의
        allow_with_override()/allow_with_medium_approval()/deny()/ask()/
        high_tier_decision() 호출에 넘겨서 재사용해야 함 -
        decision_record()가 1회성 소비라 여기서 이미 소비했고, 다시
        조회하면 항상 None만 나옴.

    LOW 등급은 이 게이트 대상이 아님 - LOW의 "마찰 없음" 설계 자체가
    이미 별개로 확정된 결정이라 여기서 뒤집지 않음."""
    decision = decision_record(hook_name, target=target, decision_id=decision_id)
    if decision is None:
        deny(
            hook_name,
            f"{no_decision_reason} 이 등급(MEDIUM/HIGH/CRITICAL)은 override/"
            "승인/ask 여부와 무관하게 decision record가 먼저 있어야 함 "
            "(강제, 예외 없음). "
            "mcp__plugin_hook_must_hook__write_decision_record 툴을 "
            f'rule="{hook_name}", target="{target}", severity=<자기평가 '
            "등급>, confidence=<0.0-1.0>, reason=<판단 근거>, "
            "expected_risk=<예상 위험>으로 먼저 호출하고 재시도할 것 "
            "(must훅 - 스키마 검증되는 MCP 툴 호출만 유효, "
            "Write 툴로 sentinel 파일 직접 쓰는 건 protect_decision_record_bypass.py가 막음).",
            severity=severity, target=target, decision=None,
        )
        return None
    return decision


def current_head_sha():
    try:
        out = subprocess.run(["git", "rev-parse", "HEAD"], cwd=_repo_root(),
                              capture_output=True, text=True, timeout=10)
        return out.stdout.strip() if out.returncode == 0 else None
    except Exception:
        return None


def _repo_root():
    return os.path.dirname(_HOOKS_DIR)


def _decision_payload(decision):
    """Shared shape for the "decision" field attached to a log entry -
    only the fields an eval tool needs, never the raw sentinel dict (which
    also carries `rule`/`target`/`decision_id`/`timestamp`, already present
    elsewhere on the entry)."""
    if not decision:
        return None
    return {
        "self_severity": decision.get("severity"),
        "confidence": decision.get("confidence"),
        "reason": decision.get("reason"),
        "expected_risk": decision.get("expected_risk"),
    }


def _record_override(rule, severity, target, reason, decision=None,
                      totp_verified=None, totp_configured=None):
    """git_sha is recorded for every override regardless of severity - it's
    an audit-trail field (proves which commit the override was granted
    at), not a gating check.

    `decision`: the dict returned by decision_record(), if a matching one
    was found - attached under a `decision` key when present. Callers
    must pass an already-resolved lookup (see allow_with_override()/
    allow_with_medium_approval() docstrings for why this isn't looked up
    here directly - the sentinel is single-use/consumed on read).

    `totp_verified`/`totp_configured`: optional (see
    bash_override_with_totp()'s docstring for the 3-state meaning) - added
    to the entry as `totp_verified`/`totp_configured` keys only when not
    None, so existing entries/call sites that never pass these stay
    byte-identical in shape."""
    entry = {
        "timestamp": datetime.now(timezone.utc).isoformat(timespec="seconds"),
        "rule": rule,
        "severity": severity,
        "target": target,
        "reason": reason,
        "git_sha": current_head_sha(),
    }
    payload = _decision_payload(decision)
    if payload:
        entry["decision"] = payload
    if totp_configured is not None:
        entry["totp_configured"] = totp_configured
    if totp_verified is not None:
        entry["totp_verified"] = totp_verified
    try:
        with open(_OVERRIDE_AUDIT_PATH, "a", encoding="utf-8") as f:
            f.write(json.dumps(entry, ensure_ascii=False) + "\n")
    except Exception as e:
        print(f"[_hook_common] failed to write override audit log: {e}",
              file=sys.stderr)


def _log_event(hook_name, severity, reason, overridden, decision_kind=None,
                target=None, decision=None):
    """`decision_kind`/`target`/`decision`: optional, all default to
    producing an entry byte-identical in shape to before this addition (no
    `decision_kind`/`target`/`decision` keys at all) when omitted - old
    entries and any not-yet-threaded caller stay backward compatible.
    `decision_kind` is one of "deny"/"ask"/"log_and_allow"/"override"/
    "medium_approval" (mirrors the calling function's name, since deny()
    and ask() otherwise write structurally identical entries with no way
    to tell which produced a given line - see ask()'s docstring for why
    that distinction matters)."""
    entry = {
        "timestamp": datetime.now(timezone.utc).isoformat(timespec="seconds"),
        "hook": hook_name,
        "severity": severity,
        "overridden": overridden,
        "reason": reason,
    }
    if decision_kind is not None:
        entry["decision_kind"] = decision_kind
    if target is not None:
        entry["target"] = target
    payload = _decision_payload(decision)
    if payload:
        entry["decision"] = payload
    try:
        with open(_LOG_PATH, "a", encoding="utf-8") as f:
            f.write(json.dumps(entry, ensure_ascii=False) + "\n")
    except Exception as e:
        print(f"[_hook_common] failed to write violations log: {e}",
              file=sys.stderr)
