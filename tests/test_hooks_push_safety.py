"""`hooks/protect_push_safety.py`의 정규식 매칭 로직 테스트.

`hooks/`는 패키지가 아니라 Claude Code가 스크립트로 직접 실행하는
독립 파일들이라 sys.path에 그 디렉토리를 넣어서 모듈로 import한다.

이 훅은 실제 우회 사례 2건을 고정으로 잡는다:
1. `git -c http.extraHeader=x push --force ...` - `git`과 `push` 사이에
   전역 옵션이 끼면 `git\s+push` 패턴이 아예 매치 안 됨.
2. `--force-with-lease=<refspec>` - `=` 뒤에 refspec이 붙으면 기존
   `(\s|$)` 경계 조건에 안 걸림.
"""
import json
import os
import shutil
import subprocess
import sys
import tempfile
import unittest

import pyotp

sys.path.insert(0, os.path.join(os.path.dirname(os.path.dirname(
    os.path.abspath(__file__))), "hooks"))
import protect_push_safety as hook  # noqa: E402


def _is_force_push(command):
    """훅의 main()과 같은 판정 로직을 순수 함수로 재현 - matched 여부와
    force 여부를 함께 반환한다."""
    matches = list(hook._PUSH_INVOCATION_RE.finditer(command))
    if not matches:
        return "not_a_push"
    for m in matches:
        if hook._FORCE_RE.search(m.group("args")):
            return "forced"
    return "safe_push"


class TestPushInvocationMatching(unittest.TestCase):
    def test_plain_force_flag_detected(self):
        self.assertEqual(_is_force_push("git push --force origin main"), "forced")

    def test_short_f_flag_detected(self):
        self.assertEqual(_is_force_push("git push -f origin main"), "forced")

    def test_force_with_lease_no_refspec_detected(self):
        self.assertEqual(
            _is_force_push("git push --force-with-lease origin main"), "forced")

    def test_force_with_lease_with_refspec_detected(self):
        """리뷰에서 발견된 우회 1 - `=<refspec>`이 붙으면 기존 경계
        조건(공백/끝)에 안 걸려서 통과되었다."""
        self.assertEqual(
            _is_force_push(
                "git push --force-with-lease=refs/heads/main:abc123 origin main"),
            "forced")

    def test_global_option_between_git_and_push_still_detected(self):
        """리뷰에서 발견된 우회 2 - `git -c ... push`는 `git\\s+push`
        패턴과 아예 매치가 안 돼서 훅 자체가 무력화되었었다."""
        self.assertEqual(
            _is_force_push("git -c http.extraHeader=x push --force origin main"),
            "forced")

    def test_multiple_global_options_still_detected(self):
        self.assertEqual(
            _is_force_push("git -C /repo --no-pager push --force origin main"),
            "forced")

    def test_safe_push_not_flagged_as_forced(self):
        self.assertEqual(_is_force_push("git push -u origin mybranch"), "safe_push")

    def test_established_retry_loop_convention_not_flagged(self):
        cmd = ("for i in 1 2 3 4; do git push -u origin mybranch && break; "
               "sleep $((2**i)); done")
        self.assertEqual(_is_force_push(cmd), "safe_push")

    def test_heredoc_prose_mentioning_force_push_not_matched(self):
        cmd = ('git commit -m "$(cat <<XEOF\n'
               'explains that git push --force is dangerous\n'
               'XEOF\n)"')
        self.assertEqual(_is_force_push(cmd), "not_a_push")

    def test_quoted_test_payload_not_matched(self):
        cmd = ('python3 -c "print({\'tool_input\': '
               '{\'command\': \'git push --force origin main\'}})"')
        self.assertEqual(_is_force_push(cmd), "not_a_push")

    def test_no_push_at_all(self):
        self.assertEqual(_is_force_push("git status"), "not_a_push")


class TestHookEndToEnd(unittest.TestCase):
    """실제 스크립트를 subprocess로 실행해서 stdin JSON -> stdout
    permissionDecision까지 전체 경로를 확인한다. author email 체크가
    실제 저장소 상태에 새지 않도록 격리된 임시 git repo를 쓴다."""

    def setUp(self):
        self.repo = tempfile.mkdtemp()
        self._log_dir = tempfile.mkdtemp()
        self._env = dict(os.environ, **{
            "HNCS_HOOK_VIOLATIONS_LOG": os.path.join(self._log_dir, "test_violations_log.jsonl"),
            "HNCS_HOOK_OVERRIDE_AUDIT_LOG": os.path.join(self._log_dir, "test_override_audit.jsonl"),
            "HNCS_HOOK_DECISION_RECORD_SENTINEL": os.path.join(self._log_dir, ".pending_decision_record.json"),
        })
        self._env.pop("HNCS_HOOK_OVERRIDE_TOTP_SECRET", None)
        run = lambda *args: subprocess.run(  # noqa: E731
            args, cwd=self.repo, capture_output=True, text=True, check=True)
        run("git", "init", "-q")
        run("git", "config", "user.email", hook._CLAUDE_AUTHOR_EMAIL)
        run("git", "config", "user.name", "Claude")
        with open(os.path.join(self.repo, "f.txt"), "w") as f:
            f.write("x")
        run("git", "add", "f.txt")
        run("git", "commit", "-q", "-m", "init")

    def tearDown(self):
        shutil.rmtree(self.repo, ignore_errors=True)
        shutil.rmtree(self._log_dir, ignore_errors=True)

    def _run_hook(self, command, agent_id=None):
        payload = {"tool_name": "Bash", "tool_input": {"command": command}}
        if agent_id:
            payload["agent_id"] = agent_id
            payload["agent_type"] = "general-purpose"
        proc = subprocess.run(
            [sys.executable, hook.__file__],
            cwd=self.repo, input=json.dumps(payload), env=self._env,
            capture_output=True, text=True, timeout=15,
        )
        out = json.loads(proc.stdout)
        return out["hookSpecificOutput"]["permissionDecision"]

    def _write_decision_record(self, target):
        sys.modules.pop("_hook_common", None)
        os.environ["HNCS_HOOK_DECISION_RECORD_SENTINEL"] = self._env["HNCS_HOOK_DECISION_RECORD_SENTINEL"]
        import _hook_common
        _hook_common.write_decision_record(
            "protect_push_safety", "CRITICAL", 0.9, "테스트 자기평가", "테스트 위험", target=target)
        del sys.modules["_hook_common"]
        os.environ.pop("HNCS_HOOK_DECISION_RECORD_SENTINEL", None)

    def test_force_push_denied_end_to_end(self):
        self.assertEqual(
            self._run_hook("git push --force-with-lease=refs/heads/main:x origin main"),
            "deny")

    def test_bypass_via_global_git_option_denied_end_to_end(self):
        self.assertEqual(
            self._run_hook("git -c http.extraHeader=x push --force origin main"),
            "deny")

    def test_safe_push_allowed_end_to_end(self):
        self.assertEqual(self._run_hook("git push -u origin main"), "allow")

    def test_non_push_command_allowed_end_to_end(self):
        self.assertEqual(self._run_hook("git status"), "allow")

    def test_force_push_with_override_allowed_and_audited(self):
        cmd = ("git push --force origin main"
               "  # HNCS-OVERRIDE: protect_push_safety: 사용자 명시 승인")
        self._write_decision_record(cmd)
        self.assertEqual(self._run_hook(cmd), "allow")
        audit_path = os.path.join(self._log_dir, "test_override_audit.jsonl")
        with open(audit_path, encoding="utf-8") as f:
            entry = json.loads(f.readline())
        self.assertEqual(entry["rule"], "protect_push_safety")
        self.assertEqual(entry["severity"], "CRITICAL")
        self.assertEqual(entry["reason"], "사용자 명시 승인")

    def test_force_push_without_decision_record_still_denied(self):
        cmd = ("git push --force origin main"
               "  # HNCS-OVERRIDE: protect_push_safety: 사용자 명시 승인")
        self.assertEqual(self._run_hook(cmd), "deny")

    def test_subagent_force_push_denied_even_with_valid_override(self):
        cmd = ("git push --force origin main"
               "  # HNCS-OVERRIDE: protect_push_safety: 사용자 명시 승인")
        self._write_decision_record(cmd)
        self.assertEqual(self._run_hook(cmd, agent_id="agt_1"), "deny")

    def test_authorship_mismatch_has_no_override(self):
        """authorship 체크는 override 대상이 아님 - 항상 고쳐야 함."""
        run = lambda *args: subprocess.run(  # noqa: E731
            args, cwd=self.repo, capture_output=True, text=True, check=True)
        run("git", "config", "user.email", "someone-else@example.com")
        with open(os.path.join(self.repo, "f.txt"), "a") as f:
            f.write("y")
        run("git", "add", "f.txt")
        run("git", "commit", "-q", "-m", "wrong author")
        cmd = "git push -u origin main  # HNCS-OVERRIDE: protect_push_safety: 사유"
        self._write_decision_record(cmd)
        self.assertEqual(self._run_hook(cmd), "deny")

    def test_force_push_override_without_totp_secret_falls_back_to_allow(self):
        """TOTP 추가 확인 단계: secret 미설정이면 하드 실패가 아니라
        기존 방식대로 통과 - 감사 로그에 totp_configured=false가 남는다."""
        cmd = ("git push --force origin main"
               "  # HNCS-OVERRIDE: protect_push_safety: 사용자 명시 승인")
        self._write_decision_record(cmd)
        self.assertEqual(self._run_hook(cmd), "allow")
        audit_path = os.path.join(self._log_dir, "test_override_audit.jsonl")
        with open(audit_path, encoding="utf-8") as f:
            entry = json.loads(f.readline())
        self.assertFalse(entry["totp_configured"])
        self.assertFalse(entry["totp_verified"])

    def test_force_push_override_with_correct_totp_code_allowed_and_audited(self):
        secret = pyotp.random_base32()
        self._env["HNCS_HOOK_OVERRIDE_TOTP_SECRET"] = secret
        code = pyotp.TOTP(secret).now()
        cmd = ("git push --force origin main"
               f"  # HNCS-OVERRIDE: protect_push_safety: 사용자 명시 승인 key={code}")
        self._write_decision_record(cmd)
        self.assertEqual(self._run_hook(cmd), "allow")
        audit_path = os.path.join(self._log_dir, "test_override_audit.jsonl")
        with open(audit_path, encoding="utf-8") as f:
            entry = json.loads(f.readline())
        self.assertTrue(entry["totp_configured"])
        self.assertTrue(entry["totp_verified"])

    def test_force_push_override_with_wrong_totp_code_denied(self):
        secret = pyotp.random_base32()
        self._env["HNCS_HOOK_OVERRIDE_TOTP_SECRET"] = secret
        wrong_code = "000000" if pyotp.TOTP(secret).now() != "000000" else "111111"
        cmd = ("git push --force origin main"
               f"  # HNCS-OVERRIDE: protect_push_safety: 사용자 명시 승인 key={wrong_code}")
        self._write_decision_record(cmd)
        self.assertEqual(self._run_hook(cmd), "deny")


if __name__ == "__main__":
    unittest.main()
