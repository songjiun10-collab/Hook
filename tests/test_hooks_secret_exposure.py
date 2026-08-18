"""`hooks/protect_secret_exposure.py` 테스트 - AWS/GitHub/Slack 토큰과
private key 헤더 패턴별 positive/negative, Edit/Write/MultiEdit/Bash 네
경로 subprocess end-to-end, override/decision-record 게이트."""
import json
import os
import shutil
import subprocess
import sys
import tempfile
import unittest

_HOOKS_DIR = os.path.join(os.path.dirname(os.path.dirname(
    os.path.abspath(__file__))), "hooks")
sys.path.insert(0, _HOOKS_DIR)
import protect_secret_exposure as hook  # noqa: E402


class TestFindSecretPattern(unittest.TestCase):
    def test_aws_access_key_detected(self):
        self.assertIsNotNone(hook.find_secret_pattern("AKIAABCDEFGHIJKLMNOP"))

    def test_aws_access_key_wrong_length_not_flagged(self):
        self.assertIsNone(hook.find_secret_pattern("AKIAABCDEFG"))

    def test_github_token_detected(self):
        self.assertIsNotNone(hook.find_secret_pattern("ghp_" + "a" * 36))

    def test_github_token_all_prefixes_detected(self):
        for prefix in ("ghp_", "gho_", "ghu_", "ghs_", "ghr_"):
            with self.subTest(prefix=prefix):
                self.assertIsNotNone(hook.find_secret_pattern(prefix + "a" * 36))

    def test_github_token_too_short_not_flagged(self):
        self.assertIsNone(hook.find_secret_pattern("ghp_" + "a" * 10))

    def test_private_key_header_detected(self):
        self.assertIsNotNone(
            hook.find_secret_pattern("-----BEGIN RSA PRIVATE KEY-----"))

    def test_private_key_header_no_type_detected(self):
        self.assertIsNotNone(
            hook.find_secret_pattern("-----BEGIN PRIVATE KEY-----"))

    def test_private_key_header_openssh_detected(self):
        self.assertIsNotNone(
            hook.find_secret_pattern("-----BEGIN OPENSSH PRIVATE KEY-----"))

    def test_slack_token_detected(self):
        self.assertIsNotNone(hook.find_secret_pattern("xoxb-123456-abcdefghij"))

    def test_slack_token_all_prefixes_detected(self):
        for prefix in ("xoxb-", "xoxa-", "xoxp-", "xoxr-", "xoxs-"):
            with self.subTest(prefix=prefix):
                self.assertIsNotNone(hook.find_secret_pattern(prefix + "1234567890"))

    def test_normal_code_not_flagged(self):
        self.assertIsNone(hook.find_secret_pattern("def foo():\n    return 1"))

    def test_empty_text_not_flagged(self):
        self.assertIsNone(hook.find_secret_pattern(""))


class TestProtectSecretExposureEndToEnd(unittest.TestCase):
    def setUp(self):
        self._log_dir = tempfile.mkdtemp()
        self._env = dict(os.environ, **{
            "HNCS_HOOK_VIOLATIONS_LOG": os.path.join(self._log_dir, "v.jsonl"),
            "HNCS_HOOK_OVERRIDE_AUDIT_LOG": os.path.join(self._log_dir, "o.jsonl"),
            "HNCS_HOOK_OVERRIDE_SENTINEL": os.path.join(self._log_dir, ".pending.json"),
            "HNCS_HOOK_DECISION_RECORD_SENTINEL": os.path.join(self._log_dir, ".pending_decision_record.json"),
        })

    def tearDown(self):
        shutil.rmtree(self._log_dir, ignore_errors=True)
        os.environ.pop("HNCS_HOOK_OVERRIDE_SENTINEL", None)

    def _write_decision_record(self, target):
        sys.modules.pop("_hook_common", None)
        os.environ["HNCS_HOOK_DECISION_RECORD_SENTINEL"] = self._env["HNCS_HOOK_DECISION_RECORD_SENTINEL"]
        import _hook_common
        _hook_common.write_decision_record(
            "protect_secret_exposure", "HIGH", 0.8, "테스트 자기평가", "테스트 위험", target=target)
        del sys.modules["_hook_common"]
        os.environ.pop("HNCS_HOOK_DECISION_RECORD_SENTINEL", None)

    def _write_sentinel_override(self, target, reason="사용자 확인함"):
        sys.modules.pop("_hook_common", None)
        os.environ["HNCS_HOOK_OVERRIDE_SENTINEL"] = self._env["HNCS_HOOK_OVERRIDE_SENTINEL"]
        import _hook_common
        _hook_common.write_sentinel_override("protect_secret_exposure", target, reason)
        del sys.modules["_hook_common"]

    def _run_hook(self, tool_name, tool_input, agent_id=None):
        payload = {"tool_name": tool_name, "tool_input": tool_input}
        if agent_id:
            payload["agent_id"] = agent_id
            payload["agent_type"] = "general-purpose"
        proc = subprocess.run(
            [sys.executable, hook.__file__], input=json.dumps(payload), env=self._env,
            capture_output=True, text=True, timeout=15,
        )
        out = json.loads(proc.stdout)
        return out["hookSpecificOutput"]["permissionDecision"]

    # --- Write ---

    def test_write_with_secret_asks(self):
        self._write_decision_record("secrets.py")
        decision = self._run_hook("Write", {
            "file_path": "secrets.py",
            "content": "AWS_KEY = 'AKIAABCDEFGHIJKLMNOP'\n",
        })
        self.assertEqual(decision, "ask")

    def test_write_with_secret_without_decision_record_denied(self):
        decision = self._run_hook("Write", {
            "file_path": "secrets.py",
            "content": "AWS_KEY = 'AKIAABCDEFGHIJKLMNOP'\n",
        })
        self.assertEqual(decision, "deny")

    def test_write_with_secret_from_subagent_denied(self):
        self._write_decision_record("secrets.py")
        decision = self._run_hook("Write", {
            "file_path": "secrets.py",
            "content": "AWS_KEY = 'AKIAABCDEFGHIJKLMNOP'\n",
        }, agent_id="agt_1")
        self.assertEqual(decision, "deny")

    def test_write_clean_content_allowed(self):
        decision = self._run_hook("Write", {
            "file_path": "app.py",
            "content": "def foo():\n    return 1\n",
        })
        self.assertEqual(decision, "allow")

    # --- Edit ---

    def test_edit_with_secret_in_new_string_asks(self):
        self._write_decision_record("config.py")
        decision = self._run_hook("Edit", {
            "file_path": "config.py",
            "old_string": "TOKEN = ''",
            "new_string": "TOKEN = 'ghp_" + "a" * 36 + "'",
        })
        self.assertEqual(decision, "ask")

    def test_edit_clean_new_string_allowed(self):
        decision = self._run_hook("Edit", {
            "file_path": "config.py",
            "old_string": "x = 1",
            "new_string": "x = 2",
        })
        self.assertEqual(decision, "allow")

    # --- MultiEdit ---

    def test_multiedit_with_secret_in_any_edit_asks(self):
        self._write_decision_record("config.py")
        decision = self._run_hook("MultiEdit", {
            "file_path": "config.py",
            "edits": [
                {"old_string": "a", "new_string": "b"},
                {"old_string": "x", "new_string": "-----BEGIN RSA PRIVATE KEY-----"},
            ],
        })
        self.assertEqual(decision, "ask")

    def test_multiedit_clean_allowed(self):
        decision = self._run_hook("MultiEdit", {
            "file_path": "config.py",
            "edits": [
                {"old_string": "a", "new_string": "b"},
                {"old_string": "x", "new_string": "y"},
            ],
        })
        self.assertEqual(decision, "allow")

    # --- Bash ---

    def test_bash_with_secret_asks(self):
        cmd = "echo 'xoxb-123456-abcdefghij' >> .env"
        self._write_decision_record(cmd)
        self.assertEqual(self._run_hook("Bash", {"command": cmd}), "ask")

    def test_bash_clean_command_allowed(self):
        self.assertEqual(self._run_hook("Bash", {"command": "ls -la"}), "allow")

    # --- override ---

    def test_edit_override_via_sentinel_allowed_and_audited(self):
        target = "config.py"
        self._write_sentinel_override(target)
        self._write_decision_record(target)
        decision = self._run_hook("Edit", {
            "file_path": target,
            "old_string": "a",
            "new_string": "ghp_" + "a" * 36,
        })
        self.assertEqual(decision, "allow")
        with open(os.path.join(self._log_dir, "o.jsonl"), encoding="utf-8") as f:
            entry = json.loads(f.readline())
        self.assertEqual(entry["rule"], "protect_secret_exposure")
        self.assertEqual(entry["severity"], "HIGH")

    def test_bash_override_allowed_and_audited(self):
        cmd = ("echo 'AKIAABCDEFGHIJKLMNOP'  # HNCS-OVERRIDE: "
               "protect_secret_exposure: 테스트 픽스처용 가짜 키")
        self._write_decision_record(cmd)
        self.assertEqual(self._run_hook("Bash", {"command": cmd}), "allow")
        with open(os.path.join(self._log_dir, "o.jsonl"), encoding="utf-8") as f:
            entry = json.loads(f.readline())
        self.assertEqual(entry["rule"], "protect_secret_exposure")
        self.assertEqual(entry["severity"], "HIGH")

    def test_override_without_decision_record_still_denied(self):
        target = "config.py"
        self._write_sentinel_override(target)
        decision = self._run_hook("Edit", {
            "file_path": target,
            "old_string": "a",
            "new_string": "ghp_" + "a" * 36,
        })
        self.assertEqual(decision, "deny")

    # --- unrelated tools ---

    def test_unrelated_tool_allowed(self):
        payload = json.dumps({"tool_name": "Read", "tool_input": {"file_path": "x.py"}})
        proc = subprocess.run(
            [sys.executable, hook.__file__], input=payload, env=self._env,
            capture_output=True, text=True, timeout=15,
        )
        out = json.loads(proc.stdout)
        self.assertEqual(out["hookSpecificOutput"]["permissionDecision"], "allow")


if __name__ == "__main__":
    unittest.main()
