"""`hooks/_hook_common.py`의 심각도/override 메커니즘 순수 함수
단위 테스트(bash_override/sentinel_override/write_sentinel_override).
end-to-end override 커버리지는 test_hooks_destructive.py/
test_hooks_push_safety.py 등 각 가드 훅의 자체 테스트가 제공한다.
감사로그(violations_log.jsonl/override_audit.jsonl)가 테스트 중 실제
git-tracked 파일을 오염시키지 않도록 매 테스트마다 HNCS_HOOK_* 환경변수로
임시 경로로 리다이렉트한다."""
import json
import os
import shutil
import sys
import tempfile
import time
import unittest

_HOOKS_DIR = os.path.join(os.path.dirname(os.path.dirname(
    os.path.abspath(__file__))), "hooks")
sys.path.insert(0, _HOOKS_DIR)


class TestBashOverrideParsing(unittest.TestCase):
    def setUp(self):
        import _hook_common
        self.hc = _hook_common

    def test_matching_rule_and_reason_returns_reason(self):
        cmd = 'echo x >> brands/hasselblad.py  # HNCS-OVERRIDE: protect_never_touch: 사용자 승인, 리팩토링'
        self.assertEqual(
            self.hc.bash_override("protect_never_touch", cmd),
            "사용자 승인, 리팩토링")

    def test_wrong_rule_name_returns_none(self):
        cmd = 'echo x >> brands/hasselblad.py  # HNCS-OVERRIDE: some_other_rule: 사유'
        self.assertIsNone(self.hc.bash_override("protect_never_touch", cmd))

    def test_empty_reason_returns_none(self):
        cmd = 'echo x  # HNCS-OVERRIDE: protect_never_touch:   '
        self.assertIsNone(self.hc.bash_override("protect_never_touch", cmd))

    def test_no_marker_at_all_returns_none(self):
        self.assertIsNone(self.hc.bash_override("protect_never_touch", "git status"))

    def test_marker_inside_heredoc_body_is_ignored(self):
        """Codex review P1 #3: a heredoc payload (e.g. writing a `.env`
        file) that happens to contain override-marker-shaped text as file
        *content* must not be treated as a real override."""
        cmd = (
            "cat <<'EOF' > .env\n"
            "SECRET=xoxb-123456-abcdefghij\n"
            "# HNCS-OVERRIDE: protect_never_touch: fake, embedded in heredoc body\n"
            "EOF\n"
        )
        self.assertIsNone(self.hc.bash_override("protect_never_touch", cmd))

    def test_marker_after_heredoc_as_real_trailing_comment_still_works(self):
        """Regression: a genuine trailing comment on the same statement as
        a heredoc-writing command must still be recognized."""
        cmd = (
            "cat <<'EOF' > .env\n"
            "SECRET=xoxb-123456-abcdefghij\n"
            "EOF\n"
            "# HNCS-OVERRIDE: protect_never_touch: 사용자 승인, 실제 사유\n"
        )
        self.assertEqual(
            self.hc.bash_override("protect_never_touch", cmd),
            "사용자 승인, 실제 사유")

    def test_plain_trailing_comment_without_heredoc_still_works(self):
        cmd = 'echo x >> brands/hasselblad.py  # HNCS-OVERRIDE: protect_never_touch: 그냥 확인'
        self.assertEqual(
            self.hc.bash_override("protect_never_touch", cmd),
            "그냥 확인")


class TestIsSubagentCall(unittest.TestCase):
    def setUp(self):
        import _hook_common
        self.hc = _hook_common

    def test_agent_id_present_is_subagent(self):
        self.assertTrue(self.hc.is_subagent_call(
            {"agent_id": "agt_1", "agent_type": "general-purpose"}))

    def test_agent_id_absent_is_not_subagent(self):
        self.assertFalse(self.hc.is_subagent_call({"tool_name": "Bash"}))


class TestSentinelOverride(unittest.TestCase):
    def setUp(self):
        self._tmpdir = tempfile.mkdtemp()
        self._sentinel_path = os.path.join(self._tmpdir, ".pending_override.json")
        self._env_patch = {
            "HNCS_HOOK_OVERRIDE_SENTINEL": self._sentinel_path,
        }
        self._old_env = {k: os.environ.get(k) for k in self._env_patch}
        os.environ.update(self._env_patch)
        sys.modules.pop("_hook_common", None)
        import _hook_common
        self.hc = _hook_common

    def tearDown(self):
        for k, v in self._old_env.items():
            if v is None:
                os.environ.pop(k, None)
            else:
                os.environ[k] = v
        sys.modules.pop("_hook_common", None)
        shutil.rmtree(self._tmpdir, ignore_errors=True)

    def test_fresh_matching_sentinel_returns_reason_and_is_consumed(self):
        self.hc.write_sentinel_override("protect_never_touch", "brands/x.py", "승인됨")
        reason = self.hc.sentinel_override("protect_never_touch", "brands/x.py")
        self.assertEqual(reason, "승인됨")
        self.assertFalse(os.path.exists(self._sentinel_path), "1회성 소비 - 재사용 방지")

    def test_second_check_after_consumption_returns_none(self):
        self.hc.write_sentinel_override("protect_never_touch", "brands/x.py", "승인됨")
        self.hc.sentinel_override("protect_never_touch", "brands/x.py")
        self.assertIsNone(self.hc.sentinel_override("protect_never_touch", "brands/x.py"))

    def test_mismatched_target_returns_none(self):
        self.hc.write_sentinel_override("protect_never_touch", "brands/x.py", "승인됨")
        self.assertIsNone(self.hc.sentinel_override("protect_never_touch", "brands/OTHER.py"))

    def test_mismatched_rule_returns_none(self):
        self.hc.write_sentinel_override("protect_never_touch", "brands/x.py", "승인됨")
        self.assertIsNone(self.hc.sentinel_override("some_other_rule", "brands/x.py"))

    def test_expired_sentinel_returns_none(self):
        with open(self._sentinel_path, "w", encoding="utf-8") as f:
            json.dump({"rule": "protect_never_touch", "target": "brands/x.py",
                       "reason": "오래된 승인", "timestamp": time.time() - 700}, f)
        self.assertIsNone(self.hc.sentinel_override("protect_never_touch", "brands/x.py"))

    def test_no_sentinel_file_returns_none(self):
        self.assertIsNone(self.hc.sentinel_override("protect_never_touch", "brands/x.py"))

    def test_empty_reason_in_sentinel_returns_none(self):
        self.hc.write_sentinel_override("protect_never_touch", "brands/x.py", "")
        self.assertIsNone(self.hc.sentinel_override("protect_never_touch", "brands/x.py"))


if __name__ == "__main__":
    unittest.main()
