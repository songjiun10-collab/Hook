"""MEDIUM tier의 "상위 에이전트가 허용하면 실행 에이전트가 실행, 단
주의사항 전달" 메커니즘 테스트 - 3개 조각을 각각 확인한다:

1. `_hook_common.medium_approval()`/`write_medium_approval()` - sentinel
   파일 자체의 순수 함수 계약(fresh/matching/consumed).
2. `record_agent_approval.py` (PostToolUse, Agent matcher) - 디스패치된
   서브에이전트 응답에서 `MEDIUM-APPROVE: <rule> :: <target> ::
   <caution>` 마커를 파싱해 승인을 기록. opus만 인정(sonnet/haiku/
   모델 미지정은 전부 기록 안 함).
3. `deliver_caution.py` (PostToolUse, Edit|Write|MultiEdit matcher) -
   `tool_use_id`로 큐잉된 caution을 `additionalContext`로 전달.

번들 9개 가드 훅은 MEDIUM 등급을 싰 것이 없어(LOW/HIGH/CRITICAL만)
MEDIUM 자체를 쓰는 가드 훅 end-to-end는 여기 번들에 없음 - 이
메커니즘을 사용하는 MEDIUM 가드를 직접 만드는 프로젝트에서 이 테스트
파일을 본보기 삼아 자신의 가드 훅을 통한 end-to-end 테스트를 추가하면
된다.

로그/sentinel 파일이 실제 git-tracked 파일을 오염시키지 않도록 매
테스트마다 HNCS_HOOK_* 환경변수로 격리한다."""
import json
import os
import shutil
import subprocess
import sys
import tempfile
import time
import unittest

_HOOKS_DIR = os.path.join(os.path.dirname(os.path.dirname(
    os.path.abspath(__file__))), "hooks")
sys.path.insert(0, _HOOKS_DIR)


class TestMediumApprovalSentinel(unittest.TestCase):
    def setUp(self):
        self._tmpdir = tempfile.mkdtemp()
        self._path = os.path.join(self._tmpdir, ".pending_medium_approval.json")
        os.environ["HNCS_HOOK_MEDIUM_APPROVAL_SENTINEL"] = self._path
        sys.modules.pop("_hook_common", None)
        import _hook_common
        self.hc = _hook_common

    def tearDown(self):
        os.environ.pop("HNCS_HOOK_MEDIUM_APPROVAL_SENTINEL", None)
        sys.modules.pop("_hook_common", None)
        shutil.rmtree(self._tmpdir, ignore_errors=True)

    def test_fresh_matching_approval_returns_caution_and_is_consumed(self):
        self.hc.write_medium_approval("some_medium_hook", "target.py", "주의해")
        caution = self.hc.medium_approval("some_medium_hook", "target.py")
        self.assertEqual(caution, "주의해")
        self.assertFalse(os.path.exists(self._path))

    def test_mismatched_target_returns_none(self):
        self.hc.write_medium_approval("some_medium_hook", "target.py", "주의해")
        self.assertIsNone(self.hc.medium_approval("some_medium_hook", "OTHER.py"))

    def test_mismatched_rule_returns_none(self):
        self.hc.write_medium_approval("some_medium_hook", "target.py", "주의해")
        self.assertIsNone(self.hc.medium_approval("some_other_rule", "target.py"))

    def test_expired_approval_returns_none(self):
        with open(self._path, "w", encoding="utf-8") as f:
            json.dump({"rule": "some_medium_hook", "target": "target.py",
                       "caution": "주의해", "timestamp": time.time() - 700}, f)
        self.assertIsNone(self.hc.medium_approval("some_medium_hook", "target.py"))

    def test_no_approval_file_returns_none(self):
        self.assertIsNone(self.hc.medium_approval("some_medium_hook", "target.py"))


class TestPendingCaution(unittest.TestCase):
    def setUp(self):
        self._tmpdir = tempfile.mkdtemp()
        self._path = os.path.join(self._tmpdir, ".pending_caution.json")
        os.environ["HNCS_HOOK_PENDING_CAUTION"] = self._path
        sys.modules.pop("_hook_common", None)
        import _hook_common
        self.hc = _hook_common

    def tearDown(self):
        os.environ.pop("HNCS_HOOK_PENDING_CAUTION", None)
        sys.modules.pop("_hook_common", None)
        shutil.rmtree(self._tmpdir, ignore_errors=True)

    def test_matching_tool_use_id_returns_caution_and_is_consumed(self):
        self.hc.write_pending_caution("tu_1", "조심해")
        self.assertEqual(self.hc.pop_pending_caution("tu_1"), "조심해")
        self.assertFalse(os.path.exists(self._path))

    def test_mismatched_tool_use_id_returns_none(self):
        self.hc.write_pending_caution("tu_1", "조심해")
        self.assertIsNone(self.hc.pop_pending_caution("tu_2"))

    def test_no_file_returns_none(self):
        self.assertIsNone(self.hc.pop_pending_caution("tu_1"))


class TestRecordAgentApproval(unittest.TestCase):
    """record_agent_approval.py를 subprocess로 실제 실행."""

    def setUp(self):
        self._tmpdir = tempfile.mkdtemp()
        self._approval_path = os.path.join(self._tmpdir, ".pending_medium_approval.json")
        self._env = dict(os.environ, HNCS_HOOK_MEDIUM_APPROVAL_SENTINEL=self._approval_path)

    def tearDown(self):
        shutil.rmtree(self._tmpdir, ignore_errors=True)

    def _run(self, tool_response):
        payload = json.dumps({"tool_name": "Agent", "tool_response": tool_response})
        subprocess.run(
            [sys.executable, os.path.join(_HOOKS_DIR, "record_agent_approval.py")],
            input=payload, env=self._env, capture_output=True, text=True, timeout=15,
        )

    def test_opus_response_with_marker_records_approval(self):
        self._run({
            "resolvedModel": "claude-opus-5",
            "content": [{"type": "text", "text":
                         "검토 결과 문제없음.\n"
                         "MEDIUM-APPROVE: some_medium_hook :: target.py :: "
                         "fold 3 재적합, monotonic 확인 필요\n"}],
        })
        with open(self._approval_path, encoding="utf-8") as f:
            data = json.load(f)
        self.assertEqual(data["rule"], "some_medium_hook")
        self.assertEqual(data["target"], "target.py")
        self.assertIn("monotonic", data["caution"])

    def test_sonnet_response_with_marker_not_recorded(self):
        """에이전트는 오퍼스 허락만 유효 - sonnet 디스패치는 MEDIUM
        승인으로 안 친다."""
        self._run({
            "resolvedModel": "claude-sonnet-5",
            "content": [{"type": "text", "text":
                         "MEDIUM-APPROVE: some_medium_hook :: target.py :: 주의\n"}],
        })
        self.assertFalse(os.path.exists(self._approval_path))

    def test_haiku_response_with_marker_not_recorded(self):
        self._run({
            "resolvedModel": "claude-haiku-4-5",
            "content": [{"type": "text", "text":
                         "MEDIUM-APPROVE: some_medium_hook :: target.py :: 주의\n"}],
        })
        self.assertFalse(os.path.exists(self._approval_path))

    def test_missing_model_with_marker_not_recorded(self):
        self._run({
            "content": [{"type": "text", "text":
                         "MEDIUM-APPROVE: some_medium_hook :: target.py :: 주의\n"}],
        })
        self.assertFalse(os.path.exists(self._approval_path))

    def test_opus_response_without_marker_not_recorded(self):
        self._run({
            "resolvedModel": "claude-opus-5",
            "content": [{"type": "text", "text": "다 괜찮아 보입니다."}],
        })
        self.assertFalse(os.path.exists(self._approval_path))


class TestDeliverCaution(unittest.TestCase):
    """deliver_caution.py를 subprocess로 실제 실행."""

    def setUp(self):
        self._tmpdir = tempfile.mkdtemp()
        self._caution_path = os.path.join(self._tmpdir, ".pending_caution.json")
        self._env = dict(os.environ, HNCS_HOOK_PENDING_CAUTION=self._caution_path)

    def tearDown(self):
        shutil.rmtree(self._tmpdir, ignore_errors=True)

    def _write_pending(self, tool_use_id, caution):
        sys.path.insert(0, _HOOKS_DIR)
        sys.modules.pop("_hook_common", None)
        os.environ["HNCS_HOOK_PENDING_CAUTION"] = self._caution_path
        import _hook_common
        _hook_common.write_pending_caution(tool_use_id, caution)
        del sys.modules["_hook_common"]

    def _run(self, tool_use_id):
        payload = json.dumps({"tool_name": "Edit", "tool_use_id": tool_use_id})
        proc = subprocess.run(
            [sys.executable, os.path.join(_HOOKS_DIR, "deliver_caution.py")],
            input=payload, env=self._env, capture_output=True, text=True, timeout=15,
        )
        return proc.stdout.strip()

    def test_matching_tool_use_id_delivers_caution(self):
        self._write_pending("tu_1", "monotonic 확인 필요")
        out = self._run("tu_1")
        self.assertTrue(out, "additionalContext should be printed")
        data = json.loads(out)
        self.assertIn("monotonic", data["hookSpecificOutput"]["additionalContext"])

    def test_no_pending_caution_prints_nothing(self):
        out = self._run("tu_1")
        self.assertEqual(out, "")

    def test_non_edit_tool_prints_nothing(self):
        self._write_pending("tu_1", "monotonic 확인 필요")
        payload = json.dumps({"tool_name": "Bash", "tool_use_id": "tu_1"})
        proc = subprocess.run(
            [sys.executable, os.path.join(_HOOKS_DIR, "deliver_caution.py")],
            input=payload, env=self._env, capture_output=True, text=True, timeout=15,
        )
        self.assertEqual(proc.stdout.strip(), "")


if __name__ == "__main__":
    unittest.main()
