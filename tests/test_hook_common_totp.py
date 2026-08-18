"""`hooks/_hook_common.py`의 TOTP 추가 확인 단계 단위 테스트 -
`verify_totp_override_key()`(3-state)와 `bash_override_with_totp()`(CRITICAL
전용 신규 함수), `allow_with_override()`/`_record_override()`의
`totp_verified`/`totp_configured` 옵션 파라미터.

이건 "물리적 키"가 아니라 CRITICAL override에 얹는 부주의 방지용 추가
확인 단계일 뿐이다(TOTP secret이 env var에 있어 에이전트가 Bash로 직접
읽어 스스로 계산 가능 - `_hook_common.py`의 모듈 docstring 참고). 가장
중요한 회귀 보증: 기존 `bash_override(rule, command) -> reason_or_None`은
이 태스크로 시그니처/리턴 타입이 전혀 안 바뀐다 - 그 함수를 쓰는 나머지
8개 훅은 이 변경과 완전히 무관해야 한다."""
import json
import os
import shutil
import sys
import tempfile
import time
import unittest

import pyotp

_HOOKS_DIR = os.path.join(os.path.dirname(os.path.dirname(
    os.path.abspath(__file__))), "hooks")
sys.path.insert(0, _HOOKS_DIR)


class TestVerifyTotpOverrideKey(unittest.TestCase):
    def setUp(self):
        self._old_secret = os.environ.pop("HNCS_HOOK_OVERRIDE_TOTP_SECRET", None)
        sys.modules.pop("_hook_common", None)
        import _hook_common
        self.hc = _hook_common

    def tearDown(self):
        if self._old_secret is None:
            os.environ.pop("HNCS_HOOK_OVERRIDE_TOTP_SECRET", None)
        else:
            os.environ["HNCS_HOOK_OVERRIDE_TOTP_SECRET"] = self._old_secret
        sys.modules.pop("_hook_common", None)

    def test_correct_code_verifies(self):
        secret = pyotp.random_base32()
        os.environ["HNCS_HOOK_OVERRIDE_TOTP_SECRET"] = secret
        code = pyotp.TOTP(secret).now()
        self.assertTrue(self.hc.verify_totp_override_key(code))

    def test_wrong_code_rejected(self):
        os.environ["HNCS_HOOK_OVERRIDE_TOTP_SECRET"] = pyotp.random_base32()
        self.assertFalse(self.hc.verify_totp_override_key("000000"))

    def test_no_secret_configured_returns_none(self):
        os.environ.pop("HNCS_HOOK_OVERRIDE_TOTP_SECRET", None)
        self.assertIsNone(self.hc.verify_totp_override_key("123456"))

    def test_old_code_outside_valid_window_rejected(self):
        """replay/시간 윈도 제한 확인 - valid_window=1은 앞뒤로 30초
        스텝 하나씩만 허용하므로, 5분 전 코드는 거부돼야 한다."""
        secret = pyotp.random_base32()
        os.environ["HNCS_HOOK_OVERRIDE_TOTP_SECRET"] = secret
        old_code = pyotp.TOTP(secret).at(time.time() - 300)
        self.assertFalse(self.hc.verify_totp_override_key(old_code))


class TestBashOverrideWithTotp(unittest.TestCase):
    def setUp(self):
        self._old_secret = os.environ.pop("HNCS_HOOK_OVERRIDE_TOTP_SECRET", None)
        sys.modules.pop("_hook_common", None)
        import _hook_common
        self.hc = _hook_common

    def tearDown(self):
        if self._old_secret is None:
            os.environ.pop("HNCS_HOOK_OVERRIDE_TOTP_SECRET", None)
        else:
            os.environ["HNCS_HOOK_OVERRIDE_TOTP_SECRET"] = self._old_secret
        sys.modules.pop("_hook_common", None)

    def test_no_marker_at_all(self):
        self.assertEqual(
            self.hc.bash_override_with_totp("protect_destructive", "git status"),
            (None, False, False))

    def test_marker_no_key_no_secret_configured(self):
        os.environ.pop("HNCS_HOOK_OVERRIDE_TOTP_SECRET", None)
        cmd = "git reset --hard  # HNCS-OVERRIDE: protect_destructive: 사유"
        self.assertEqual(
            self.hc.bash_override_with_totp("protect_destructive", cmd),
            ("사유", False, False))

    def test_marker_no_key_secret_configured(self):
        """키 자체가 커맨드에 없으면 secret 설정 여부와 무관하게
        검증을 시도조차 안 하고 통과(added friction일 뿐, 강제 아님) -
        totp_configured=False로 감사 로그에 남는다."""
        os.environ["HNCS_HOOK_OVERRIDE_TOTP_SECRET"] = pyotp.random_base32()
        cmd = "git reset --hard  # HNCS-OVERRIDE: protect_destructive: 사유"
        self.assertEqual(
            self.hc.bash_override_with_totp("protect_destructive", cmd),
            ("사유", False, False))

    def test_marker_with_key_but_secret_not_configured(self):
        os.environ.pop("HNCS_HOOK_OVERRIDE_TOTP_SECRET", None)
        cmd = "git reset --hard  # HNCS-OVERRIDE: protect_destructive: 사유 key=123456"
        reason, totp_configured, totp_verified = self.hc.bash_override_with_totp(
            "protect_destructive", cmd)
        self.assertIsNotNone(reason)
        self.assertFalse(totp_configured)
        self.assertFalse(totp_verified)

    def test_marker_with_wrong_key_invalidates_override(self):
        secret = pyotp.random_base32()
        os.environ["HNCS_HOOK_OVERRIDE_TOTP_SECRET"] = secret
        wrong_code = "000000" if pyotp.TOTP(secret).now() != "000000" else "111111"
        cmd = f"git reset --hard  # HNCS-OVERRIDE: protect_destructive: 사유 key={wrong_code}"
        self.assertEqual(
            self.hc.bash_override_with_totp("protect_destructive", cmd),
            (None, True, False))

    def test_marker_with_correct_key_verifies(self):
        secret = pyotp.random_base32()
        os.environ["HNCS_HOOK_OVERRIDE_TOTP_SECRET"] = secret
        code = pyotp.TOTP(secret).now()
        cmd = f"git reset --hard  # HNCS-OVERRIDE: protect_destructive: 사유 key={code}"
        reason, totp_configured, totp_verified = self.hc.bash_override_with_totp(
            "protect_destructive", cmd)
        self.assertIsNotNone(reason)
        self.assertTrue(totp_configured)
        self.assertTrue(totp_verified)

    def test_wrong_rule_still_returns_none_state(self):
        cmd = "git reset --hard  # HNCS-OVERRIDE: some_other_rule: 사유 key=123456"
        self.assertEqual(
            self.hc.bash_override_with_totp("protect_destructive", cmd),
            (None, False, False))


class TestBashOverrideUnchanged(unittest.TestCase):
    """회귀 lock-in: `bash_override()`는 이 태스크로 전혀 안 바뀐다 -
    시그니처/리턴 타입 모두 그대로. 그 함수를 쓰는 나머지 8개 훅은 이
    변경과 완전히 무관해야 한다."""

    def setUp(self):
        sys.modules.pop("_hook_common", None)
        import _hook_common
        self.hc = _hook_common

    def test_bash_override_unchanged_signature(self):
        reason = self.hc.bash_override(
            "some_rule", "cmd  # HNCS-OVERRIDE: some_rule: 사유")
        self.assertEqual(reason, "사유")

    def test_bash_override_ignores_totp_key_suffix(self):
        """bash_override()는 key=<code> 서픽스를 특별 취급하지 않는다 -
        reason 파싱 로직 자체가 안 바뀌었으니 그냥 reason 문자열의
        일부로 캡처될 뿐."""
        reason = self.hc.bash_override(
            "some_rule", "cmd  # HNCS-OVERRIDE: some_rule: 사유 key=123456")
        self.assertEqual(reason, "사유 key=123456")

    def test_bash_override_no_marker_returns_none(self):
        self.assertIsNone(self.hc.bash_override("some_rule", "git status"))


class TestOverrideAuditTotpFields(unittest.TestCase):
    """`allow_with_override()`/`_record_override()`의 `totp_verified`/
    `totp_configured` 옵션 파라미터 - 값이 있을 때만 override_audit.jsonl
    항목에 키가 붙고, 없으면(기존 8개 훅처럼 인자를 안 넘기면) 기존
    항목 모양 그대로 유지된다(하위 호환)."""

    def setUp(self):
        self._tmpdir = tempfile.mkdtemp()
        self._env_patch = {
            "HNCS_HOOK_VIOLATIONS_LOG": os.path.join(self._tmpdir, "violations.jsonl"),
            "HNCS_HOOK_OVERRIDE_AUDIT_LOG": os.path.join(self._tmpdir, "override_audit.jsonl"),
        }
        self._old_env = {k: os.environ.get(k) for k in self._env_patch}
        os.environ.update(self._env_patch)
        sys.modules.pop("_hook_common", None)
        import _hook_common
        self.hc = _hook_common
        self._audit_path = self._env_patch["HNCS_HOOK_OVERRIDE_AUDIT_LOG"]

    def tearDown(self):
        for k, v in self._old_env.items():
            if v is None:
                os.environ.pop(k, None)
            else:
                os.environ[k] = v
        sys.modules.pop("_hook_common", None)
        shutil.rmtree(self._tmpdir, ignore_errors=True)

    def _last_audit_entry(self):
        with open(self._audit_path, encoding="utf-8") as f:
            lines = f.readlines()
        return json.loads(lines[-1])

    def test_omitted_totp_fields_produce_no_keys(self):
        """기존 8개 훅과 동일한 호출부(totp 인자 없음) - 감사 항목에
        totp_verified/totp_configured 키가 아예 안 붙어야 한다."""
        self.hc.allow_with_override(
            "protect_branch", "HIGH", "protect_branch", "main", "사유")
        entry = self._last_audit_entry()
        self.assertNotIn("totp_verified", entry)
        self.assertNotIn("totp_configured", entry)

    def test_totp_fields_present_when_passed(self):
        self.hc.allow_with_override(
            "protect_destructive", "CRITICAL", "protect_destructive",
            "git reset --hard", "사유", totp_verified=True, totp_configured=True)
        entry = self._last_audit_entry()
        self.assertTrue(entry["totp_verified"])
        self.assertTrue(entry["totp_configured"])

    def test_totp_fields_can_be_false(self):
        self.hc.allow_with_override(
            "protect_destructive", "CRITICAL", "protect_destructive",
            "git reset --hard", "사유", totp_verified=False, totp_configured=False)
        entry = self._last_audit_entry()
        self.assertFalse(entry["totp_verified"])
        self.assertFalse(entry["totp_configured"])


if __name__ == "__main__":
    unittest.main()
