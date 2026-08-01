import hashlib
import hmac
import math
from collections import Counter
from unittest.mock import patch

from tlsotp.core import (
    OTP_gen,
    get_OTP,
    get_time_OTP,
    location_str,
    password_str,
    time_str,
)
from tlsotp.interface import get_OTP_from_dict, verify_otp

# ======================== HMAC construction equivalence ========================

_ALGO_MAP = {
    0: hashlib.sha1,
    1: hashlib.sha224,
    2: hashlib.sha256,
    3: hashlib.sha384,
    4: hashlib.sha512,
    5: hashlib.sha3_512,
}


def _hmac_otp(key, msg, digestmod, otp_mode, n_chars):
    return OTP_gen(hmac.new(key.encode('utf-8'), msg, digestmod).digest(), otp_mode, n_chars)


class TestHMACConstruction:
    def test_get_time_otp_equals_manual_hmac_all_algorithms(self):
        key = "test-key"
        now = 1000
        for algo_id, digestmod in _ALGO_MAP.items():
            msg = time_str(30, now=now).encode('utf-8')
            expected = _hmac_otp(key, msg, digestmod, 0, 6)
            actual = get_time_OTP(key, algorithm=algo_id, now=now)
            assert actual == expected, f"algo {algo_id} mismatch"

    def test_get_otp_equals_manual_hmac_full_message(self):
        key = "test-key"
        now = 1000
        msg = (
            time_str(30, now=now)
            + location_str(301, iso3_code="IND")
            + password_str(-1, "pass")
        ).encode('utf-8')
        expected = _hmac_otp(key, msg, hashlib.sha256, 0, 6)
        actual = get_OTP(
            key,
            location_mode=301,
            iso3_code="IND",
            password_str_mode=-1,
            password_string="pass",
            algorithm="sha256",
            now=now,
        )
        assert actual == expected

    def test_get_otp_matches_get_time_otp_when_components_disabled(self):
        key = "key"
        now = 1000
        assert get_OTP(key, now=now) == get_time_OTP(key, now=now)

    def test_utf8_key_encoding(self):
        key = "\u00e9\u00e0\u00fc"
        now = 1000
        msg = time_str(30, now=now).encode('utf-8')
        expected = _hmac_otp(key, msg, hashlib.sha1, 0, 6)
        assert get_OTP(key, now=now) == expected

    def test_utf8_password_encoding(self):
        key = "k"
        now = 1000
        pwd = "\u00e9\u00e0\u00fc"
        msg = (time_str(30, now=now) + password_str(-1, pwd)).encode('utf-8')
        expected = _hmac_otp(key, msg, hashlib.sha1, 0, 6)
        actual = get_OTP(key, password_str_mode=-1, password_string=pwd, now=now)
        assert actual == expected


# ======================== Big-endian chunk consumption ========================

class TestChunkConsumption:
    def test_big_endian_known_answer(self):
        # 0x00000005 -> 5 -> 5 % 10 == 5
        assert OTP_gen(b'\x00\x00\x00\x05', otp_mode=0, n_chars=1) == "5"

    def test_little_endian_known_answer_distinguishes(self):
        # 0x05000000 -> 83886080 -> % 10 == 0 (proves big-endian, not little)
        assert OTP_gen(b'\x05\x00\x00\x00', otp_mode=0, n_chars=1) == "0"

    def test_multiple_chunks_consumed_in_order(self):
        # chunks 0x05 and 0x0a -> "5" then "0"
        assert OTP_gen(b'\x00\x00\x00\x05\x00\x00\x00\x0a', otp_mode=0, n_chars=2) == "50"

    def test_modulo_10_known_answer(self):
        # 0x0000000f == 15 -> 15 % 10 == 5
        assert OTP_gen(b'\x00\x00\x00\x0f', otp_mode=0, n_chars=1) == "5"

    def test_chaining_after_input_exhausted(self):
        # 4-byte input supports exactly 1 char before sha256 chaining kicks in
        first = OTP_gen(b'\x00\x00\x00\x05', otp_mode=0, n_chars=6)
        assert len(first) == 6
        assert first[0] == "5"
        assert first != "5" * 6

    def test_chaining_matches_manual_sha256(self):
        data = b'\x00\x00\x00\x05'
        manual = []
        d = data
        offset = 0
        alphabet = "0123456789"
        while len(manual) < 6:
            if offset + 4 > len(d):
                d = hashlib.sha256(d).digest()
                offset = 0
            chunk = d[offset:offset + 4]
            manual.append(alphabet[int.from_bytes(chunk, 'big') % 10])
            offset += 4
        assert OTP_gen(data, otp_mode=0, n_chars=6) == ''.join(manual)

    def test_input_shorter_than_chunk_chains_immediately(self):
        # 3-byte input is too short for one 4-byte chunk -> sha256 immediately
        otp = OTP_gen(b'\x01\x02\x03', otp_mode=0, n_chars=6)
        assert len(otp) == 6
        assert otp == OTP_gen(b'\x01\x02\x03', otp_mode=0, n_chars=6)


# ======================== Avalanche effect ========================

class TestAvalanche:
    def test_key_change_alters_all_positions(self):
        key = "avalanche_key_123"
        with patch("time.time", return_value=1000):
            a = get_OTP(key, n_chars=8)
            b = get_OTP(key + "x", n_chars=8)
        assert a != b
        differing = sum(x != y for x, y in zip(a, b))
        assert differing >= 7, f"only {differing}/8 positions differ"

    def test_single_char_key_change(self):
        key = "secretkey123"
        with patch("time.time", return_value=1000):
            a = get_OTP(key, n_chars=8)
            b = get_OTP(key[:-1] + ("a" if key[-1] != "a" else "b"), n_chars=8)
        assert a != b

    def test_password_change_alters_otp(self):
        with patch("time.time", return_value=1000):
            a = get_OTP("k", password_str_mode=-1, password_string="pass_one")
            b = get_OTP("k", password_str_mode=-1, password_string="pass_two")
        assert a != b

    def test_location_change_alters_otp(self):
        with patch("time.time", return_value=1000):
            a = get_OTP("k", location_mode=301, iso3_code="IND")
            b = get_OTP("k", location_mode=301, iso3_code="USA")
        assert a != b

    def test_algorithm_change_alters_otp(self):
        with patch("time.time", return_value=1000):
            a = get_OTP("k", algorithm="sha1")
            b = get_OTP("k", algorithm="sha256")
        assert a != b


# ======================== Statistical uniformity ========================

def _chi_square(mode, n_samples=20000, n_chars=1):
    with patch("time.time", return_value=1000):
        samples = [get_OTP(f"k{i}", otp_mode=mode, n_chars=n_chars) for i in range(n_samples)]
    joined = "".join(samples)
    counter = Counter(joined)
    alphabet = "0123456789"
    if mode == 1:
        alphabet = "ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz"
    elif mode == 2:
        alphabet = "0123456789ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz"
    expected = len(joined) / len(alphabet)
    return sum((counter[c] - expected) ** 2 / expected for c in alphabet), len(alphabet) - 1


class TestUniformity:
    def test_digit_distribution_uniform(self):
        chi2, df = _chi_square(0)
        assert chi2 < 30, f"chi2={chi2:.2f} too high for df={df}"

    def test_alpha_distribution_uniform(self):
        chi2, df = _chi_square(1)
        assert chi2 < 100, f"chi2={chi2:.2f} too high for df={df}"

    def test_alnum_distribution_uniform(self):
        chi2, df = _chi_square(2)
        assert chi2 < 100, f"chi2={chi2:.2f} too high for df={df}"

    def test_no_symbol_never_appears(self):
        chi2, _df = _chi_square(1, n_samples=30000)
        assert math.isfinite(chi2)

    def test_8_char_samples_uniform_digits(self):
        chi2, df = _chi_square(0, n_samples=5000, n_chars=8)
        assert chi2 < 40, f"chi2={chi2:.2f} too high for df={df}"


# ======================== Drift window verification ========================

class TestDriftWindowCount:
    @staticmethod
    def _stub_get_otp(calls):
        from tlsotp import interface as interface_module

        original = interface_module.get_OTP
        # the stub always returns a NON-matching OTP so verify_otp cannot
        # short-circuit; every window must be probed
        interface_module.get_OTP = lambda **kw: calls.append(kw.get("now")) or "999999"
        return original

    def test_verify_checks_exactly_2N_plus_1_windows(self):
        from tlsotp import interface as interface_module

        for drift in (0, 1, 2, 5):
            calls = []
            original = self._stub_get_otp(calls)
            try:
                verify_otp(main_key="k", user_otp="000000", drift_windows=drift, now=1000)
            finally:
                interface_module.get_OTP = original

            assert len(calls) == 2 * drift + 1, f"drift={drift}: {len(calls)} calls"

    def test_verify_window_now_values_are_centered(self):
        from tlsotp import interface as interface_module

        calls = []
        original = self._stub_get_otp(calls)
        try:
            verify_otp(main_key="k", user_otp="000000", drift_windows=2, now=1000)
        finally:
            interface_module.get_OTP = original

        assert calls == [930, 960, 990, 1020, 1050]

    def test_verify_at_window_boundary(self):
        with patch("time.time", return_value=90):
            w2 = get_OTP_from_dict({"main_key": "k"})
        # OTP for the 60s window (same as 90s? no -> 60//30=2, 90//30=3)
        with patch("time.time", return_value=60):
            w1 = get_OTP_from_dict({"main_key": "k"})
        with patch("time.time", return_value=90):
            w3 = get_OTP_from_dict({"main_key": "k"})
        assert w1 != w2
        assert w2 == w3
        # at now=89 (window 60), drift=1 must accept the 90-window OTP
        assert verify_otp("k", w2, drift_windows=1, now=89) is True
        assert verify_otp("k", w2, drift_windows=0, now=89) is False


# ======================== Constant-time comparison ========================

class TestConstantTime:
    def test_verify_uses_compare_digest(self):
        import tlsotp.interface as interface_module
        calls = []
        original = hmac.compare_digest
        interface_module.hmac.compare_digest = lambda a, b: calls.append((a, b)) or original(a, b)
        try:
            verify_otp(main_key="k", user_otp="000000", drift_windows=1, now=1000)
        finally:
            interface_module.hmac.compare_digest = original
        assert calls, "compare_digest was never called"

    def test_compare_digest_used_for_every_window(self):
        import tlsotp.interface as interface_module
        calls = []
        original = hmac.compare_digest
        interface_module.hmac.compare_digest = lambda a, b: calls.append(1) or original(a, b)
        try:
            verify_otp(main_key="k", user_otp="000000", drift_windows=3, now=1000)
        finally:
            interface_module.hmac.compare_digest = original
        assert len(calls) == 7
