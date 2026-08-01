from unittest.mock import patch

from tlsotp.core import get_OTP


def _otps(count, n_chars=6, key_prefix="key"):
    with patch("time.time", return_value=1000):
        return [get_OTP(f"{key_prefix}{i}", n_chars=n_chars) for i in range(count)]


class TestCollisionSmall:
    def test_collision_rate_1000_keys_6chars(self):
        otps = _otps(1000, n_chars=6)
        unique = len(set(otps))
        assert unique > 950, f"Too many collisions: {unique} unique out of 1000"

    def test_collision_rate_3000_keys_8chars(self):
        otps = _otps(3000, n_chars=8)
        unique = len(set(otps))
        assert unique > 2900, f"Too many collisions: {unique} unique out of 3000"


class TestCollisionLarge:
    def test_collision_rate_10000_keys_8chars(self):
        otps = _otps(10000, n_chars=8, key_prefix="user_")
        unique = len(set(otps))
        assert unique > 9900, f"Too many collisions: {unique} unique out of 10000"

    def test_collision_rate_5000_keys_10chars(self):
        otps = _otps(5000, n_chars=10, key_prefix="test_")
        unique = len(set(otps))
        assert unique > 4995, f"Too many collisions: {unique} unique out of 5000"


class TestCollisionSameKey:
    def test_same_key_same_otp(self):
        with patch("time.time", return_value=1000):
            assert get_OTP("same_key") == get_OTP("same_key")

    def test_no_collision_small_keys(self):
        with patch("time.time", return_value=1000):
            keys = [f"key_{i}" for i in range(100)]
            otps = [get_OTP(k, n_chars=12) for k in keys]
            assert len(set(otps)) == 100
