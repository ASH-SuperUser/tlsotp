from tlsotp.core import get_OTP
from unittest.mock import patch


def test_collision_rate_small():
    with patch("time.time", return_value=1000):
        otps = [get_OTP(f"key{i}") for i in range(1000)]

    unique = len(set(otps))

    # allow small collision margin
    assert unique > 950


def test_collision_rate_large():
    with patch("time.time", return_value=1000):
        otps = [get_OTP(f"user_{i}", n_chars=8) for i in range(3000)]

    unique = len(set(otps))

    assert unique > 2900