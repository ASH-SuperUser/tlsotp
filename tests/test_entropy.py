import math
from collections import Counter
from unittest.mock import patch

from tlsotp.core import get_OTP


def shannon_entropy(data: str) -> float:
    freq = Counter(data)
    total = len(data)
    return -sum((c / total) * math.log2(c / total) for c in freq.values())


def _samples(count, otp_mode, n_chars, key_prefix="key_"):
    with patch("time.time", return_value=1000):
        return [get_OTP(f"{key_prefix}{i}", otp_mode=otp_mode, n_chars=n_chars) for i in range(count)]


class TestEntropyDigits:
    def test_entropy_digits_6chars(self):
        samples = _samples(500, otp_mode=0, n_chars=6)
        joined = "".join(samples)
        entropy = shannon_entropy(joined)
        assert entropy > 3.0, f"Digit entropy too low: {entropy}"

    def test_entropy_digits_8chars(self):
        samples = _samples(500, otp_mode=0, n_chars=8)
        joined = "".join(samples)
        entropy = shannon_entropy(joined)
        assert entropy > 3.0, f"Digit entropy too low: {entropy}"


class TestEntropyAlphanumeric:
    def test_entropy_alphanumeric_6chars(self):
        samples = _samples(500, otp_mode=2, n_chars=6)
        joined = "".join(samples)
        entropy = shannon_entropy(joined)
        assert entropy > 4.0, f"Alphanumeric entropy too low: {entropy}"

    def test_entropy_alphanumeric_8chars(self):
        samples = _samples(500, otp_mode=2, n_chars=8)
        joined = "".join(samples)
        entropy = shannon_entropy(joined)
        assert entropy > 4.0, f"Alphanumeric entropy too low: {entropy}"


class TestEntropyAlpha:
    def test_entropy_alpha_6chars(self):
        samples = _samples(500, otp_mode=1, n_chars=6)
        joined = "".join(samples)
        entropy = shannon_entropy(joined)
        assert entropy > 4.0, f"Alpha entropy too low: {entropy}"


class TestEntropyDistribution:
    def test_digit_distribution_balanced(self):
        samples = _samples(2000, otp_mode=0, n_chars=6)
        joined = "".join(samples)
        freq = Counter(joined)
        total = len(joined)
        for digit in '0123456789':
            ratio = freq[digit] / total
            assert 0.05 < ratio < 0.15, f"Digit {digit} frequency {ratio:.4f} outside expected range"
