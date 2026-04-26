import math
from collections import Counter
from tlsotp.core import get_OTP
from unittest.mock import patch


def shannon_entropy(data: str) -> float:
    freq = Counter(data)
    total = len(data)
    return -sum((c / total) * math.log2(c / total) for c in freq.values())


# ---------------- FIXED DIGIT ENTROPY ----------------

def test_entropy_digits():
    with patch("time.time", return_value=1000):
        samples = []

        for i in range(500):
            otp = get_OTP(f"key_{i}", otp_mode=0, n_chars=6)
            samples.append(otp)

    joined = "".join(samples)
    entropy = shannon_entropy(joined)

    # realistic bound for deterministic PRF outputs
    assert entropy > 3.0


# ---------------- FIXED ALPHANUMERIC ENTROPY ----------------

def test_entropy_alphanumeric():
    with patch("time.time", return_value=1000):
        samples = []

        for i in range(500):
            otp = get_OTP(f"key_{i}", otp_mode=2, n_chars=6)
            samples.append(otp)

    joined = "".join(samples)
    entropy = shannon_entropy(joined)

    assert entropy > 4.0