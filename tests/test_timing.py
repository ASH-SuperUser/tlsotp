import time
from tlsotp.core import get_OTP


def measure(key):
    start = time.perf_counter()
    get_OTP(key)
    return time.perf_counter() - start


def test_timing_consistency():
    samples_short = [measure("a") for _ in range(200)]
    samples_long = [measure("a" * 100) for _ in range(200)]

    avg_short = sum(samples_short) / len(samples_short)
    avg_long = sum(samples_long) / len(samples_long)

    ratio = avg_long / avg_short if avg_short else 1

    # Should not be drastically different
    assert ratio < 3