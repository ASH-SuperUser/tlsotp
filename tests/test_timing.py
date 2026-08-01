import time as time_module

from tlsotp.core import get_OTP


def measure(key, n_runs=100):
    start = time_module.perf_counter()
    for _ in range(n_runs):
        get_OTP(key)
    elapsed = time_module.perf_counter() - start
    return elapsed / n_runs


class TestTimingConsistency:
    def test_short_vs_long_key(self):
        avg_short = measure("a", n_runs=100)
        avg_long = measure("a" * 1000, n_runs=100)
        ratio = avg_long / avg_short if avg_short else 1
        assert ratio < 10, f"Long key too slow relative to short: {ratio:.2f}x"

    def test_different_algorithms_similar(self):
        times = {}
        for algo_name in ['sha1', 'sha256', 'sha512']:
            start = time_module.perf_counter()
            for _ in range(100):
                get_OTP("key", algorithm=algo_name)
            elapsed = time_module.perf_counter() - start
            times[algo_name] = elapsed

        max_time = max(times.values())
        min_time = min(times.values())
        ratio = max_time / min_time if min_time else 1
        assert ratio < 10, f"Algorithm timing ratio too large: {ratio:.2f}x"
