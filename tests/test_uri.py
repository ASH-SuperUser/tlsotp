import time
from unittest.mock import patch

import pytest

from tlsotp.interface import (
    get_data_dict,
    get_dict_from_uri,
    get_OTP_from_dict,
    get_otp_from_uri,
    get_OTP_uri,
    get_OTP_uri_from_dict,
    verify_otp,
    verify_otp_from_dict,
    verify_otp_from_uri,
)

# ======================== get_OTP_uri ========================

class TestGetOTPUri:
    def test_basic_uri(self):
        uri = get_OTP_uri(main_key="testkey")
        assert uri.startswith("TLSOTP://")
        assert "main_key=testkey" in uri
        assert "otp_mode=0" in uri
        assert "algorithm=sha1" in uri

    def test_all_params_encoded(self):
        uri = get_OTP_uri(
            main_key="key123",
            otp_mode=2,
            n_chars=8,
            time_binning=60,
            location_mode=301,
            password_str_mode=2,
            algorithm="sha256",
        )
        assert uri.startswith("TLSOTP://")
        assert "main_key=key123" in uri
        assert "otp_mode=2" in uri
        assert "n_chars=8" in uri
        assert "time_binning=60" in uri
        assert "location_mode=301" in uri
        assert "password_str_mode=2" in uri
        assert "algorithm=sha256" in uri
        assert "latitude" not in uri
        assert "longitude" not in uri
        assert "iso3_code" not in uri
        assert "password_string" not in uri

    def test_default_algo_in_uri(self):
        uri = get_OTP_uri(main_key="k", algorithm=0)
        assert "algorithm=sha1" in uri

    def test_non_default_algo_in_uri(self):
        uri = get_OTP_uri(main_key="k", algorithm="sha512")
        assert "algorithm=sha512" in uri

    def test_location_mode_0_in_uri(self):
        uri = get_OTP_uri(main_key="k", location_mode=0)
        assert "location_mode=0" in uri

    def test_location_mode_nonzero_in_uri(self):
        uri = get_OTP_uri(main_key="k", location_mode=301)
        assert "location_mode=301" in uri
        assert "iso3_code" not in uri

    def test_password_mode_0_in_uri(self):
        uri = get_OTP_uri(main_key="k", password_str_mode=0)
        assert "password_str_mode=0" in uri

    def test_lat_lon_not_in_uri(self):
        uri = get_OTP_uri(main_key="k", location_mode=301)
        assert "location_mode=301" in uri
        assert "latitude" not in uri
        assert "longitude" not in uri

    def test_validates_input(self):
        with pytest.raises(ValueError):
            get_OTP_uri(main_key="", otp_mode=99)

    def test_algorithm_int_uri(self):
        uri = get_OTP_uri(main_key="k", algorithm=4)
        assert "algorithm=sha512" in uri

    def test_sha3_512_uri(self):
        uri = get_OTP_uri(main_key="k", algorithm=5)
        assert "algorithm=sha3-512" in uri

    def test_invalid_algorithm_int_raises(self):
        with pytest.raises(ValueError, match="algorithm"):
            get_OTP_uri(main_key="k", algorithm=99)

    def test_invalid_algorithm_str_raises(self):
        with pytest.raises(ValueError, match="algorithm"):
            get_OTP_uri(main_key="k", algorithm="md5")


# ======================== get_OTP_uri_from_dict ========================

class TestGetOTPUriFromDict:
    def test_from_minimal_dict(self):
        d = {"main_key": "key"}
        uri = get_OTP_uri_from_dict(d)
        assert uri.startswith("TLSOTP://")

    def test_from_full_dict(self):
        d = get_data_dict(
            main_key="key", otp_mode=2, n_chars=10,
            location_mode=301, iso3_code="USA",
            algorithm="sha256",
        )
        uri = get_OTP_uri_from_dict(d)
        assert "main_key=key" in uri
        assert "algorithm=sha256" in uri
        assert "location_mode=301" in uri

    def test_extra_keys_ignored(self):
        d = {"main_key": "key", "extra_stuff": "ignored"}
        uri = get_OTP_uri_from_dict(d)
        assert uri.startswith("TLSOTP://")

    def test_invalid_dict_raises(self):
        with pytest.raises(ValueError):
            get_OTP_uri_from_dict({"main_key": ""})


# ======================== get_dict_from_uri ========================

class TestGetDictFromUri:
    def test_roundtrip_minimal(self):
        uri = get_OTP_uri(main_key="testkey")
        config = get_dict_from_uri(uri)
        assert config["main_key"] == "testkey"
        assert config["otp_mode"] == 0
        assert config["n_chars"] == 6
        assert config["time_binning"] == 30
        assert config["algorithm"] == 0
        assert config["location_mode"] == 0
        assert config["latitude"] is None
        assert config["longitude"] is None

    def test_roundtrip_full(self):
        uri_params = {
            "main_key": "key123",
            "otp_mode": 2,
            "n_chars": 10,
            "time_binning": 60,
            "location_mode": 402,
            "password_str_mode": 3,
            "algorithm": "sha256",
        }
        uri = get_OTP_uri(**uri_params)
        config = get_dict_from_uri(uri)
        assert config["main_key"] == "key123"
        assert config["otp_mode"] == 2
        assert config["n_chars"] == 10
        assert config["time_binning"] == 60
        assert config["location_mode"] == 402
        assert config["password_str_mode"] == 3
        assert config["algorithm"] in ("sha256", 2)
        assert config["latitude"] is None
        assert config["longitude"] is None
        assert config["iso3_code"] is None
        assert config["password_string"] is None

    def test_roundtrip_algorithm_int(self):
        uri = get_OTP_uri(main_key="k", algorithm=4)
        config = get_dict_from_uri(uri)
        assert config["algorithm"] == 4

    def test_roundtrip_sha3_512(self):
        uri = get_OTP_uri(main_key="k", algorithm=5)
        config = get_dict_from_uri(uri)
        assert config["algorithm"] == 5

    def test_roundtrip_algorithm_str(self):
        uri = get_OTP_uri(main_key="k", algorithm="sha224")
        config = get_dict_from_uri(uri)
        assert config["algorithm"] == 1

    def test_invalid_scheme_raises(self):
        with pytest.raises(ValueError, match="TLSOTP://"):
            get_dict_from_uri("http://example.com")

    def test_missing_main_key_raises(self):
        with pytest.raises(ValueError, match="main_key"):
            get_dict_from_uri("TLSOTP://n_chars=6")

    def test_empty_uri_raises(self):
        with pytest.raises(ValueError, match="TLSOTP://"):
            get_dict_from_uri("")

    def test_roundtrip_location_mode_301(self):
        uri = get_OTP_uri(main_key="k", location_mode=301)
        config = get_dict_from_uri(uri)
        assert config["location_mode"] == 301
        assert config["iso3_code"] is None

    def test_roundtrip_negative_location_mode(self):
        uri = get_OTP_uri(main_key="k", location_mode=-10)
        config = get_dict_from_uri(uri)
        assert config["location_mode"] == -10
        assert config["latitude"] is None
        assert config["longitude"] is None

    def test_password_mode_negative(self):
        uri = get_OTP_uri(main_key="k", password_str_mode=-1)
        config = get_dict_from_uri(uri)
        assert config["password_str_mode"] == -1
        assert config["password_string"] is None


# ======================== get_otp_from_uri ========================

class TestGetOTPFromUri:
    def test_roundtrip_otp(self, monkeypatch):
        monkeypatch.setattr(time, "time", lambda: 1000)
        uri = get_OTP_uri(main_key="testkey")
        otp = get_otp_from_uri(uri)
        assert isinstance(otp, str)
        assert len(otp) == 6

    def test_consistent_with_direct(self, monkeypatch):
        monkeypatch.setattr(time, "time", lambda: 1000)
        direct = get_OTP_from_dict({"main_key": "testkey"})
        uri = get_OTP_uri(main_key="testkey")
        from_uri = get_otp_from_uri(uri)
        assert direct == from_uri

    def test_with_override_dict(self, monkeypatch):
        monkeypatch.setattr(time, "time", lambda: 1000)
        uri = get_OTP_uri(main_key="testkey", n_chars=6)
        otp = get_otp_from_uri(uri, override_dict={"n_chars": 10})
        assert len(otp) == 10

    def test_with_adder_dict(self, monkeypatch):
        monkeypatch.setattr(time, "time", lambda: 1000)
        uri = get_OTP_uri(main_key="testkey", n_chars=6, password_str_mode=2)
        with pytest.raises(ValueError):
            get_otp_from_uri(uri)
        otp = get_otp_from_uri(uri, adder_dict={"password_string": "secret"})
        assert isinstance(otp, str)
        assert otp == get_otp_from_uri(uri, password_string="secret")

    def test_adder_dict_does_not_override_present_value(self, monkeypatch):
        monkeypatch.setattr(time, "time", lambda: 1000)
        uri = get_OTP_uri(main_key="testkey", n_chars=6, password_str_mode=2)
        explicit = get_otp_from_uri(uri, password_string="secret")
        added = get_otp_from_uri(
            uri,
            password_string="secret",
            adder_dict={"password_str_mode": 0, "n_chars": 99},
        )
        assert explicit == added

    def test_full_config_roundtrip(self, monkeypatch):
        monkeypatch.setattr(time, "time", lambda: 1000)
        config = {
            "main_key": "secret123",
            "otp_mode": 2,
            "n_chars": 8,
            "location_mode": 301,
            "iso3_code": "DEU",
            "algorithm": "sha512",
        }
        uri = get_OTP_uri(
            main_key="secret123", otp_mode=2, n_chars=8,
            location_mode=301, algorithm="sha512",
        )
        otp_uri = get_otp_from_uri(uri, iso3_code="DEU")
        otp_direct = get_OTP_from_dict(config)
        assert otp_uri == otp_direct

    def test_invalid_uri_raises(self):
        with pytest.raises(ValueError):
            get_otp_from_uri("not_a_uri")

    def test_mode_301_missing_iso3_raises(self):
        uri = get_OTP_uri(main_key="k", location_mode=301)
        with pytest.raises(ValueError, match="iso3_code"):
            get_otp_from_uri(uri)

    def test_mode_4xx_missing_latlon_raises(self):
        uri = get_OTP_uri(main_key="k", location_mode=402)
        with pytest.raises(ValueError, match="latitude"):
            get_otp_from_uri(uri)

    def test_password_mode_missing_string_raises(self):
        uri = get_OTP_uri(main_key="k", password_str_mode=2)
        with pytest.raises(ValueError, match="password_string"):
            get_otp_from_uri(uri)

    def test_mode_301_provided_iso3_works(self):
        uri = get_OTP_uri(main_key="k", location_mode=301)
        otp = get_otp_from_uri(uri, iso3_code="IND")
        assert isinstance(otp, str)
        assert len(otp) == 6


# ======================== verify_otp ========================

class TestVerifyOTP:
    def test_valid_otp_current_window(self):
        now = int(time.time())
        with patch("time.time", return_value=now):
            expected = get_OTP_from_dict({"main_key": "testkey"})

        result = verify_otp(main_key="testkey", user_otp=expected, drift_windows=0)
        assert result is True

    def test_invalid_otp_returns_false(self):
        result = verify_otp(main_key="testkey", user_otp="000000", drift_windows=0)
        assert result is False

    def test_drift_window_positive(self):
        now = int(time.time())
        binning = 30
        with patch("time.time", return_value=now + binning):
            future_otp = get_OTP_from_dict({"main_key": "testkey"})

        result = verify_otp(main_key="testkey", user_otp=future_otp, drift_windows=1)
        assert result is True

    def test_drift_window_negative(self):
        now = int(time.time())
        binning = 30
        with patch("time.time", return_value=now - binning):
            past_otp = get_OTP_from_dict({"main_key": "testkey"})

        result = verify_otp(main_key="testkey", user_otp=past_otp, drift_windows=1)
        assert result is True

    def test_drift_too_small_returns_false(self):
        now = int(time.time())
        binning = 30
        with patch("time.time", return_value=now + binning * 2):
            future_otp = get_OTP_from_dict({"main_key": "testkey"})

        result = verify_otp(main_key="testkey", user_otp=future_otp, drift_windows=0)
        assert result is False

    def test_empty_otp_returns_false(self):
        result = verify_otp(main_key="testkey", user_otp="", drift_windows=1)
        assert result is False

    def test_wrong_length_otp_returns_false(self):
        result = verify_otp(main_key="testkey", user_otp="12345", drift_windows=1)
        assert result is False

    def test_none_otp_returns_false(self):
        result = verify_otp(main_key="testkey", user_otp=None, drift_windows=1)
        assert result is False

    def test_with_custom_params(self):
        now = int(time.time())
        with patch("time.time", return_value=now):
            expected = get_OTP_from_dict({
                "main_key": "key",
                "otp_mode": 2,
                "n_chars": 10,
                "algorithm": "sha256",
            })

        result = verify_otp(
            main_key="key",
            user_otp=expected,
            drift_windows=0,
            otp_mode=2,
            n_chars=10,
            algorithm="sha256",
        )
        assert result is True

    def test_large_drift_window(self):
        now = int(time.time())
        binning = 30
        with patch("time.time", return_value=now + binning * 5):
            future_otp = get_OTP_from_dict({"main_key": "testkey"})

        result = verify_otp(main_key="testkey", user_otp=future_otp, drift_windows=5)
        assert result is True

    def test_accepts_explicit_now(self):
        now = int(time.time())
        with patch("time.time", return_value=now):
            expected = get_OTP_from_dict({"main_key": "testkey"})

        result = verify_otp(main_key="testkey", user_otp=expected, drift_windows=0, now=now)
        assert result is True

    def test_thread_safe_concurrent_verification(self):
        import threading

        now = int(time.time())
        with patch("time.time", return_value=now):
            otp_a = get_OTP_from_dict({"main_key": "keyA"})
        with patch("time.time", return_value=now + 30):
            otp_b = get_OTP_from_dict({"main_key": "keyB"})

        results = {}

        def worker(name, key, otp, ts):
            results[name] = verify_otp(
                main_key=key, user_otp=otp, drift_windows=0, now=ts
            )

        threads = [
            threading.Thread(target=worker, args=("a", "keyA", otp_a, now)),
            threading.Thread(target=worker, args=("b", "keyB", otp_b, now + 30)),
        ]
        for t in threads:
            t.start()
        for t in threads:
            t.join()

        assert results == {"a": True, "b": True}


# ======================== verify_otp_from_dict ========================

class TestVerifyOTPFromDict:
    def test_valid_from_dict(self):
        now = int(time.time())
        with patch("time.time", return_value=now):
            expected = get_OTP_from_dict({"main_key": "testkey"})

        result = verify_otp_from_dict({"main_key": "testkey"}, expected, drift_windows=0)
        assert result is True

    def test_invalid_from_dict(self):
        result = verify_otp_from_dict({"main_key": "testkey"}, "999999", drift_windows=0)
        assert result is False

    def test_with_drift(self):
        now = int(time.time())
        binning = 30
        with patch("time.time", return_value=now + binning):
            future_otp = get_OTP_from_dict({"main_key": "testkey"})

        result = verify_otp_from_dict({"main_key": "testkey"}, future_otp, drift_windows=1)
        assert result is True

    def test_non_dict_raises_typeerror(self):
        with pytest.raises(TypeError, match="data_dict"):
            verify_otp_from_dict("not_a_dict", "000000")


# ======================== verify_otp_from_uri ========================

class TestVerifyOTPFromUri:
    def test_valid_from_uri(self):
        now = int(time.time())
        with patch("time.time", return_value=now):
            expected = get_OTP_from_dict({"main_key": "testkey"})

        uri = get_OTP_uri(main_key="testkey")
        result = verify_otp_from_uri(expected, uri, drift_windows=0)
        assert result is True

    def test_invalid_from_uri(self):
        uri = get_OTP_uri(main_key="testkey")
        result = verify_otp_from_uri("999999", uri, drift_windows=0)
        assert result is False

    def test_with_drift_from_uri(self):
        now = int(time.time())
        binning = 30
        with patch("time.time", return_value=now + binning):
            future_otp = get_OTP_from_dict({"main_key": "testkey"})

        uri = get_OTP_uri(main_key="testkey")
        result = verify_otp_from_uri(future_otp, uri, drift_windows=1)
        assert result is True

    def test_invalid_uri_raises(self):
        with pytest.raises(ValueError):
            verify_otp_from_uri("000000", "bad_uri", drift_windows=1)
