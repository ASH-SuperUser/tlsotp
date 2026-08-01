import time
from unittest.mock import patch

import pytest

from tlsotp.core import OTP_gen, get_OTP, location_str, password_str, time_str
from tlsotp.interface import (
    get_data_dict,
    get_dict_from_uri,
    get_OTP_from_dict,
    get_otp_from_uri,
    get_OTP_uri,
    get_OTP_uri_from_dict,
    key_gen,
    verify_otp,
    verify_otp_from_dict,
    verify_otp_from_uri,
)

# ======================== time_str boundaries ========================

class TestTimeStrBoundaries:
    def test_now_zero(self):
        assert time_str(30, now=0) == "-0-"

    def test_negative_now(self):
        assert time_str(30, now=-1) == "--30-"

    def test_negative_now_larger(self):
        assert time_str(30, now=-31) == "--60-"

    def test_exact_bin_boundary(self):
        assert time_str(30, now=30) == "-30-"
        assert time_str(30, now=60) == "-60-"

    def test_just_below_boundary(self):
        assert time_str(30, now=59) == "-30-"

    def test_float_now(self):
        assert time_str(30, now=100.7) == "-90-"

    def test_bin_one(self):
        assert time_str(1, now=100) == "-100-"

    def test_large_bin(self):
        assert time_str(3600, now=7200) == "-7200-"

    def test_deterministic_negative(self):
        assert time_str(30, now=-45) == time_str(30, now=-45)


# ======================== location_str boundaries ========================

class TestLocationStrBoundaries:
    def test_mode_400_rounds_to_zero_decimals(self):
        assert location_str(400, latitude=12.345, longitude=77.987) == "12-78"

    def test_mode_499_precision_capped_at_six(self):
        result = location_str(499, latitude=12.3456789, longitude=77.9876543)
        assert result == "12.345679-77.987654"

    def test_mode_401_single_decimal(self):
        assert location_str(401, latitude=12.34, longitude=77.98) == "12.3-78.0"

    def test_mode_501_step_one_grid(self):
        assert location_str(501, latitude=27.9, longitude=88.1) == "27-88"

    def test_mode_600_rounds_to_zero_with_iso(self):
        assert location_str(600, latitude=12.345, longitude=77.987, iso3_code="IND") == "IND-12-78"

    def test_mode_699_capped_precision_with_iso(self):
        result = location_str(699, latitude=12.3456789, longitude=77.9876543, iso3_code="IND")
        assert result == "IND-12.345679-77.987654"

    def test_mode_701_step_one_with_iso(self):
        assert location_str(701, latitude=27.9, longitude=88.1, iso3_code="IND") == "IND-27-88"

    def test_negative_zero_coordinates(self):
        assert location_str(1, latitude=-0.0, longitude=-0.0) == "-0.0--0.0"

    def test_huge_positive_mode_capped(self):
        assert location_str(100000, latitude=12.345678, longitude=77.987654) == "12.345678-77.987654"

    def test_negative_mode_snaps_above(self):
        assert location_str(-10, latitude=10.5, longitude=20.5) == "10-20"

    def test_negative_mode_exact_boundary(self):
        assert location_str(-10, latitude=10.0, longitude=20.0) == "10-20"

    def test_iso3_exactly_three_chars(self):
        assert location_str(301, iso3_code="ABC") == "ABC"

    def test_iso3_more_than_three_chars_truncated(self):
        assert location_str(301, iso3_code="ABCDE") == "ABC"

    def test_iso3_empty_string_mode_301(self):
        assert location_str(301, iso3_code="") == ""

    def test_iso3_whitespace_mode_301_raises(self):
        # whitespace counts toward the 3-char minimum
        with pytest.raises(ValueError):
            location_str(301, iso3_code="  ")

    def test_lat_lon_exact_bounds(self):
        assert location_str(1, latitude=90.0, longitude=180.0) == "90.0-180.0"
        assert location_str(1, latitude=-90.0, longitude=-180.0) == "-90.0--180.0"

    def test_6xx_missing_lat_lon_returns_empty(self):
        assert location_str(602, iso3_code="IND") == ""

    def test_7xx_missing_coords_returns_empty(self):
        assert location_str(702, iso3_code="IND") == ""

    def test_6xx_short_iso_raises(self):
        with pytest.raises(ValueError):
            location_str(602, latitude=10, longitude=20, iso3_code="AB")

    def test_7xx_short_iso_raises(self):
        with pytest.raises(ValueError):
            location_str(702, latitude=10, longitude=20, iso3_code="AB")


# ======================== password_str boundaries ========================

class TestPasswordStrBoundaries:
    def test_mode_exactly_length(self):
        assert password_str(4, "abcd") == "-abcd-"

    def test_mode_greater_than_length(self):
        assert password_str(5, "ab") == "-ab-"

    def test_mode_one(self):
        assert password_str(1, "a") == "-a-"

    def test_negative_mode_empty_string(self):
        assert password_str(-1, "") == ""

    def test_positive_mode_empty_string(self):
        assert password_str(1, "") == ""

    def test_unicode_truncation_surrogate_pairs(self):
        # 4 chars including a surrogate-pair emoji; slicing by codepoint
        pwd = "a\u2764\U0001f600b"
        assert password_str(4, pwd) == "-a\u2764\U0001f600b-"

    def test_mode_zero_ignores_pwd(self):
        assert password_str(0, "anything") == ""


# ======================== OTP_gen boundaries ========================

class TestOTPGenBoundaries:
    def test_n_chars_one(self):
        assert len(OTP_gen(b'\x01', n_chars=1)) == 1

    def test_n_chars_128(self):
        assert len(OTP_gen(b'\x01\x02\x03', n_chars=128)) == 128

    def test_input_single_byte(self):
        assert len(OTP_gen(b'\x01', n_chars=64)) == 64

    def test_input_exact_multiple_of_four(self):
        assert OTP_gen(b'\x00\x00\x00\x05\x00\x00\x00\x0a', n_chars=2) == "50"

    def test_input_zero_raises(self):
        with pytest.raises(ValueError):
            OTP_gen(b'')

    def test_none_input_raises(self):
        with pytest.raises(ValueError):
            OTP_gen(None)

    def test_n_chars_zero_returns_empty(self):
        assert OTP_gen(b'\x01\x02', n_chars=0) == ""

    def test_very_long_output_stable(self):
        a = OTP_gen(b'\xde\xad\xbe\xef', n_chars=128)
        b = OTP_gen(b'\xde\xad\xbe\xef', n_chars=128)
        assert a == b
        assert len(a) == 128


# ======================== key_gen boundaries ========================

class TestKeyGenBoundaries:
    def test_zero_length(self):
        assert key_gen(0) == ""

    def test_one_byte_length(self):
        assert len(key_gen(1)) > 0

    def test_large_length(self):
        assert len(key_gen(1024)) > 0

    def test_exact_ratio(self):
        k = key_gen(16)
        assert len(k) >= 16

    def test_all_urlsafe_chars(self):
        k = key_gen(64)
        assert all(c.isalnum() or c in '-_' for c in k)


# ======================== get_OTP boundaries ========================

class TestGetOTPBoundaries:
    def test_n_chars_one(self):
        with patch("time.time", return_value=1000):
            assert len(get_OTP("k", n_chars=1)) == 1

    def test_n_chars_128(self):
        with patch("time.time", return_value=1000):
            assert len(get_OTP("k", n_chars=128)) == 128

    def test_time_binning_one(self):
        with patch("time.time", return_value=1000):
            o1 = get_OTP("k", time_binning=1)
        with patch("time.time", return_value=1001):
            o2 = get_OTP("k", time_binning=1)
        assert o1 != o2

    def test_negative_now(self):
        with patch("time.time", return_value=1000):
            otp = get_OTP("k", now=-100)
        assert isinstance(otp, str)

    def test_float_lat_lon(self):
        with patch("time.time", return_value=1000):
            otp = get_OTP("k", location_mode=1, latitude=12.34, longitude=56.78)
        assert isinstance(otp, str)

    def test_zero_coordinates(self):
        with patch("time.time", return_value=1000):
            otp = get_OTP("k", location_mode=1, latitude=0, longitude=0)
        assert isinstance(otp, str)


# ======================== get_data_dict boundaries ========================

class TestGetDataDictBoundaries:
    def test_lat_lon_lower_bound(self):
        d = get_data_dict(main_key="k", location_mode=1, latitude=-90, longitude=-180)
        assert d["latitude"] == -90
        assert d["longitude"] == -180

    def test_lat_lon_upper_bound(self):
        d = get_data_dict(main_key="k", location_mode=1, latitude=90, longitude=180)
        assert d["latitude"] == 90
        assert d["longitude"] == 180

    def test_n_chars_float_raises(self):
        with pytest.raises(ValueError):
            get_data_dict(main_key="k", n_chars=6.0)

    def test_n_chars_bool_is_int(self):
        # bool is an int subclass; True == 1 passes validation
        d = get_data_dict(main_key="k", n_chars=True)
        assert d["n_chars"] == 1

    def test_time_binning_float_raises(self):
        with pytest.raises(ValueError):
            get_data_dict(main_key="k", time_binning=30.0)

    def test_location_mode_400_valid(self):
        d = get_data_dict(main_key="k", location_mode=400, latitude=1, longitude=2)
        assert d["location_mode"] == 400

    def test_location_mode_500_requires_coords(self):
        with pytest.raises(ValueError, match="latitude"):
            get_data_dict(main_key="k", location_mode=500)

    def test_location_mode_700_requires_coords(self):
        with pytest.raises(ValueError, match="iso3_code"):
            get_data_dict(main_key="k", location_mode=700)

    def test_iso3_exactly_three(self):
        d = get_data_dict(main_key="k", location_mode=301, iso3_code="IND")
        assert d["iso3_code"] == "IND"


# ======================== URI boundaries ========================

class TestURIBoundaries:
    def test_special_chars_roundtrip(self):
        uri = get_OTP_uri(main_key="k e y/+?=%&")
        parsed = get_dict_from_uri(uri)
        assert parsed["main_key"] == "k e y/+?=%&"

    def test_unicode_key_roundtrip(self):
        uri = get_OTP_uri(main_key="h\u00e9llo")
        parsed = get_dict_from_uri(uri)
        assert parsed["main_key"] == "h\u00e9llo"

    def test_negative_location_mode_roundtrip(self):
        uri = get_OTP_uri(main_key="k", location_mode=-10)
        assert "location_mode=-10" in uri
        assert get_dict_from_uri(uri)["location_mode"] == -10

    def test_negative_password_mode_roundtrip(self):
        uri = get_OTP_uri(main_key="k", password_str_mode=-1)
        assert get_dict_from_uri(uri)["password_str_mode"] == -1

    def test_malformed_int_raises(self):
        with pytest.raises(ValueError, match="n_chars"):
            get_dict_from_uri("TLSOTP://main_key=k&n_chars=abc")

    def test_malformed_time_binning_raises(self):
        with pytest.raises(ValueError, match="time_binning"):
            get_dict_from_uri("TLSOTP://main_key=k&time_binning=x")

    def test_unknown_algorithm_string_passthrough(self):
        parsed = get_dict_from_uri("TLSOTP://main_key=k&algorithm=md5")
        assert parsed["algorithm"] == "md5"

    def test_unknown_algorithm_digit_string(self):
        parsed = get_dict_from_uri("TLSOTP://main_key=k&algorithm=99")
        assert parsed["algorithm"] == 99

    def test_duplicate_params_first_wins(self):
        parsed = get_dict_from_uri("TLSOTP://main_key=a&main_key=b")
        assert parsed["main_key"] == "a"

    def test_empty_uri_raises(self):
        with pytest.raises(ValueError):
            get_dict_from_uri("")

    def test_lowercase_scheme_raises(self):
        with pytest.raises(ValueError):
            get_dict_from_uri("tlsotp://main_key=k")

    def test_otp_uri_none_key_raises(self):
        with pytest.raises(ValueError):
            get_OTP_uri(main_key=None)

    def test_otp_uri_n_chars_zero_raises(self):
        with pytest.raises(ValueError):
            get_OTP_uri(main_key="k", n_chars=0)

    def test_otp_uri_n_chars_129_raises(self):
        with pytest.raises(ValueError):
            get_OTP_uri(main_key="k", n_chars=129)

    def test_otp_uri_location_mode_str_raises(self):
        with pytest.raises(TypeError):
            get_OTP_uri(main_key="k", location_mode="0")

    def test_otp_uri_password_mode_str_raises(self):
        with pytest.raises(TypeError):
            get_OTP_uri(main_key="k", password_str_mode="0")

    def test_otp_uri_float_algorithm_raises(self):
        with pytest.raises(TypeError):
            get_OTP_uri(main_key="k", algorithm=1.5)

    def test_otp_uri_from_dict_non_dict_raises(self):
        with pytest.raises(AttributeError):
            get_OTP_uri_from_dict("not a dict")

    def test_otp_uri_from_dict_missing_key_raises(self):
        with pytest.raises(TypeError):
            get_OTP_uri_from_dict({"otp_mode": 1})


# ======================== verify_otp boundaries ========================

class TestVerifyOTPBoundaries:
    def test_user_otp_int_returns_false(self):
        assert verify_otp(main_key="k", user_otp=123456, drift_windows=0) is False

    def test_user_otp_bytes_returns_false(self):
        assert verify_otp(main_key="k", user_otp=b"123456", drift_windows=0) is False

    def test_drift_zero_checks_one_window(self):
        with patch("time.time", return_value=1000):
            otp = get_OTP("k")
        assert verify_otp("k", otp, drift_windows=0, now=1000) is True

    def test_otp_from_next_window_with_drift(self):
        with patch("time.time", return_value=1000):
            now_otp = get_OTP("k")
        with patch("time.time", return_value=1030):
            next_otp = get_OTP("k")
        assert now_otp != next_otp
        assert verify_otp("k", next_otp, drift_windows=1, now=1000) is True
        assert verify_otp("k", next_otp, drift_windows=0, now=1000) is False

    def test_verify_from_dict_with_full_config(self):
        now = int(time.time())
        with patch("time.time", return_value=now):
            otp = get_OTP("k", otp_mode=2, n_chars=8, algorithm="sha256")
        config = {"main_key": "k", "otp_mode": 2, "n_chars": 8, "algorithm": "sha256"}
        assert verify_otp_from_dict(config, otp, drift_windows=0) is True

    def test_verify_from_dict_minimal(self):
        now = int(time.time())
        with patch("time.time", return_value=now):
            otp = get_OTP_from_dict({"main_key": "k"})
        assert verify_otp_from_dict({"main_key": "k"}, otp, drift_windows=0) is True

    def test_verify_from_uri_roundtrip(self):
        now = int(time.time())
        with patch("time.time", return_value=now):
            otp = get_OTP_from_dict({"main_key": "k"})
        uri = get_OTP_uri(main_key="k")
        assert verify_otp_from_uri(otp, uri, drift_windows=0) is True


# ======================== misc interface boundaries ========================

class TestMiscBoundaries:
    def test_get_OTP_from_dict_none_value_main_key_raises(self):
        with pytest.raises(ValueError):
            get_OTP_from_dict({"main_key": None})

    def test_get_OTP_from_dict_empty_main_key_raises(self):
        with pytest.raises(ValueError):
            get_OTP_from_dict({"main_key": ""})

    def test_get_otp_from_uri_with_runtime_values(self):
        uri = get_OTP_uri(main_key="k", location_mode=301)
        with pytest.raises(ValueError):
            get_otp_from_uri(uri)
        otp = get_otp_from_uri(uri, iso3_code="IND")
        assert isinstance(otp, str)
