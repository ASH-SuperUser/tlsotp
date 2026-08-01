import time

import pytest

from tlsotp.core import (
    OTP_gen,
    get_OTP,
    get_time_OTP,
    location_str,
    password_str,
    time_str,
)

# ======================== OTP_gen ========================

class TestOTPGen:
    def test_empty_bytes_raises_valueerror(self):
        with pytest.raises(ValueError, match="non-empty"):
            OTP_gen(b'', otp_mode=0)

    def test_invalid_mode_raises_valueerror(self):
        with pytest.raises(ValueError, match="otp_mode"):
            OTP_gen(b'\x00\x01', otp_mode=99)

    def test_negative_mode_raises_valueerror(self):
        with pytest.raises(ValueError, match="otp_mode"):
            OTP_gen(b'\x00\x01', otp_mode=-1)

    def test_mode_0_returns_digits(self):
        otp = OTP_gen(b'\x01\x02\x03', otp_mode=0, n_chars=10)
        assert otp.isdigit()

    def test_mode_1_returns_alpha(self):
        otp = OTP_gen(b'\x01\x02\x03', otp_mode=1, n_chars=10)
        assert otp.isalpha()

    def test_mode_2_returns_alnum(self):
        otp = OTP_gen(b'\x01\x02\x03', otp_mode=2, n_chars=10)
        assert otp.isalnum()

    def test_correct_length(self):
        for n in [1, 6, 8, 16, 32, 64, 128]:
            otp = OTP_gen(b'\x01\x02\x03', otp_mode=0, n_chars=n)
            assert len(otp) == n

    def test_deterministic(self):
        data = b'\xde\xad\xbe\xef'
        assert OTP_gen(data) == OTP_gen(data)

    def test_different_inputs_different_outputs(self):
        assert OTP_gen(b'\x00\xff') != OTP_gen(b'\xff\x00')

    def test_mode_0_only_digit_chars(self):
        otp = OTP_gen(b'\xff' * 32, otp_mode=0, n_chars=100)
        assert all(c in '0123456789' for c in otp)

    def test_mode_1_only_alpha_chars(self):
        otp = OTP_gen(b'\xff' * 32, otp_mode=1, n_chars=100)
        assert all(c.isalpha() for c in otp)
        assert all(c in 'ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz' for c in otp)

    def test_mode_2_alphabet_coverage(self):
        otp = OTP_gen(b'\xff' * 64, otp_mode=2, n_chars=500)
        alphabet = "0123456789ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz"
        assert all(c in alphabet for c in otp)

    def test_single_byte_input(self):
        otp = OTP_gen(b'\x42', otp_mode=0, n_chars=6)
        assert len(otp) == 6
        assert otp.isdigit()

    def test_large_input_bytes(self):
        otp = OTP_gen(b'\x01' * 1024, otp_mode=2, n_chars=128)
        assert len(otp) == 128

    def test_n_chars_1(self):
        otp = OTP_gen(b'\x01\x02', otp_mode=0, n_chars=1)
        assert len(otp) == 1


# ======================== time_str ========================

class TestTimeStr:
    def test_deterministic(self, monkeypatch):
        monkeypatch.setattr(time, "time", lambda: 1000)
        assert time_str(30) == "-990-"

    def test_different_bins_different_output(self, monkeypatch):
        monkeypatch.setattr(time, "time", lambda: 1000)
        assert time_str(30) != time_str(60)

    def test_bin_1(self, monkeypatch):
        monkeypatch.setattr(time, "time", lambda: 100)
        assert time_str(1) == "-100-"

    def test_large_bin(self, monkeypatch):
        monkeypatch.setattr(time, "time", lambda: 3600)
        assert time_str(3600) == "-3600-"

    def test_time_boundary(self, monkeypatch):
        monkeypatch.setattr(time, "time", lambda: 29)
        assert time_str(30) == "-0-"

    def test_format(self, monkeypatch):
        monkeypatch.setattr(time, "time", lambda: 12345)
        result = time_str(30)
        assert result.startswith('-')
        assert result.endswith('-')
        assert result.count('-') == 2

    def test_zero_binning_raises(self):
        with pytest.raises(ValueError, match="time_binning"):
            time_str(0)

    def test_negative_binning_raises(self):
        with pytest.raises(ValueError, match="time_binning"):
            time_str(-30)

    def test_non_int_binning_raises(self):
        with pytest.raises(ValueError, match="time_binning"):
            time_str("30")


# ======================== location_str ========================

class TestLocationStr:
    def test_mode_0_returns_empty(self):
        assert location_str(0) == ''

    def test_mode_301_with_iso3(self):
        assert location_str(301, iso3_code="IND") == "IND"

    def test_mode_301_truncates_long_iso3(self):
        assert location_str(301, iso3_code="INDIA") == "IND"

    def test_mode_301_without_iso3(self):
        assert location_str(301) == ''

    def test_mode_301_none_iso3(self):
        assert location_str(301, iso3_code=None) == ''

    def test_mode_4xx_full(self):
        result = location_str(402, latitude=12.34567, longitude=77.98765)
        assert result == "12.35-77.99"
        assert result.count('-') == 1

    def test_mode_4xx_ignores_iso3(self):
        result = location_str(402, latitude=12.34, longitude=77.98, iso3_code="IND")
        assert result == "12.34-77.98"
        assert "IND" not in result

    def test_mode_4xx_without_lat(self):
        assert location_str(402) == ''

    def test_mode_5xx_full(self):
        result = location_str(501, latitude=27.9, longitude=88.1)
        assert result == "27-88"

    def test_mode_5xx_ignores_iso3(self):
        result = location_str(501, latitude=27.9, longitude=88.1, iso3_code="IND")
        assert result == "27-88"
        assert "IND" not in result

    def test_mode_6xx_full(self):
        result = location_str(602, latitude=12.34567, longitude=77.98765, iso3_code="IND")
        assert result == "IND-12.35-77.99"
        assert result.count('-') == 2

    def test_mode_6xx_without_iso3(self):
        assert location_str(602, latitude=12.34, longitude=77.98) == ''

    def test_mode_6xx_without_lat(self):
        assert location_str(602, iso3_code="IND") == ''

    def test_mode_7xx_full(self):
        result = location_str(701, latitude=27.9, longitude=88.1, iso3_code="IND")
        assert result == "IND-27-88"

    def test_mode_7xx_without_iso3(self):
        assert location_str(701, latitude=27.9, longitude=88.1) == ''

    def test_negative_mode_grid(self):
        result = location_str(-10, latitude=27.9, longitude=88.1)
        assert result == "20-80"

    def test_negative_mode_large_step(self):
        result = location_str(-100, latitude=123.4, longitude=456.7)
        assert result == "100-400"

    def test_positive_precision_mode(self):
        result = location_str(2, latitude=12.34567, longitude=77.98765)
        assert result.startswith("12.35")
        assert result.endswith("77.99")

    def test_positive_precision_mode_missing_lat(self):
        assert location_str(2) == ''

    def test_location_301_positive_mode_fallthrough(self):
        result = location_str(301, latitude=12.34, longitude=56.78, iso3_code="USA")
        assert result == "USA"

    def test_location_301_fallthrough_no_iso(self):
        result = location_str(301, latitude=12.34, longitude=56.78)
        assert result == ''

    def test_mode_0_with_data(self):
        assert location_str(0, latitude=12.34, longitude=56.78, iso3_code="USA") == ''

    def test_precision_zero(self):
        result = location_str(0, latitude=12.34, longitude=56.78)
        assert result == ''

    def test_boundary_lat_lon(self):
        result = location_str(1, latitude=-90.0, longitude=-180.0)
        assert '-90.0' in result
        assert '-180.0' in result


# ======================== password_str ========================

class TestPasswordStr:
    def test_mode_0_returns_empty(self):
        assert password_str(0, "secret") == ''

    def test_none_pwd_returns_empty(self):
        assert password_str(1, None) == ''

    def test_positive_mode_truncates(self):
        assert password_str(3, "hello") == "-hel-"

    def test_positive_mode_less_than_pwd_length(self):
        assert password_str(10, "hi") == "-hi-"

    def test_negative_mode_returns_full(self):
        assert password_str(-1, "secret") == "-secret-"

    def test_negative_mode_long_pwd(self):
        assert password_str(-1, "a" * 1000) == f"-{'a' * 1000}-"

    def test_empty_string_pwd(self):
        assert password_str(1, "") == ''

    def test_mode_0_with_none_pwd(self):
        assert password_str(0, None) == ''

    def test_mode_0_with_empty_string(self):
        assert password_str(0, "") == ''

    def test_positive_mode_zero_chars(self):
        assert password_str(1, "a") == "-a-"


# ======================== get_time_OTP ========================

class TestGetTimeOTP:
    def test_all_algorithms(self, monkeypatch):
        monkeypatch.setattr(time, "time", lambda: 1000)
        for algo in [0, 1, 2, 3, 4, 5, 'sha1', 'sha224', 'sha256', 'sha384', 'sha512', 'sha3-512']:
            otp = get_time_OTP("key", algorithm=algo)
            assert isinstance(otp, str)
            assert len(otp) == 6

    def test_invalid_algorithm_raises(self):
        with pytest.raises(ValueError):
            get_time_OTP("key", algorithm="invalid")

    def test_none_algorithm_raises(self):
        with pytest.raises(ValueError):
            get_time_OTP("key", algorithm=None)

    def test_deterministic(self, monkeypatch):
        monkeypatch.setattr(time, "time", lambda: 1000)
        assert get_time_OTP("key") == get_time_OTP("key")

    def test_different_keys_different_otp(self, monkeypatch):
        monkeypatch.setattr(time, "time", lambda: 1000)
        assert get_time_OTP("key1") != get_time_OTP("key2")

    def test_empty_key_raises(self):
        with pytest.raises(ValueError):
            get_time_OTP("")

    def test_non_string_key_raises(self):
        with pytest.raises(ValueError):
            get_time_OTP(123)

    def test_different_binning(self, monkeypatch):
        monkeypatch.setattr(time, "time", lambda: 1000)
        assert get_time_OTP("key", time_binning=30) != get_time_OTP("key", time_binning=60)

    def test_otp_mode_affects_output(self, monkeypatch):
        monkeypatch.setattr(time, "time", lambda: 1000)
        dig = get_time_OTP("key", otp_mode=0)
        alpha = get_time_OTP("key", otp_mode=1)
        alnum = get_time_OTP("key", otp_mode=2)
        assert dig.isdigit()
        assert alpha.isalpha()
        assert alnum.isalnum()

    def test_sha3_512_works(self, monkeypatch):
        monkeypatch.setattr(time, "time", lambda: 1000)
        otp = get_time_OTP("key", algorithm='sha3-512')
        assert isinstance(otp, str) and len(otp) == 6


# ======================== get_OTP ========================

class TestGetOTP:
    def test_basic_otp(self, monkeypatch):
        monkeypatch.setattr(time, "time", lambda: 1000)
        otp = get_OTP("key")
        assert isinstance(otp, str)
        assert len(otp) == 6

    def test_deterministic(self, monkeypatch):
        monkeypatch.setattr(time, "time", lambda: 1000)
        assert get_OTP("key") == get_OTP("key")

    def test_different_keys(self, monkeypatch):
        monkeypatch.setattr(time, "time", lambda: 1000)
        assert get_OTP("key1") != get_OTP("key2")

    def test_time_variation(self, monkeypatch):
        monkeypatch.setattr(time, "time", lambda: 1000)
        otp1 = get_OTP("key")
        monkeypatch.setattr(time, "time", lambda: 2000)
        otp2 = get_OTP("key")
        assert otp1 != otp2

    def test_empty_key_raises(self):
        with pytest.raises(ValueError):
            get_OTP("")

    def test_non_string_key_raises(self):
        with pytest.raises(ValueError):
            get_OTP(123)

    def test_none_key_raises(self):
        with pytest.raises(ValueError):
            get_OTP(None)

    def test_full_combination(self, monkeypatch):
        monkeypatch.setattr(time, "time", lambda: 1000)
        otp = get_OTP(
            main_key="supersecret",
            otp_mode=2,
            n_chars=10,
            time_binning=30,
            location_mode=402,
            latitude=12.97,
            longitude=77.59,
            iso3_code="IND",
            password_str_mode=3,
            password_string="mypassword",
            algorithm='sha256'
        )
        assert len(otp) == 10
        assert otp.isalnum()

    def test_location_mode_301(self, monkeypatch):
        monkeypatch.setattr(time, "time", lambda: 1000)
        otp = get_OTP("key", location_mode=301, iso3_code="USA")
        assert isinstance(otp, str)

    def test_location_mode_301_no_iso(self, monkeypatch):
        monkeypatch.setattr(time, "time", lambda: 1000)
        otp = get_OTP("key", location_mode=301)
        assert isinstance(otp, str)

    def test_location_mode_301_short_iso_raises(self, monkeypatch):
        monkeypatch.setattr(time, "time", lambda: 1000)
        with pytest.raises(ValueError, match="iso3_code"):
            get_OTP("key", location_mode=301, iso3_code="AB")

    def test_location_mode_6xx_short_iso_raises(self, monkeypatch):
        monkeypatch.setattr(time, "time", lambda: 1000)
        with pytest.raises(ValueError, match="iso3_code"):
            get_OTP("key", location_mode=602, latitude=10, longitude=20, iso3_code="AB")

    def test_zero_time_binning_raises(self):
        with pytest.raises(ValueError, match="time_binning"):
            get_OTP("key", time_binning=0)

    def test_location_mode_negative_grid(self, monkeypatch):
        monkeypatch.setattr(time, "time", lambda: 1000)
        otp = get_OTP("key", location_mode=-10, latitude=40.7, longitude=-74.0)
        assert isinstance(otp, str)

    def test_password_mode_positive(self, monkeypatch):
        monkeypatch.setattr(time, "time", lambda: 1000)
        otp = get_OTP("key", password_str_mode=3, password_string="hello")
        assert isinstance(otp, str)

    def test_password_mode_negative(self, monkeypatch):
        monkeypatch.setattr(time, "time", lambda: 1000)
        otp = get_OTP("key", password_str_mode=-1, password_string="hello")
        assert isinstance(otp, str)

    def test_all_algorithms(self, monkeypatch):
        monkeypatch.setattr(time, "time", lambda: 1000)
        for algo in [0, 1, 2, 3, 4, 5, 'sha1', 'sha224', 'sha256', 'sha384', 'sha512', 'sha3-512']:
            otp = get_OTP("key", algorithm=algo)
            assert isinstance(otp, str)
            assert len(otp) == 6

    def test_invalid_algorithm(self):
        with pytest.raises(ValueError):
            get_OTP("key", algorithm="invalid")

    def test_all_otp_modes(self, monkeypatch):
        monkeypatch.setattr(time, "time", lambda: 1000)
        dig = get_OTP("key", otp_mode=0)
        alpha = get_OTP("key", otp_mode=1)
        alnum = get_OTP("key", otp_mode=2)
        assert dig.isdigit()
        assert alpha.isalpha()
        assert alnum.isalnum()

    def test_various_n_chars(self, monkeypatch):
        monkeypatch.setattr(time, "time", lambda: 1000)
        for n in [1, 6, 8, 16, 32, 64, 128]:
            otp = get_OTP("key", n_chars=n)
            assert len(otp) == n

    def test_different_binnings(self, monkeypatch):
        monkeypatch.setattr(time, "time", lambda: 1000)
        assert get_OTP("key", time_binning=1) != get_OTP("key", time_binning=3600)

    def test_no_location(self, monkeypatch):
        monkeypatch.setattr(time, "time", lambda: 1000)
        otp = get_OTP("key", location_mode=0)
        assert isinstance(otp, str)

    def test_no_password(self, monkeypatch):
        monkeypatch.setattr(time, "time", lambda: 1000)
        otp = get_OTP("key", password_str_mode=0)
        assert isinstance(otp, str)

    def test_unicode_key(self, monkeypatch):
        monkeypatch.setattr(time, "time", lambda: 1000)
        otp = get_OTP("\u00e9\u00e0\u00fc\u00f1")
        assert isinstance(otp, str)

    def test_unicode_password(self, monkeypatch):
        monkeypatch.setattr(time, "time", lambda: 1000)
        otp = get_OTP("key", password_str_mode=-1, password_string="\u00e9\u00e0")
        assert isinstance(otp, str)

    def test_very_long_key(self, monkeypatch):
        monkeypatch.setattr(time, "time", lambda: 1000)
        otp = get_OTP("k" * 10000)
        assert isinstance(otp, str)
