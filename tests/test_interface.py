import pytest

from tlsotp.interface import (
    get_data_dict,
    get_OTP_from_dict,
    key_gen,
)

# ======================== top-level re-exports ========================

class TestTopLevelExports:
    def test_get_OTP_is_importable(self):
        import tlsotp
        assert hasattr(tlsotp, "get_OTP")

        from tlsotp import get_OTP
        assert callable(get_OTP)

    def test_get_OTP_is_re_exported_via_interface_all(self):
        from tlsotp.interface import __all__
        assert "get_OTP" in __all__


# ======================== key_gen ========================

class TestKeyGen:
    def test_generates_string(self):
        k = key_gen()
        assert isinstance(k, str)

    def test_uniqueness(self):
        k1 = key_gen()
        k2 = key_gen()
        assert k1 != k2

    def test_default_length_positive(self):
        k = key_gen()
        assert len(k) > 0

    def test_custom_length(self):
        k = key_gen(length=64)
        assert len(k) > 0

    def test_urlsafe_chars(self):
        k = key_gen()
        assert all(c in 'ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789-_' for c in k)


# ======================== get_data_dict ========================

class TestGetDataDict:
    def test_valid_minimal(self):
        d = get_data_dict(main_key="abc")
        assert d['main_key'] == "abc"
        assert d['otp_mode'] == 0
        assert d['n_chars'] == 6
        assert d['time_binning'] == 30
        assert d['algorithm'] == 0

    def test_valid_full(self):
        d = get_data_dict(
            main_key="abc", otp_mode=2, n_chars=8, time_binning=60,
            location_mode=301, iso3_code="USA",
            password_str_mode=2, password_string="secret",
            algorithm="sha256"
        )
        assert d['main_key'] == "abc"
        assert d['otp_mode'] == 2
        assert d['n_chars'] == 8
        assert d['time_binning'] == 60
        assert d['location_mode'] == 301
        assert d['iso3_code'] == "USA"
        assert d['password_str_mode'] == 2
        assert d['password_string'] == "secret"
        assert d['algorithm'] == "sha256"

    def test_empty_main_key_raises(self):
        with pytest.raises(ValueError, match="main_key"):
            get_data_dict(main_key="")

    def test_non_string_key_raises(self):
        with pytest.raises(ValueError, match="main_key"):
            get_data_dict(main_key=123)

    def test_invalid_otp_mode_raises(self):
        with pytest.raises(ValueError, match="otp_mode"):
            get_data_dict(main_key="abc", otp_mode=99)

    def test_negative_otp_mode_raises(self):
        with pytest.raises(ValueError, match="otp_mode"):
            get_data_dict(main_key="abc", otp_mode=-1)

    def test_n_chars_zero_raises(self):
        with pytest.raises(ValueError, match="n_chars"):
            get_data_dict(main_key="abc", n_chars=0)

    def test_n_chars_negative_raises(self):
        with pytest.raises(ValueError, match="n_chars"):
            get_data_dict(main_key="abc", n_chars=-5)

    def test_n_chars_too_large_raises(self):
        with pytest.raises(ValueError, match="n_chars"):
            get_data_dict(main_key="abc", n_chars=129)

    def test_n_chars_upper_bound(self):
        d = get_data_dict(main_key="abc", n_chars=128)
        assert d['n_chars'] == 128

    def test_n_chars_lower_bound(self):
        d = get_data_dict(main_key="abc", n_chars=1)
        assert d['n_chars'] == 1

    def test_time_binning_zero_raises(self):
        with pytest.raises(ValueError, match="time_binning"):
            get_data_dict(main_key="abc", time_binning=0)

    def test_time_binning_negative_raises(self):
        with pytest.raises(ValueError, match="time_binning"):
            get_data_dict(main_key="abc", time_binning=-1)

    def test_location_301_requires_iso3(self):
        with pytest.raises(ValueError, match="iso3_code"):
            get_data_dict(main_key="abc", location_mode=301)

    def test_location_301_short_iso3_raises(self):
        with pytest.raises(ValueError):
            get_data_dict(main_key="abc", location_mode=301, iso3_code="AB")

    def test_location_4xx_requires_latlon(self):
        with pytest.raises(ValueError, match="latitude"):
            get_data_dict(main_key="abc", location_mode=402)

    def test_location_4xx_works_without_iso3(self):
        d = get_data_dict(main_key="abc", location_mode=402, latitude=10, longitude=20)
        assert d["location_mode"] == 402
        assert d["iso3_code"] is None

    def test_location_5xx_requires_latlon(self):
        with pytest.raises(ValueError, match="latitude"):
            get_data_dict(main_key="abc", location_mode=502)

    def test_location_5xx_works_without_iso3(self):
        d = get_data_dict(main_key="abc", location_mode=502, latitude=10, longitude=20)
        assert d["location_mode"] == 502
        assert d["iso3_code"] is None

    def test_location_6xx_requires_all(self):
        with pytest.raises(ValueError, match="6xx"):
            get_data_dict(main_key="abc", location_mode=602)

        with pytest.raises(ValueError, match="6xx"):
            get_data_dict(main_key="abc", location_mode=602, latitude=10, longitude=20)

    def test_location_6xx_valid_full(self):
        d = get_data_dict(main_key="abc", location_mode=602, latitude=10, longitude=20, iso3_code="IND")
        assert d["iso3_code"] == "IND"

    def test_location_7xx_requires_all(self):
        with pytest.raises(ValueError, match="7xx"):
            get_data_dict(main_key="abc", location_mode=702)

        with pytest.raises(ValueError, match="7xx"):
            get_data_dict(main_key="abc", location_mode=702, latitude=10, longitude=20)

    def test_location_7xx_valid_full(self):
        d = get_data_dict(main_key="abc", location_mode=702, latitude=10, longitude=20, iso3_code="IND")
        assert d["iso3_code"] == "IND"

    def test_location_mode_1_requires_latlon(self):
        with pytest.raises(ValueError, match="latitude"):
            get_data_dict(main_key="abc", location_mode=1)

    def test_location_mode_1_partial_latlon_raises(self):
        with pytest.raises(ValueError, match="latitude"):
            get_data_dict(main_key="abc", location_mode=1, latitude=10.0)

    def test_latitude_out_of_range_high(self):
        with pytest.raises(ValueError, match="latitude"):
            get_data_dict(main_key="abc", location_mode=1, latitude=91, longitude=0)

    def test_latitude_out_of_range_low(self):
        with pytest.raises(ValueError, match="latitude"):
            get_data_dict(main_key="abc", location_mode=1, latitude=-91, longitude=0)

    def test_longitude_out_of_range_high(self):
        with pytest.raises(ValueError, match="longitude"):
            get_data_dict(main_key="abc", location_mode=1, latitude=0, longitude=181)

    def test_longitude_out_of_range_low(self):
        with pytest.raises(ValueError, match="longitude"):
            get_data_dict(main_key="abc", location_mode=1, latitude=0, longitude=-181)

    def test_boundary_lat_valid(self):
        d = get_data_dict(main_key="abc", location_mode=1, latitude=90, longitude=0)
        assert d['latitude'] == 90

    def test_boundary_lon_valid(self):
        d = get_data_dict(main_key="abc", location_mode=1, latitude=0, longitude=180)
        assert d['longitude'] == 180

    def test_password_required_when_mode_nonzero(self):
        with pytest.raises(ValueError, match="password_string"):
            get_data_dict(main_key="abc", password_str_mode=2)

    def test_non_int_password_mode_raises_before_password_check(self):
        with pytest.raises(ValueError, match="password_str_mode must be an integer"):
            get_data_dict(main_key="abc", password_str_mode="x")

    def test_non_int_password_mode_with_password_raises(self):
        with pytest.raises(ValueError, match="password_str_mode must be an integer"):
            get_data_dict(main_key="abc", password_str_mode=1.5, password_string="secret")

    def test_password_with_mode_positive(self):
        d = get_data_dict(main_key="abc", password_str_mode=2, password_string="hi")
        assert d['password_str_mode'] == 2
        assert d['password_string'] == "hi"

    def test_password_with_mode_negative(self):
        d = get_data_dict(main_key="abc", password_str_mode=-1, password_string="full")
        assert d['password_string'] == "full"

    def test_password_not_required_when_mode_zero(self):
        d = get_data_dict(main_key="abc", password_str_mode=0)
        assert d['password_string'] is None

    def test_invalid_algorithm_raises(self):
        with pytest.raises(ValueError, match="algorithm"):
            get_data_dict(main_key="abc", algorithm="bad_algo")

    def test_none_algorithm_raises(self):
        with pytest.raises(ValueError, match="algorithm"):
            get_data_dict(main_key="abc", algorithm=None)

    def test_all_valid_algorithms(self):
        for algo in [0, 1, 2, 3, 4, 5, 'sha1', 'sha224', 'sha256', 'sha384', 'sha512', 'sha3-512']:
            d = get_data_dict(main_key="abc", algorithm=algo)
            assert d['algorithm'] == algo

    def test_location_mode_negative_valid(self):
        d = get_data_dict(main_key="abc", location_mode=-10, latitude=10, longitude=20)
        assert d['location_mode'] == -10

    def test_negative_mode_no_lat(self):
        with pytest.raises(ValueError):
            get_data_dict(main_key="abc", location_mode=-10)


# ======================== get_OTP_from_dict ========================

class TestGetOTPFromDict:
    def test_minimal_dict(self):
        otp = get_OTP_from_dict({"main_key": "abc"})
        assert isinstance(otp, str)
        assert len(otp) == 6

    def test_extra_keys_ignored(self):
        otp = get_OTP_from_dict({"main_key": "abc", "extra": "ignore_me", "unknown": 42})
        assert isinstance(otp, str)

    def test_defaults_applied(self):
        otp = get_OTP_from_dict({"main_key": "abc"})
        assert len(otp) == 6

    def test_full_dict_flow(self):
        data = get_data_dict(
            main_key="abc123",
            otp_mode=2,
            n_chars=8,
            location_mode=301,
            iso3_code="IND",
            password_str_mode=2,
            password_string="secret",
            algorithm="sha256"
        )
        otp = get_OTP_from_dict(data)
        assert len(otp) == 8
        assert otp.isalnum()

    def test_missing_main_key_raises(self):
        with pytest.raises(ValueError, match="main_key"):
            get_OTP_from_dict({"otp_mode": 0})

    def test_empty_main_key_raises(self):
        with pytest.raises(ValueError, match="main_key"):
            get_OTP_from_dict({"main_key": ""})

    def test_non_dict_input_raises(self):
        with pytest.raises(TypeError, match="dictionary"):
            get_OTP_from_dict("not_a_dict")

    def test_none_input_raises(self):
        with pytest.raises(TypeError, match="dictionary"):
            get_OTP_from_dict(None)

    def test_all_settings_from_dict(self, monkeypatch):
        import time
        monkeypatch.setattr(time, "time", lambda: 1000)
        d = {
            "main_key": "key",
            "otp_mode": 2,
            "n_chars": 10,
            "time_binning": 30,
            "location_mode": 402,
            "latitude": 12.97,
            "longitude": 77.59,
            "iso3_code": "IND",
            "password_str_mode": 3,
            "password_string": "mypassword",
            "algorithm": "sha256"
        }
        otp = get_OTP_from_dict(d)
        assert len(otp) == 10

    def test_partial_overrides(self):
        otp1 = get_OTP_from_dict({"main_key": "abc"})
        otp2 = get_OTP_from_dict({"main_key": "abc", "n_chars": 10})
        assert len(otp1) == 6
        assert len(otp2) == 10

    def test_mode_301_missing_iso3_raises(self):
        with pytest.raises(ValueError, match="iso3_code"):
            get_OTP_from_dict({"main_key": "abc", "location_mode": 301})

    def test_mode_4xx_missing_latlon_raises(self):
        with pytest.raises(ValueError, match="latitude"):
            get_OTP_from_dict({"main_key": "abc", "location_mode": 402})

    def test_mode_negative_missing_latlon_raises(self):
        with pytest.raises(ValueError, match="latitude"):
            get_OTP_from_dict({"main_key": "abc", "location_mode": -5})

    def test_password_mode_missing_string_raises(self):
        with pytest.raises(ValueError, match="password_string"):
            get_OTP_from_dict({"main_key": "abc", "password_str_mode": 2})

