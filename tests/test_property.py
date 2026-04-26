import pytest
from hypothesis import given, strategies as st, settings
from unittest.mock import patch

from tlsotp.core import OTP_gen, get_OTP
from tlsotp.interface import get_data_dict, get_OTP_from_dict


# ---------------- OTP GEN PROPERTIES ----------------

@given(
    data=st.binary(min_size=1, max_size=128),
    n_chars=st.integers(min_value=1, max_value=128),
    mode=st.integers(min_value=0, max_value=2)
)
def test_otp_gen_properties(data, n_chars, mode):
    otp = OTP_gen(data, otp_mode=mode, n_chars=n_chars)

    assert isinstance(otp, str)
    assert len(otp) == n_chars

    if mode == 0:
        assert otp.isdigit()
    elif mode == 1:
        assert otp.isalpha()
    elif mode == 2:
        assert otp.isalnum()


# ---------------- OTP GEN STABILITY ----------------

@given(
    data=st.binary(min_size=1, max_size=64),
    mode=st.integers(min_value=0, max_value=2)
)
def test_otp_gen_deterministic(data, mode):
    otp1 = OTP_gen(data, otp_mode=mode, n_chars=10)
    otp2 = OTP_gen(data, otp_mode=mode, n_chars=10)

    assert otp1 == otp2


# ---------------- CORE OTP DETERMINISM ----------------

@given(
    key=st.text(min_size=1, max_size=50),
)
@settings(max_examples=100)
def test_get_otp_deterministic_same_input(key):
    with patch("time.time", return_value=1000):
        otp1 = get_OTP(key)
        otp2 = get_OTP(key)

        assert otp1 == otp2


# ---------------- DIFFERENT KEYS → DIFFERENT OTP ----------------

@given(
    key1=st.text(min_size=1, max_size=50),
    key2=st.text(min_size=1, max_size=50),
)
def test_get_otp_diff_keys(key1, key2):
    with patch("time.time", return_value=1000):
        if key1 != key2:
            assert get_OTP(key1) != get_OTP(key2)


# ---------------- TIME VARIATION ----------------

@given(
    key=st.text(min_size=1, max_size=50),
)
def test_get_otp_time_changes(key):
    with patch("time.time", return_value=1000):
        otp1 = get_OTP(key)

    with patch("time.time", return_value=2000):
        otp2 = get_OTP(key)

    assert otp1 != otp2


# ---------------- INTERFACE ROUNDTRIP ----------------

@given(
    key=st.text(min_size=1, max_size=50),
    otp_mode=st.integers(0, 2),
    n_chars=st.integers(1, 32),
)
def test_dict_pipeline(key, otp_mode, n_chars):
    data = get_data_dict(
        main_key=key,
        otp_mode=otp_mode,
        n_chars=n_chars
    )

    otp = get_OTP_from_dict(data)

    assert isinstance(otp, str)
    assert len(otp) == n_chars


# ---------------- LOCATION ROBUSTNESS ----------------

@given(
    lat=st.floats(min_value=-90, max_value=90, allow_nan=False, allow_infinity=False),
    lon=st.floats(min_value=-180, max_value=180, allow_nan=False, allow_infinity=False),
)
def test_location_inputs(lat, lon):
    with patch("time.time", return_value=1000):
        otp = get_OTP(
            main_key="key",
            location_mode=1,
            latitude=lat,
            longitude=lon
        )

        assert isinstance(otp, str)


# ---------------- PASSWORD MODES ----------------

@given(
    key=st.text(min_size=1, max_size=50),
    pwd=st.text(min_size=1, max_size=50),
    mode=st.integers(min_value=-5, max_value=10)
)
def test_password_modes(key, pwd, mode):
    with patch("time.time", return_value=1000):
        if mode == 0:
            otp = get_OTP(key, password_str_mode=mode, password_string=pwd)
            assert isinstance(otp, str)

        else:
            otp = get_OTP(
                key,
                password_str_mode=mode,
                password_string=pwd
            )
            assert isinstance(otp, str)


# ---------------- ALGORITHM COVERAGE ----------------

@given(
    key=st.text(min_size=1, max_size=50),
    algo=st.sampled_from([0, 1, 2, 3, 4, 5, 'sha1', 'sha224', 'sha256', 'sha384', 'sha512', 'sha3-512'])
)
def test_all_algorithms(key, algo):
    with patch("time.time", return_value=1000):
        otp = get_OTP(key, algorithm=algo)
        assert isinstance(otp, str)


# ---------------- LENGTH GUARANTEE ----------------

@given(
    key=st.text(min_size=1, max_size=50),
    n_chars=st.integers(min_value=1, max_value=128)
)
def test_output_length(key, n_chars):
    with patch("time.time", return_value=1000):
        otp = get_OTP(key, n_chars=n_chars)
        assert len(otp) == n_chars


# ---------------- NO CRASH ON VALID INPUT SPACE ----------------

@given(
    key=st.text(min_size=1, max_size=50),
    lat=st.one_of(st.none(), st.floats(-90, 90, allow_nan=False)),
    lon=st.one_of(st.none(), st.floats(-180, 180, allow_nan=False)),
    iso=st.one_of(st.none(), st.text(min_size=3, max_size=5)),
)
def test_no_crash_valid_space(key, lat, lon, iso):
    with patch("time.time", return_value=1000):
        try:
            otp = get_OTP(
                main_key=key,
                location_mode=0 if lat is None else 1,
                latitude=lat,
                longitude=lon,
                iso3_code=iso
            )
            assert isinstance(otp, str)
        except ValueError:
            # acceptable
            pass