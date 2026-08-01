from hypothesis import given, settings
from hypothesis import strategies as st

from tlsotp.core import OTP_gen, get_OTP
from tlsotp.interface import get_data_dict, get_OTP_from_dict


@given(st.dictionaries(
    keys=st.text(min_size=0, max_size=20),
    values=st.one_of(st.text(), st.integers(), st.floats(allow_nan=False), st.none()),
    max_size=20,
))
@settings(max_examples=200)
def test_random_dict_input(data):
    try:
        otp = get_OTP_from_dict(data)
        assert isinstance(otp, str)
    except (ValueError, TypeError):
        pass


@given(st.text(min_size=0, max_size=10000))
@settings(max_examples=100)
def test_extreme_key_sizes(key):
    try:
        if key:
            data = get_data_dict(main_key=key)
            otp = get_OTP_from_dict(data)
            assert isinstance(otp, str)
    except (ValueError, TypeError):
        pass


@given(st.integers(min_value=-10**9, max_value=10**9))
@settings(max_examples=100)
def test_extreme_n_chars(n):
    try:
        data = get_data_dict(main_key="abc", n_chars=n)
        otp = get_OTP_from_dict(data)
        assert isinstance(otp, str)
    except (ValueError, TypeError):
        pass


@given(
    key=st.text(min_size=0, max_size=100),
    lat=st.floats(allow_nan=False, allow_infinity=False),
    lon=st.floats(allow_nan=False, allow_infinity=False),
    iso=st.one_of(st.none(), st.text(max_size=10)),
    pwd=st.one_of(st.none(), st.text(max_size=100)),
    algo=st.one_of(st.none(), st.integers(-5, 10), st.text(max_size=20)),
)
@settings(max_examples=200)
def test_get_otp_fuzz(key, lat, lon, iso, pwd, algo):
    from unittest.mock import patch
    with patch("time.time", return_value=1000):
        try:
            kwargs = {"main_key": key} if key else {}
            if not kwargs:
                return
            if lat is not None:
                kwargs['latitude'] = lat
            if lon is not None:
                kwargs['longitude'] = lon
            if iso is not None:
                kwargs['iso3_code'] = iso
            if pwd is not None:
                kwargs['password_string'] = pwd
            if algo is not None:
                kwargs['algorithm'] = algo

            otp = get_OTP(**kwargs)
            assert isinstance(otp, str)
        except (ValueError, TypeError, ZeroDivisionError, OverflowError):
            pass


@given(
    data=st.binary(min_size=0, max_size=256),
    n_chars=st.integers(min_value=-10, max_value=256),
    mode=st.integers(min_value=-5, max_value=10),
)
@settings(max_examples=100)
def test_otp_gen_fuzz(data, n_chars, mode):
    try:
        otp = OTP_gen(data, otp_mode=mode, n_chars=n_chars)
        assert isinstance(otp, str)
        if n_chars > 0:
            assert len(otp) == n_chars
    except (ValueError, ZeroDivisionError):
        pass


@given(
    time_binning=st.integers(min_value=-1000, max_value=1000),
)
@settings(max_examples=50)
def test_time_str_fuzz(time_binning):
    from tlsotp.core import time_str
    try:
        result = time_str(time_binning)
        assert isinstance(result, str)
    except (ValueError, ZeroDivisionError):
        pass



