import pytest
from hypothesis import given, strategies as st
from tlsotp.interface import get_data_dict, get_OTP_from_dict


@given(st.dictionaries(
    keys=st.text(min_size=0, max_size=20),
    values=st.one_of(
        st.text(),
        st.integers(),
        st.floats(allow_nan=False),
        st.none()
    ),
    max_size=20
))
def test_random_dict_input(data):
    """
    Fuzz test: random dictionaries should not crash system.
    Either:
    - clean ValueError
    - or valid OTP
    """
    try:
        otp = get_OTP_from_dict(data)
        assert isinstance(otp, str)
    except Exception as e:
        assert isinstance(e, ValueError)


# Extreme strings
@given(st.text(min_size=0, max_size=10000))
def test_extreme_key_sizes(key):
    try:
        if key:
            data = get_data_dict(main_key=key)
            otp = get_OTP_from_dict(data)
            assert isinstance(otp, str)
    except ValueError:
        pass


# Numeric edge cases
@given(st.integers(min_value=-10**9, max_value=10**9))
def test_extreme_n_chars(n):
    try:
        data = get_data_dict(main_key="abc", n_chars=n)
        otp = get_OTP_from_dict(data)
        assert isinstance(otp, str)
    except ValueError:
        pass