from unittest.mock import patch

from hypothesis import given, settings
from hypothesis import strategies as st

from tlsotp.core import OTP_gen, get_OTP
from tlsotp.interface import get_data_dict, get_OTP_from_dict

# ===================== OTP_gen property tests =====================

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


@given(
    data=st.binary(min_size=1, max_size=64),
    mode=st.integers(min_value=0, max_value=2)
)
def test_otp_gen_deterministic(data, mode):
    otp1 = OTP_gen(data, otp_mode=mode, n_chars=10)
    otp2 = OTP_gen(data, otp_mode=mode, n_chars=10)
    assert otp1 == otp2


def test_otp_gen_different_inputs():
    assert OTP_gen(b'\x00\xff') != OTP_gen(b'\xff\x00')


# ===================== get_OTP determinism =====================

@given(key=st.text(min_size=1, max_size=50))
@settings(max_examples=50)
def test_get_otp_deterministic(key):
    with patch("time.time", return_value=1000):
        otp1 = get_OTP(key)
        otp2 = get_OTP(key)
        assert otp1 == otp2


@given(
    key1=st.text(min_size=1, max_size=50),
    key2=st.text(min_size=1, max_size=50),
)
@settings(max_examples=50)
def test_get_otp_diff_keys(key1, key2):
    with patch("time.time", return_value=1000):
        if key1 != key2:
            assert get_OTP(key1) != get_OTP(key2)


@given(key=st.text(min_size=1, max_size=50))
@settings(max_examples=30)
def test_get_otp_time_changes(key):
    with patch("time.time", return_value=1000):
        otp1 = get_OTP(key)
    with patch("time.time", return_value=2000):
        otp2 = get_OTP(key)
    assert otp1 != otp2


# ===================== Output format properties =====================

@given(
    key=st.text(min_size=1, max_size=30),
    mode=st.integers(min_value=0, max_value=2),
)
@settings(max_examples=30)
def test_get_otp_format_modes(key, mode):
    with patch("time.time", return_value=1000):
        otp = get_OTP(key, otp_mode=mode)
        if mode == 0:
            assert otp.isdigit()
        elif mode == 1:
            assert otp.isalpha()
        elif mode == 2:
            assert otp.isalnum()


@given(
    key=st.text(min_size=1, max_size=30),
    n_chars=st.integers(min_value=1, max_value=128),
)
@settings(max_examples=50)
def test_output_length(key, n_chars):
    with patch("time.time", return_value=1000):
        otp = get_OTP(key, n_chars=n_chars)
        assert len(otp) == n_chars


# ===================== Interface pipeline =====================

@given(
    key=st.text(min_size=1, max_size=50),
    otp_mode=st.integers(0, 2),
    n_chars=st.integers(1, 32),
)
@settings(max_examples=50)
def test_dict_pipeline(key, otp_mode, n_chars):
    data = get_data_dict(main_key=key, otp_mode=otp_mode, n_chars=n_chars)
    otp = get_OTP_from_dict(data)
    assert isinstance(otp, str)
    assert len(otp) == n_chars


# ===================== Algorithm coverage =====================

@given(
    key=st.text(min_size=1, max_size=50),
    algo=st.sampled_from([0, 1, 2, 3, 4, 5, 'sha1', 'sha224', 'sha256', 'sha384', 'sha512', 'sha3-512']),
)
@settings(max_examples=50)
def test_all_algorithms(key, algo):
    with patch("time.time", return_value=1000):
        otp = get_OTP(key, algorithm=algo)
        assert isinstance(otp, str)
        assert len(otp) == 6


# ===================== Location robustness =====================

@given(
    lat=st.floats(min_value=-90, max_value=90, allow_nan=False, allow_infinity=False),
    lon=st.floats(min_value=-180, max_value=180, allow_nan=False, allow_infinity=False),
)
@settings(max_examples=50)
def test_location_inputs(lat, lon):
    with patch("time.time", return_value=1000):
        otp = get_OTP(main_key="key", location_mode=1, latitude=lat, longitude=lon)
        assert isinstance(otp, str)


# ===================== Password modes =====================

@given(
    key=st.text(min_size=1, max_size=50),
    pwd=st.text(min_size=1, max_size=50),
    mode=st.integers(min_value=-5, max_value=10),
)
@settings(max_examples=50)
def test_password_modes(key, pwd, mode):
    with patch("time.time", return_value=1000):
        otp = get_OTP(key, password_str_mode=mode, password_string=pwd)
        assert isinstance(otp, str)


# ===================== No crash on valid input space =====================

@given(
    key=st.text(min_size=1, max_size=50),
    lat=st.one_of(st.none(), st.floats(-90, 90, allow_nan=False)),
    lon=st.one_of(st.none(), st.floats(-180, 180, allow_nan=False)),
    iso=st.one_of(st.none(), st.text(min_size=3, max_size=5)),
)
@settings(max_examples=100)
def test_no_crash_valid_space(key, lat, lon, iso):
    with patch("time.time", return_value=1000):
        try:
            otp = get_OTP(
                main_key=key,
                location_mode=0 if lat is None else 1,
                latitude=lat,
                longitude=lon,
                iso3_code=iso,
            )
            assert isinstance(otp, str)
        except ValueError:
            pass


# ===================== Location mode 4xx/5xx =====================

@given(
    lat=st.floats(-90, 90, allow_nan=False),
    lon=st.floats(-180, 180, allow_nan=False),
    iso=st.text(min_size=3, max_size=3),
    precision=st.integers(min_value=1, max_value=10),
)
@settings(max_examples=30)
def test_location_4xx_modes(lat, lon, iso, precision):
    loc_mode = 400 + precision
    with patch("time.time", return_value=1000):
        otp = get_OTP(
            main_key="key",
            location_mode=loc_mode,
            latitude=lat,
            longitude=lon,
            iso3_code=iso,
        )
        assert isinstance(otp, str)


@given(
    lat=st.floats(-90, 90, allow_nan=False),
    lon=st.floats(-180, 180, allow_nan=False),
    iso=st.text(min_size=3, max_size=3),
    step=st.integers(min_value=1, max_value=10),
)
@settings(max_examples=30)
def test_location_5xx_modes(lat, lon, iso, step):
    loc_mode = 500 + step
    with patch("time.time", return_value=1000):
        otp = get_OTP(
            main_key="key",
            location_mode=loc_mode,
            latitude=lat,
            longitude=lon,
            iso3_code=iso,
        )
        assert isinstance(otp, str)


@given(
    lat=st.floats(-90, 90, allow_nan=False),
    lon=st.floats(-180, 180, allow_nan=False),
    iso=st.text(min_size=3, max_size=3),
    precision=st.integers(min_value=1, max_value=10),
)
@settings(max_examples=30)
def test_location_6xx_modes(lat, lon, iso, precision):
    loc_mode = 600 + precision
    with patch("time.time", return_value=1000):
        otp = get_OTP(
            main_key="key",
            location_mode=loc_mode,
            latitude=lat,
            longitude=lon,
            iso3_code=iso,
        )
        assert isinstance(otp, str)


@given(
    lat=st.floats(-90, 90, allow_nan=False),
    lon=st.floats(-180, 180, allow_nan=False),
    iso=st.text(min_size=3, max_size=3),
    step=st.integers(min_value=1, max_value=10),
)
@settings(max_examples=30)
def test_location_7xx_modes(lat, lon, iso, step):
    loc_mode = 700 + step
    with patch("time.time", return_value=1000):
        otp = get_OTP(
            main_key="key",
            location_mode=loc_mode,
            latitude=lat,
            longitude=lon,
            iso3_code=iso,
        )
        assert isinstance(otp, str)


# ===================== get_OTP with location 301 =====================

@given(
    iso=st.text(min_size=3, max_size=5),
)
@settings(max_examples=20)
def test_location_mode_301(iso):
    with patch("time.time", return_value=1000):
        otp = get_OTP(main_key="key", location_mode=301, iso3_code=iso)
        assert isinstance(otp, str)


# ===================== get_OTP with password variations =====================

@given(
    key=st.text(min_size=1, max_size=30),
    pwd=st.text(min_size=0, max_size=30),
)
@settings(max_examples=30)
def test_password_empty_string(key, pwd):
    with patch("time.time", return_value=1000):
        otp = get_OTP(key, password_str_mode=0, password_string=pwd)
        assert isinstance(otp, str)
