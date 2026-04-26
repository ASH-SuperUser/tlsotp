import pytest
from tlsotp.interface import key_gen, get_data_dict, get_OTP_from_dict


# ---------------- KEY GEN ----------------

def test_key_gen_uniqueness():
    k1 = key_gen()
    k2 = key_gen()
    assert k1 != k2


# ---------------- DATA VALIDATION ----------------

def test_invalid_otp_mode():
    with pytest.raises(ValueError):
        get_data_dict(main_key="abc", otp_mode=99)


def test_invalid_n_chars():
    with pytest.raises(ValueError):
        get_data_dict(main_key="abc", n_chars=0)


def test_invalid_time_binning():
    with pytest.raises(ValueError):
        get_data_dict(main_key="abc", time_binning=-1)


def test_location_requires_iso():
    with pytest.raises(ValueError):
        get_data_dict(main_key="abc", location_mode=301)


def test_location_requires_latlon():
    with pytest.raises(ValueError):
        get_data_dict(main_key="abc", location_mode=1)


def test_password_required():
    with pytest.raises(ValueError):
        get_data_dict(main_key="abc", password_str_mode=2)


def test_invalid_algorithm():
    with pytest.raises(ValueError):
        get_data_dict(main_key="abc", algorithm="bad_algo")


# ---------------- OTP FROM DICT ----------------

def test_extra_keys_ignored():
    data = {
        "main_key": "abc",
        "extra": "ignore_me"
    }
    otp = get_OTP_from_dict(data)
    assert isinstance(otp, str)


def test_defaults_applied():
    data = {"main_key": "abc"}
    otp = get_OTP_from_dict(data)
    assert len(otp) == 6


def test_full_dict_flow():
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