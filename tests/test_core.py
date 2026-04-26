import pytest
import time
from tlsotp.core import (
    OTP_gen,
    time_str,
    location_str,
    password_str,
    get_time_OTP,
    get_OTP
)


# ---------------- OTP GEN ----------------

def test_otp_gen_invalid_mode():
    with pytest.raises(ValueError):
        OTP_gen(b'\x00\x01', otp_mode=99)


def test_otp_gen_empty_bytes():
    with pytest.raises(ZeroDivisionError):
        OTP_gen(b'', otp_mode=0)


def test_otp_gen_large_length():
    otp = OTP_gen(b'\x01\x02', otp_mode=2, n_chars=128)
    assert len(otp) == 128


# ---------------- TIME ----------------

def test_time_str_deterministic(monkeypatch):
    def fake_time():
        return 1000

    monkeypatch.setattr(time, "time", fake_time)

    assert time_str(30) == "-990-"


def test_time_str_different_bins(monkeypatch):
    monkeypatch.setattr(time, "time", lambda: 1000)

    t1 = time_str(30)
    t2 = time_str(60)

    assert t1 != t2


# ---------------- LOCATION ----------------

def test_location_precision_mode():
    result = location_str(2, latitude=12.34567, longitude=77.98765)
    assert result.startswith("12.35")


def test_location_grid_mode():
    result = location_str(-10, latitude=27.9, longitude=88.1)
    assert result == "20-80"


def test_location_4xx_mode():
    result = location_str(402, latitude=12.345, longitude=77.987, iso3_code="IND")
    assert "IND" in result


def test_location_5xx_mode():
    result = location_str(501, latitude=27.9, longitude=88.1, iso3_code="IND")
    assert "IND" in result


def test_location_missing_data():
    assert location_str(1) == ""


# ---------------- PASSWORD ----------------

def test_password_none():
    assert password_str(1, None) == ""


def test_password_zero_mode():
    assert password_str(0, "secret") == ""


# ---------------- TIME OTP ----------------

def test_get_time_otp_all_algorithms(monkeypatch):
    monkeypatch.setattr(time, "time", lambda: 1000)

    for algo in [0, 1, 2, 3, 4, 5, 'sha1', 'sha256', 'sha512']:
        otp = get_time_OTP("key", algorithm=algo)
        assert isinstance(otp, str)


def test_get_time_otp_invalid_algo():
    with pytest.raises(ValueError):
        get_time_OTP("key", algorithm="invalid")


# ---------------- FULL OTP ----------------

def test_get_otp_full_combination(monkeypatch):
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


def test_get_otp_different_inputs(monkeypatch):
    monkeypatch.setattr(time, "time", lambda: 1000)

    otp1 = get_OTP("key1")
    otp2 = get_OTP("key2")

    assert otp1 != otp2


def test_get_otp_time_variation(monkeypatch):
    monkeypatch.setattr(time, "time", lambda: 1000)
    otp1 = get_OTP("key")

    monkeypatch.setattr(time, "time", lambda: 2000)
    otp2 = get_OTP("key")

    assert otp1 != otp2