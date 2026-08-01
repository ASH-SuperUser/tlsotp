import time

import pytest

from tlsotp import legacy as L
from tlsotp.interface import (
    get_dict_from_uri,
    get_OTP,
    get_OTP_from_dict,
    get_otp_from_uri,
    get_OTP_uri,
    get_OTP_uri_from_dict,
    verify_otp,
    verify_otp_from_dict,
    verify_otp_from_uri,
)

# ======================== normalize_version / is_current_version ========================

class TestVersionHelpers:
    def test_normalize_v0_2(self):
        assert L.normalize_version("v0.2") == "v0.2"

    def test_normalize_no_v(self):
        assert L.normalize_version("0.2") == "v0.2"

    def test_normalize_three_part(self):
        assert L.normalize_version("v0.2.0") == "v0.2"

    def test_normalize_v1(self):
        assert L.normalize_version("v1") == "v1.0"

    def test_normalize_current(self):
        assert L.normalize_version("v1.0") == "v1.0"

    def test_normalize_empty_raises(self):
        with pytest.raises(ValueError):
            L.normalize_version("")

    def test_normalize_garbage_raises(self):
        with pytest.raises(ValueError):
            L.normalize_version("abc")

    def test_is_current_version_none(self):
        assert L.is_current_version("v1.0") is True

    def test_is_current_version_future_minor(self):
        assert L.is_current_version("v1.3") is True

    def test_is_current_version_legacy_false(self):
        assert L.is_current_version("v0.2") is False

    def test_supported_legacy_versions(self):
        assert L.supported_legacy_versions() == ("v0.1", "v0.2")

    def test_current_version_constant(self):
        assert L.CURRENT_VERSION == "v1.0"


# ======================== v0.2 fixtures (ground truth from v0.2.0) ========================

class TestLegacyV02Fixtures:
    NOW = 1000.0

    def _otp(self, **kw):
        return L.get_otp_legacy("key", "v0.2", now=self.NOW, **kw)

    def test_base(self):
        assert self._otp() == "112982"

    def test_mode2_8chars(self):
        assert self._otp(otp_mode=2, n_chars=8) == "A7GyoFSU"

    def test_sha256(self):
        assert self._otp(algorithm=2) == "294960"

    def test_sha3(self):
        assert self._otp(algorithm=5) == "810096"

    def test_binning60(self):
        assert self._otp(time_binning=60) == "588902"

    def test_location301(self):
        assert self._otp(location_mode=301, iso3_code="IND") == "662651"

    def test_location402(self):
        assert self._otp(
            location_mode=402, iso3_code="IND",
            latitude=28.6139, longitude=77.2090,
        ) == "772814"

    def test_location520(self):
        assert self._otp(
            location_mode=520, iso3_code="IND",
            latitude=28.6139, longitude=77.2090,
        ) == "209636"

    def test_location_negative(self):
        assert self._otp(location_mode=-5, latitude=28.6139, longitude=77.2090) == "239600"

    def test_password_positive(self):
        assert self._otp(password_str_mode=4, password_string="DelhiSecure") == "291236"

    def test_password_negative(self):
        assert self._otp(password_str_mode=-1, password_string="MyPass") == "598366"

    def test_requires_iso3_for_4xx(self):
        # v0.2 4xx embeds the ISO3 code and returns '' without it
        assert self._otp(location_mode=402, latitude=28.6139, longitude=77.2090) != "772814"


# ======================== v0.1 vs v0.2 ========================

class TestLegacyV01:
    NOW = 1000.0

    def test_v01_matches_v02(self):
        for kw in [
            {},
            {"otp_mode": 2, "n_chars": 8},
            {"algorithm": 2},
            {"location_mode": 301, "iso3_code": "IND"},
            {"password_str_mode": -1, "password_string": "MyPass"},
        ]:
            a = L.get_otp_legacy("key", "v0.1", now=self.NOW, **kw)
            b = L.get_otp_legacy("key", "v0.2", now=self.NOW, **kw)
            assert a == b


# ======================== legacy dispatch ========================

class TestLegacyDispatch:
    def test_unsupported_version_raises(self):
        with pytest.raises(ValueError, match="[Uu]nsupported"):
            L.get_otp_legacy("key", "v0.9")

    def test_current_version_not_legacy(self):
        # v1.x must route to the live core algorithm, never the legacy module
        with pytest.raises(ValueError, match="[Uu]nsupported"):
            L.get_otp_legacy("key", "v1.0")

    def test_empty_version_raises(self):
        with pytest.raises(ValueError):
            L.get_otp_legacy("key", "")

    def test_get_otp_legacy_requires_key(self):
        with pytest.raises(ValueError, match="main_key"):
            L.get_otp_legacy("", "v0.2")


# ======================== get_OTP with use_version ========================

class TestGetOTPUseVersion:
    def test_default_is_current(self, monkeypatch):
        monkeypatch.setattr(time, "time", lambda: 1000)
        assert get_OTP("key") == get_OTP("key", use_version=None)
        assert get_OTP("key") == get_OTP("key", use_version="v1.0")

    def test_v02_request(self):
        assert get_OTP("key", use_version="v0.2", now=1000) == "112982"

    def test_v02_normalized(self):
        assert get_OTP("key", use_version="0.2.0", now=1000) == "112982"

    def test_unsupported_legacy_version_raises(self):
        with pytest.raises(ValueError, match="[Uu]nsupported"):
            get_OTP("key", use_version="v0.9")

    def test_current_version_uses_core(self):
        # legacy OTP_gen differs from v1.0, so this must NOT equal the legacy value
        assert get_OTP("key", use_version="v1.0", now=1000) != "112982"


# ======================== get_OTP_from_dict with use_version ========================

class TestGetOTPFromDictUseVersion:
    def test_default_current(self, monkeypatch):
        monkeypatch.setattr(time, "time", lambda: 1000)
        assert get_OTP_from_dict({"main_key": "key"}) == get_OTP("key")

    def test_explicit_v02(self, monkeypatch):
        monkeypatch.setattr(time, "time", lambda: 1000)
        assert get_OTP_from_dict({"main_key": "key"}, use_version="v0.2") == "112982"

    def test_dict_version_key_honored(self, monkeypatch):
        monkeypatch.setattr(time, "time", lambda: 1000)
        assert get_OTP_from_dict({"main_key": "key", "version": "v0.2"}) == "112982"

    def test_dict_version_key_overridden_by_explicit(self, monkeypatch):
        monkeypatch.setattr(time, "time", lambda: 1000)
        legacy = get_OTP_from_dict({"main_key": "key", "version": "v0.2"}, use_version="v1.0")
        assert legacy != "112982"
        assert legacy == get_OTP("key", now=1000)

    def test_v02_with_params(self, monkeypatch):
        monkeypatch.setattr(time, "time", lambda: 1000)
        otp = get_OTP_from_dict(
            {
                "main_key": "key",
                "otp_mode": 2,
                "n_chars": 8,
                "algorithm": 2,
                "location_mode": 301,
                "iso3_code": "IND",
            },
            use_version="v0.2",
        )
        assert otp == get_OTP(
            "key", use_version="v0.2",
            otp_mode=2, n_chars=8, algorithm=2,
            location_mode=301, iso3_code="IND", now=1000,
        )

    def test_unsupported_version_raises(self):
        with pytest.raises(ValueError):
            get_OTP_from_dict({"main_key": "key"}, use_version="v9.9")


# ======================== URI version support ========================

class TestUriVersion:
    def test_default_uri_records_current(self):
        uri = get_OTP_uri(main_key="key")
        assert "version=v1.0" in uri
        assert get_dict_from_uri(uri)["version"] == "v1.0"

    def test_uri_with_explicit_version(self):
        uri = get_OTP_uri(main_key="key", version="v0.2")
        assert "version=v0.2" in uri
        assert get_dict_from_uri(uri)["version"] == "v0.2"

    def test_uri_version_normalized(self):
        uri = get_OTP_uri(main_key="key", version="0.2.0")
        assert "version=v0.2" in uri

    def test_uri_from_dict_honors_version_key(self):
        uri = get_OTP_uri_from_dict({"main_key": "key", "version": "v0.2"})
        assert "version=v0.2" in uri

    def test_uri_from_dict_explicit_overrides(self):
        uri = get_OTP_uri_from_dict({"main_key": "key", "version": "v0.1"}, version="v0.2")
        assert "version=v0.2" in uri

    def test_uri_missing_version_defaults_current(self):
        config = get_dict_from_uri("TLSOTP://main_key=key&algorithm=sha1")
        assert config["version"] == "v1.0"

    def test_uri_invalid_version_raises(self):
        with pytest.raises(ValueError, match="[Vv]ersion"):
            get_OTP_uri(main_key="key", version="bogus")

    def test_uri_invalid_version_in_uri_raises(self):
        with pytest.raises(ValueError, match="[Vv]ersion"):
            get_dict_from_uri("TLSOTP://main_key=key&version=zzz")

    def test_legacy_uri_otp_matches_legacy(self, monkeypatch):
        monkeypatch.setattr(time, "time", lambda: 1000)
        uri = get_OTP_uri(main_key="key", version="v0.2")
        assert get_otp_from_uri(uri) == "112982"

    def test_legacy_uri_dict_roundtrip_matches_legacy(self, monkeypatch):
        monkeypatch.setattr(time, "time", lambda: 1000)
        uri = get_OTP_uri(main_key="key", version="v0.2")
        config = get_dict_from_uri(uri)
        assert config["version"] == "v0.2"
        assert get_OTP_from_dict(config) == "112982"

    def test_legacy_uri_full_roundtrip(self, monkeypatch):
        monkeypatch.setattr(time, "time", lambda: 1000)
        uri = get_OTP_uri(
            main_key="key", version="v0.2",
            otp_mode=2, n_chars=8, algorithm=2, location_mode=301,
        )
        otp_uri = get_otp_from_uri(uri, iso3_code="IND")
        otp_direct = get_OTP(
            "key", use_version="v0.2", otp_mode=2, n_chars=8,
            algorithm=2, location_mode=301, iso3_code="IND", now=1000,
        )
        assert otp_uri == otp_direct == "nslsKGU3"

    def test_current_uri_unchanged_behavior(self, monkeypatch):
        monkeypatch.setattr(time, "time", lambda: 1000)
        uri = get_OTP_uri(main_key="key")
        assert get_otp_from_uri(uri) == get_OTP("key")


# ======================== verify with legacy versions ========================

class TestVerifyLegacy:
    def test_verify_legacy_otp_true(self):
        otp = get_OTP("key", use_version="v0.2", now=1000)
        assert verify_otp("key", otp, drift_windows=0, use_version="v0.2", now=1000) is True

    def test_verify_legacy_otp_false(self):
        assert verify_otp("key", "000000", drift_windows=0, use_version="v0.2", now=1000) is False

    def test_verify_legacy_drift(self):
        now = 1000
        binning = 30
        future_otp = get_OTP("key", use_version="v0.2", now=now + binning)
        assert verify_otp(
            "key", future_otp, drift_windows=1, use_version="v0.2", now=now
        ) is True

    def test_verify_legacy_from_dict(self):
        otp = get_OTP_from_dict({"main_key": "key"}, use_version="v0.2")
        assert verify_otp_from_dict(
            {"main_key": "key"}, otp, drift_windows=0, use_version="v0.2"
        ) is True

    def test_verify_legacy_from_dict_version_key(self):
        otp = get_OTP_from_dict({"main_key": "key"}, use_version="v0.2")
        assert verify_otp_from_dict(
            {"main_key": "key", "version": "v0.2"}, otp, drift_windows=0
        ) is True

    def test_verify_legacy_from_uri(self):
        uri = get_OTP_uri(main_key="key", version="v0.2")
        otp = get_otp_from_uri(uri)
        assert verify_otp_from_uri(otp, uri, drift_windows=0) is True

    def test_verify_current_rejects_legacy_otp(self, monkeypatch):
        monkeypatch.setattr(time, "time", lambda: 1000)
        legacy_otp = get_OTP("key", use_version="v0.2", now=1000)
        assert verify_otp("key", legacy_otp, drift_windows=0) is False

    def test_verify_wrong_length_returns_false(self):
        assert verify_otp(
            "key", "12345", drift_windows=0, use_version="v0.2", now=1000
        ) is False
