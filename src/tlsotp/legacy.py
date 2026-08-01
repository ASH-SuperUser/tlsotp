from __future__ import annotations

import hashlib
import hmac
import secrets
import time

#: Current 2-level version string used when no explicit version is requested.
CURRENT_VERSION = "v1.0"


def normalize_version(version: str) -> str:
    """Normalize any version string to the 2-level form ``v<major>.<minor>``.

    Accepts ``"0.2"``, ``"v0.2"``, ``"v0.2.0"``, ``"v0.2.x"``, ``"v1"``,
    ``"v1.x"``, etc. The minor component is kept verbatim so future minor
    versions like ``"v1.3"`` normalize cleanly.

    Args:
        version (str): Version string to normalize.

    Returns:
        str: 2-level version, e.g. ``"v0.2"``.

    Raises:
        ValueError: If `version` is empty or has no usable numeric major
            component.
    """
    if not version:
        raise ValueError("version must be a non-empty string")

    v = str(version).strip().lower()
    if v.startswith('v'):
        v = v[1:]

    parts = v.split('.')
    major = parts[0].strip()
    if not major or not major.isdigit():
        raise ValueError(f"version has no numeric major component: {version!r}")

    minor = parts[1].strip() if len(parts) > 1 else '0'
    return f"v{major}.{minor}"


def is_current_version(version: str) -> bool:
    """Return ``True`` if `version` belongs to the current major release line.

    The current line is the major of `CURRENT_VERSION` (``v1``). Any ``v1.x``
    request therefore maps to the live algorithm, not the legacy module.

    Args:
        version (str): Version string to check.

    Returns:
        bool: Whether the version is on the current major line.
    """
    return normalize_version(version).split('.')[0] == CURRENT_VERSION.split('.')[0]


class LegacyVersion_0_2:
    """OTP generation for the ``v0.2.x`` release (and ``v0.1.x``).

    Reproduces the exact v0.2.0 algorithm, byte for byte:
    - ``OTP_gen`` maps each hash byte with ``(v * size) // 256`` and reuses
      the byte list cyclically via ``i % t_len``.
    - ``location_str`` 4xx/5xx modes embed the ISO3 code and *require*
      ``iso3_code``.
    - Positive location modes are **not** capped at 6 decimal places.
    - No ``now`` parameter existed upstream; it is accepted here only to
      keep verification deterministic (defaults to ``time.time()``).

    Future legacy lines (``v0.3``, ``v1.1``…) should add sibling classes and
    register them in ``_LEGACY_CLASSES``.
    """

    version = "v0.2"

    @staticmethod
    def OTP_gen(input_bytes: bytes, otp_mode: int = 0, n_chars: int = 6) -> str:
        """v0.2 ``OTP_gen``: per-byte mapping with cyclic reuse.

        Args:
            input_bytes (bytes): Raw hash bytes.
            otp_mode (int): ``0`` digits, ``1`` alpha, ``2`` alphanumeric.
            n_chars (int): Output length.

        Returns:
            str: Generated OTP.

        Raises:
            ValueError: If `input_bytes` is empty or `otp_mode` is invalid.
        """
        t_list = list(input_bytes)
        t_len = len(t_list)

        if not t_list:
            raise ValueError("input_bytes must be non-empty")

        if otp_mode == 0:
            t_list = [(v * 10) // 256 for v in t_list]
            return ''.join(str(t_list[i % t_len]) for i in range(n_chars))

        elif otp_mode == 1:
            alphabet = "ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz"
            t_list = [(v * 52) // 256 for v in t_list]
            return ''.join(alphabet[t_list[i % t_len]] for i in range(n_chars))

        elif otp_mode == 2:
            alphabet = "0123456789ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz"
            t_list = [(v * 62) // 256 for v in t_list]
            return ''.join(alphabet[t_list[i % t_len]] for i in range(n_chars))

        else:
            raise ValueError("otp_mode must be 0, 1, or 2")

    @staticmethod
    def time_str(time_binning: int = 30, now: float | None = None) -> str:
        """v0.2 ``time_str``: binned timestamp string.

        Args:
            time_binning (int): Time window in seconds.
            now (float | None): Explicit timestamp (defaults to
                ``time.time()``).

        Returns:
            str: Binned timestamp string.

        Raises:
            ValueError: If `time_binning` is not a positive integer.
        """
        if not isinstance(time_binning, int) or time_binning < 1:
            raise ValueError("time_binning must be a positive integer")

        current_time = int(now) if now is not None else int(time.time())
        return f'-{(current_time // time_binning) * time_binning}-'

    @staticmethod
    def location_str(
        location_mode: int = 0,
        latitude: float | None = None,
        longitude: float | None = None,
        iso3_code: str | None = None
    ) -> str:
        """v0.2 ``location_str``: encodes location, ISO3 embedded in 4xx/5xx.

        Args:
            location_mode (int): Controls encoding strategy.
            latitude (float | None): Latitude.
            longitude (float | None): Longitude.
            iso3_code (str | None): ISO3 country code.

        Returns:
            str: Encoded location string.
        """
        if location_mode == 0:
            return ''

        if location_mode == 301 and iso3_code:
            return iso3_code[:3]

        if (location_mode // 100) == 4 and iso3_code and latitude is not None and longitude is not None:
            precision = location_mode % 400
            lat = round(latitude, precision)
            lon = round(longitude, precision)
            return f"{iso3_code[:3]}-{lat:.{precision}f}-{lon:.{precision}f}"

        if (location_mode // 100) == 5 and iso3_code and latitude is not None and longitude is not None:
            step = location_mode % 500
            lat = int((latitude // step) * step)
            lon = int((longitude // step) * step)
            return f"{iso3_code[:3]}-{lat}-{lon}"

        if location_mode < 0 and latitude is not None and longitude is not None:
            step = abs(location_mode)
            lat = int((latitude // step) * step)
            lon = int((longitude // step) * step)
            return f"{lat}-{lon}"

        if location_mode > 0 and latitude is not None and longitude is not None:
            lat = round(latitude, location_mode)
            lon = round(longitude, location_mode)
            return f"{lat:.{location_mode}f}-{lon:.{location_mode}f}"

        return ''

    @staticmethod
    def password_str(password_str_mode: int = 0, pwd_string: str | None = None) -> str:
        """v0.2 ``password_str``: encode password into OTP input string.

        Args:
            password_str_mode (int): ``<0`` full, ``>0`` truncated, ``0`` off.
            pwd_string (str | None): Password.

        Returns:
            str: Encoded password segment.
        """
        if not pwd_string:
            return ''

        if password_str_mode < 0:
            return f'-{pwd_string}-'

        if password_str_mode > 0:
            return f'-{pwd_string[:password_str_mode]}-'

        return ''

    @classmethod
    def get_time_OTP(
        cls,
        main_key: str,
        otp_mode: int = 0,
        n_chars: int = 6,
        time_binning: int = 30,
        algorithm: int | str = 0,
        now: float | None = None
    ) -> str:
        """v0.2 time-only HMAC OTP.

        Args:
            main_key (str): Secret key.
            otp_mode (int): Output format mode.
            n_chars (int): OTP length.
            time_binning (int): Time step window.
            algorithm (int | str): Hash algorithm.
            now (float | None): Explicit timestamp (extension for
                deterministic verification).

        Returns:
            str: Generated OTP.

        Raises:
            ValueError: If `main_key` is empty or `algorithm` is unknown.
        """
        if not isinstance(main_key, str) or not main_key:
            raise ValueError("main_key must be a non-empty string")

        key_bytes = main_key.encode('utf-8')
        msg = cls.time_str(time_binning, now=now).encode('utf-8')

        def compute(digest):
            return cls.OTP_gen(hmac.new(key_bytes, msg, digest).digest(), otp_mode, n_chars)

        if algorithm in (0, 'sha1'):
            return compute(hashlib.sha1)
        if algorithm in (1, 'sha224'):
            return compute(hashlib.sha224)
        if algorithm in (2, 'sha256'):
            return compute(hashlib.sha256)
        if algorithm in (3, 'sha384'):
            return compute(hashlib.sha384)
        if algorithm in (4, 'sha512'):
            return compute(hashlib.sha512)
        if algorithm in (5, 'sha3-512'):
            return compute(hashlib.sha3_512)

        raise ValueError("Invalid algorithm")

    @classmethod
    def get_OTP(
        cls,
        main_key: str,
        otp_mode: int = 0,
        n_chars: int = 6,
        time_binning: int = 30,
        location_mode: int = 0,
        latitude: float | None = None,
        longitude: float | None = None,
        iso3_code: str | None = None,
        password_str_mode: int = 0,
        password_string: str | None = None,
        algorithm: int | str = 0,
        now: float | None = None
    ) -> str:
        """v0.2 full-featured HMAC OTP.

        Args:
            main_key (str): Secret key.
            otp_mode (int): Output format mode.
            n_chars (int): OTP length.
            time_binning (int): Time window.
            location_mode (int): Location encoding mode.
            latitude (float | None): Latitude.
            longitude (float | None): Longitude.
            iso3_code (str | None): Country code.
            password_str_mode (int): Password encoding mode.
            password_string (str | None): Password.
            algorithm (int | str): Hash algorithm.
            now (float | None): Explicit timestamp (extension for
                deterministic verification).

        Returns:
            str: Generated OTP.

        Raises:
            ValueError: If `main_key` is empty or `algorithm` is unknown.
        """
        if not isinstance(main_key, str) or not main_key:
            raise ValueError("main_key must be a non-empty string")

        key_bytes = main_key.encode('utf-8')

        msg = (
            cls.time_str(time_binning, now=now) +
            cls.location_str(location_mode, latitude, longitude, iso3_code) +
            cls.password_str(password_str_mode, password_string)
        ).encode('utf-8')

        def compute(digest):
            return cls.OTP_gen(hmac.new(key_bytes, msg, digest).digest(), otp_mode, n_chars)

        if algorithm in (0, 'sha1'):
            return compute(hashlib.sha1)
        if algorithm in (1, 'sha224'):
            return compute(hashlib.sha224)
        if algorithm in (2, 'sha256'):
            return compute(hashlib.sha256)
        if algorithm in (3, 'sha384'):
            return compute(hashlib.sha384)
        if algorithm in (4, 'sha512'):
            return compute(hashlib.sha512)
        if algorithm in (5, 'sha3-512'):
            return compute(hashlib.sha3_512)

        raise ValueError("Invalid algorithm")

    @staticmethod
    def key_gen(length: int = 32) -> str:
        """v0.2 ``key_gen``: cryptographically secure URL-safe token.

        Args:
            length (int): Number of random bytes.

        Returns:
            str: URL-safe random secret key.
        """
        return secrets.token_urlsafe(length)


class LegacyVersion_0_1(LegacyVersion_0_2):
    """OTP generation for the ``v0.1.x`` release.

    v0.1.0 and v0.2.0 ship an identical ``core.py``, so the algorithm is the
    same. The class exists as an explicit dispatch target so future releases
    that differ from v0.1.x can override behaviour here.
    """

    version = "v0.1"


#: Registry of supported legacy lines -> per-version classes.
_LEGACY_CLASSES = {
    'v0.1': LegacyVersion_0_1,
    'v0.2': LegacyVersion_0_2,
}


def get_otp_legacy(
    main_key: str,
    version: str = "v0.2",
    otp_mode: int = 0,
    n_chars: int = 6,
    time_binning: int = 30,
    location_mode: int = 0,
    latitude: float | None = None,
    longitude: float | None = None,
    iso3_code: str | None = None,
    password_str_mode: int = 0,
    password_string: str | None = None,
    algorithm: int | str = 0,
    now: float | None = None
) -> str:
    """Master legacy dispatch: generate an OTP using an older version's algorithm.

    Selects the per-version implementation class from `_LEGACY_CLASSES` and
    delegates to its ``get_OTP``. Supports the ``v0.1`` and ``v0.2`` lines;
    newer legacy lines can be added by subclassing and registering.

    Args:
        main_key (str): Secret key.
        version (str): Version to emulate, e.g. ``"v0.2"``, ``"0.2"``,
            ``"v0.2.0"``.
        otp_mode (int): Output format mode.
        n_chars (int): OTP length.
        time_binning (int): Time window.
        location_mode (int): Location encoding mode.
        latitude (float | None): Latitude.
        longitude (float | None): Longitude.
        iso3_code (str | None): Country code.
        password_str_mode (int): Password encoding mode.
        password_string (str | None): Password.
        algorithm (int | str): Hash algorithm.
        now (float | None): Explicit timestamp (extension for deterministic
            verification).

    Returns:
        str: Generated OTP.

    Raises:
        ValueError: If `version` is unsupported, `main_key` is empty, or
            `algorithm` is unknown.
    """
    cls = _resolve_legacy_class(version)
    return cls.get_OTP(
        main_key=main_key,
        otp_mode=otp_mode,
        n_chars=n_chars,
        time_binning=time_binning,
        location_mode=location_mode,
        latitude=latitude,
        longitude=longitude,
        iso3_code=iso3_code,
        password_str_mode=password_str_mode,
        password_string=password_string,
        algorithm=algorithm,
        now=now,
    )


def _resolve_legacy_class(version: str):
    """Look up the implementation class for a legacy `version`.

    Args:
        version (str): Version string to resolve.

    Returns:
        type: The per-version legacy class.

    Raises:
        ValueError: If the version is not a supported legacy line.
    """
    key = normalize_version(version)
    cls = _LEGACY_CLASSES.get(key)
    if cls is None:
        supported = ", ".join(sorted(_LEGACY_CLASSES))
        raise ValueError(
            f"Unsupported legacy version: {version!r} (normalized {key!r}). "
            f"Supported legacy lines: {supported}"
        )
    return cls


def supported_legacy_versions() -> tuple:
    """Return the supported legacy version lines, e.g. ``('v0.1', 'v0.2')``.

    Returns:
        tuple: Sorted supported legacy version strings.
    """
    return tuple(sorted(_LEGACY_CLASSES))
