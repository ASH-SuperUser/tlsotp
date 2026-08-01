from __future__ import annotations

import hashlib
import hmac
import time


def OTP_gen(input_bytes: bytes, otp_mode: int = 0, n_chars: int = 6) -> str:
    """Generate an OTP string from raw bytes.

    Consumes input bytes sequentially in 4-byte chunks as big-endian
    integers modulo the output alphabet size.  When fewer than 4 bytes
    remain, fresh bytes are derived by hashing the current data with
    SHA-256, chaining on each subsequent exhaustion.  This avoids cyclic
    reuse of the input, but note that the modulo reduction does not
    eliminate output bias.

    Args:
        input_bytes (bytes): Raw hash bytes.
        otp_mode (int): OTP format mode:
            - 0: digits only
            - 1: alphabets only (A-Z, a-z)
            - 2: alphanumeric
        n_chars (int): Length of OTP.

    Returns:
        str: Generated OTP.

    Raises:
        ValueError: If `input_bytes` is empty or `otp_mode` is not
            0, 1, or 2.
    """
    if not input_bytes:
        raise ValueError("input_bytes must be non-empty")

    MODE_CONFIG = {
        0: (10, "0123456789"),
        1: (52, "ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz"),
        2: (62, "0123456789ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz"),
    }

    if otp_mode not in MODE_CONFIG:
        raise ValueError("otp_mode must be 0, 1, or 2")

    range_size, alphabet = MODE_CONFIG[otp_mode]
    result: list[str] = []
    data = input_bytes
    offset = 0

    while len(result) < n_chars:
        if offset + 4 > len(data):
            data = hashlib.sha256(data).digest()
            offset = 0

        chunk = data[offset:offset + 4]
        value = int.from_bytes(chunk, 'big') % range_size
        result.append(alphabet[value])
        offset += 4

    return ''.join(result)


def time_str(time_binning: int = 30, now: float | None = None) -> str:
    """Generate a time-binned timestamp string.

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


def location_str(
    location_mode: int = 0,
    latitude: float | None = None,
    longitude: float | None = None,
    iso3_code: str | None = None
) -> str:
    """Encode location into a deterministic string.

    The encoding depends on `location_mode`:
        - 0: disabled, returns ``''``.
        - 301: first 3 chars of `iso3_code`.
        - 4xx (400-499): `latitude`/`longitude` rounded to
          ``min(location_mode % 400, 6)`` decimal places.
        - 5xx (500-599): `latitude`/`longitude` snapped to a grid of
          step ``location_mode % 500`` (step 0 returns ``''``).
        - 6xx (600-699): ``ISO3-lat-lon`` with `latitude`/`longitude`
          rounded to ``min(location_mode % 600, 6)`` decimal places.
        - 7xx (700-799): ``ISO3-lat-lon`` with `latitude`/`longitude`
          snapped to a grid of step ``location_mode % 700`` (step 0
          returns ``''``).
        - negative: `latitude`/`longitude` snapped to a grid of step
          ``abs(location_mode)``.
        - positive (any other): `latitude`/`longitude` rounded to
          ``min(location_mode, 6)`` decimal places.

    Modes requiring coordinates or an ISO3 code return ``''`` when the
    required values are not provided.

    Args:
        location_mode (int): Controls encoding strategy.
        latitude (float | None): Latitude.
        longitude (float | None): Longitude.
        iso3_code (str | None): ISO3 country code.

    Returns:
        str: Encoded location string.

    Raises:
        ValueError: If `iso3_code` is shorter than 3 characters for
            location modes 301, 6xx, or 7xx.
    """
    if location_mode == 0:
        return ''

    if location_mode == 301:
        if not iso3_code:
            return ''
        if len(iso3_code) < 3:
            raise ValueError("iso3_code must be at least 3 characters for location_mode 301")
        return iso3_code[:3]

    if (location_mode // 100) == 4 and latitude is not None and longitude is not None:
        precision = min(location_mode % 400, 6)
        lat = round(latitude, precision)
        lon = round(longitude, precision)
        return f"{lat:.{precision}f}-{lon:.{precision}f}"

    if (location_mode // 100) == 5 and latitude is not None and longitude is not None:
        step = location_mode % 500
        if step == 0:
            return ''
        lat = int((latitude // step) * step)
        lon = int((longitude // step) * step)
        return f"{lat}-{lon}"

    if (location_mode // 100) == 6:
        if not iso3_code:
            return ''
        if len(iso3_code) < 3:
            raise ValueError("iso3_code must be at least 3 characters")
        if latitude is not None and longitude is not None:
            precision = min(location_mode % 600, 6)
            lat = round(latitude, precision)
            lon = round(longitude, precision)
            return f"{iso3_code[:3]}-{lat:.{precision}f}-{lon:.{precision}f}"

    if (location_mode // 100) == 7:
        if not iso3_code:
            return ''
        if len(iso3_code) < 3:
            raise ValueError("iso3_code must be at least 3 characters")
        if latitude is not None and longitude is not None:
            step = location_mode % 700
            if step == 0:
                return ''
            lat = int((latitude // step) * step)
            lon = int((longitude // step) * step)
            return f"{iso3_code[:3]}-{lat}-{lon}"

    if location_mode < 0 and latitude is not None and longitude is not None:
        step = abs(location_mode)
        lat = int((latitude // step) * step)
        lon = int((longitude // step) * step)
        return f"{lat}-{lon}"

    if location_mode > 0 and latitude is not None and longitude is not None:
        precision = min(location_mode, 6)
        lat = round(latitude, precision)
        lon = round(longitude, precision)
        return f"{lat:.{precision}f}-{lon:.{precision}f}"

    return ''


def password_str(password_str_mode: int = 0, pwd_string: str | None = None) -> str:
    """Encode password into OTP input string.

    Args:
        password_str_mode (int):
            - <0: full password
            - >0: truncated password
            - 0: disabled
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


def get_time_OTP(
    main_key: str,
    otp_mode: int = 0,
    n_chars: int = 6,
    time_binning: int = 30,
    algorithm: int | str = 0,
    now: float | None = None
) -> str:
    """Generate a time-based HMAC OTP.

    The HMAC message is the binned time string from `time_str`; the
    HMAC output is reduced to an OTP via `OTP_gen`.

    Args:
        main_key (str): Secret key.
        otp_mode (int): OTP format mode (see `OTP_gen`).
        n_chars (int): OTP length.
        time_binning (int): Time step window in seconds.
        algorithm (int | str): Hash algorithm:
            0/``'sha1'``, 1/``'sha224'``, 2/``'sha256'``,
            3/``'sha384'``, 4/``'sha512'``, 5/``'sha3-512'``.
        now (float | None): Explicit timestamp (defaults to
            ``time.time()``).

    Returns:
        str: Generated OTP.

    Raises:
        ValueError: If `main_key` is empty or `algorithm` is unknown.
    """
    if not isinstance(main_key, str) or not main_key:
        raise ValueError("main_key must be a non-empty string")

    key_bytes = main_key.encode('utf-8')
    msg = time_str(time_binning, now=now).encode('utf-8')

    def compute(digest):
        return OTP_gen(hmac.new(key_bytes, msg, digest).digest(), otp_mode, n_chars)

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


def get_OTP(
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
    """Generate a full-featured HMAC-based OTP.

    The HMAC message is the concatenation of:
    - Time (from `time_str`)
    - Location (from `location_str`)
    - Password (from `password_str`, optional)

    Args:
        main_key (str): Secret key.
        otp_mode (int): OTP format mode (see `OTP_gen`).
        n_chars (int): OTP length.
        time_binning (int): Time window in seconds.
        location_mode (int): Location encoding mode (see
            `location_str`).
        latitude (float | None): Latitude.
        longitude (float | None): Longitude.
        iso3_code (str | None): Country code.
        password_str_mode (int): Password encoding mode (see
            `password_str`).
        password_string (str | None): Password.
        algorithm (int | str): Hash algorithm:
            0/``'sha1'``, 1/``'sha224'``, 2/``'sha256'``,
            3/``'sha384'``, 4/``'sha512'``, 5/``'sha3-512'``.
        now (float | None): Explicit timestamp (defaults to
            ``time.time()``).

    Returns:
        str: Generated OTP.

    Raises:
        ValueError: If `main_key` is empty or `algorithm` is unknown.
    """
    if not isinstance(main_key, str) or not main_key:
        raise ValueError("main_key must be a non-empty string")

    key_bytes = main_key.encode('utf-8')

    msg = (
        time_str(time_binning, now=now) +
        location_str(location_mode, latitude, longitude, iso3_code) +
        password_str(password_str_mode, password_string)
    ).encode('utf-8')

    def compute(digest):
        return OTP_gen(hmac.new(key_bytes, msg, digest).digest(), otp_mode, n_chars)

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


