import hashlib
import hmac
import time


def OTP_gen(input_bytes: bytes, otp_mode: int = 0, n_chars: int = 6) -> str:
    """Generate an OTP string from raw bytes.

    Maps hash bytes into a deterministic OTP string depending on mode.

    Args:
        input_bytes (bytes): Raw hash bytes.
        otp_mode (int): OTP format mode:
            - 0: digits only
            - 1: alphabets only (A-Z, a-z)
            - 2: alphanumeric
        n_chars (int): Length of OTP.

    Returns:
        str: Generated OTP.
    """
    t_list = list(input_bytes)
    t_len = len(t_list)

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


def time_str(time_binning: int = 30) -> str:
    """Generate a time-binned timestamp string.

    Args:
        time_binning (int): Time window in seconds.

    Returns:
        str: Binned timestamp string.
    """
    current_time = int(time.time())
    return f'-{(current_time // time_binning) * time_binning}-'


def location_str(
    location_mode: int = 0,
    latitude: float | None = None,
    longitude: float | None = None,
    iso3_code: str | None = None
) -> str:
    """Encode location into a deterministic string.

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
    algorithm: int | str = 0
) -> str:
    """Generate a time-based HMAC OTP.

    Args:
        main_key (str): Secret key.
        otp_mode (int): OTP format mode.
        n_chars (int): OTP length.
        time_binning (int): Time step window.
        algorithm (int | str): Hash algorithm.

    Returns:
        str: Generated OTP.
    """
    if not isinstance(main_key, str) or not main_key:
        raise ValueError("main_key must be a non-empty string")

    key_bytes = main_key.encode('utf-8')
    msg = time_str(time_binning).encode('utf-8')

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
    algorithm: int | str = 0
) -> str:
    """Generate a full-featured HMAC-based OTP.

    Combines:
    - Time
    - Location
    - Password (optional)

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

    Returns:
        str: Generated OTP.
    """
    if not isinstance(main_key, str) or not main_key:
        raise ValueError("main_key must be a non-empty string")

    key_bytes = main_key.encode('utf-8')

    msg = (
        time_str(time_binning) +
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


