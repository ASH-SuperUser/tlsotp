from __future__ import annotations

import hmac
import secrets
import time
import urllib.parse
from typing import Any

from . import legacy as _legacy
from .core import get_OTP as _core_get_OTP

__all__ = [
    'get_OTP',
    'get_OTP_from_dict',
    'get_OTP_uri',
    'get_OTP_uri_from_dict',
    'get_data_dict',
    'get_dict_from_uri',
    'get_otp_from_uri',
    'key_gen',
    'verify_otp',
    'verify_otp_from_dict',
    'verify_otp_from_uri',
]


def key_gen(length=32) -> str:
    """Generate a random secret key string.

    Uses Python's `secrets` module to generate a cryptographically
    secure URL-safe token from ``length`` random bytes.

    Args:
        length (int): Number of random bytes to use; the returned
            string is approximately 4/3 this length.

    Returns:
        str: URL-safe random secret key.
    """
    return secrets.token_urlsafe(length)


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
    now: float | None = None,
    use_version: str | None = None,
) -> str:
    """Generate a full-featured HMAC-based OTP.

    The HMAC message is the concatenation of:
    - Time (from `time_str`)
    - Location (from `location_str`)
    - Password (from `password_str`, optional)

    `use_version` selects the algorithm version.  ``None`` (default) or
    any current-line version (``v1.x``) uses the live algorithm; legacy
    versions such as ``"v0.2"`` or ``"v0.2.0"`` are dispatched to the
    corresponding `legacy` implementation.

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
        use_version (str | None): Algorithm version; ``None`` uses the
            current line, ``"v0.1"``/``"v0.2"`` use legacy emulation.

    Returns:
        str: Generated OTP.

    Raises:
        ValueError: If `main_key` is empty, `algorithm` is unknown, or
            `use_version` is an unsupported legacy version.
    """
    if use_version is None or _legacy.is_current_version(use_version):
        return _core_get_OTP(
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

    return _legacy.get_otp_legacy(
        main_key=main_key,
        version=use_version,
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


def get_data_dict(
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
    ) -> dict:
    """Validate OTP configuration parameters and build a data dictionary.

    Performs validation for:
    - OTP mode
    - OTP length
    - Time binning
    - Location configuration
    - Password configuration
    - Hash algorithm

    Returns a normalized dictionary compatible with `get_OTP`
    and related helper functions.

    Args:
        main_key (str): Secret key used for OTP generation.
        otp_mode (int): OTP format mode:
            - 0: digits only
            - 1: alphabets only
            - 2: alphanumeric
        n_chars (int): Length of OTP.
        time_binning (int): Time window in seconds.
        location_mode (int): Location encoding mode.
        latitude (float | None): Latitude coordinate.
        longitude (float | None): Longitude coordinate.
        iso3_code (str | None): ISO3 country code.
        password_str_mode (int): Password encoding mode.
        password_string (str | None): Optional password string.
        algorithm (int | str): Hash algorithm identifier.

    Returns:
        dict: Validated OTP configuration dictionary.

    Raises:
        ValueError: If any argument is invalid.
    """
    # ----------- BASIC VALIDATIONS -----------

    if not isinstance(main_key, str) or not main_key:
        raise ValueError("main_key must be a non-empty string")

    if otp_mode not in (0, 1, 2):
        raise ValueError("otp_mode must be 0, 1, or 2")

    if not isinstance(n_chars, int) or n_chars <= 0 or n_chars > 128:
        raise ValueError("n_chars must be between 1 and 128")

    if not isinstance(time_binning, int) or time_binning <= 0:
        raise ValueError("time_binning must be a positive integer")

    # ----------- LOCATION VALIDATION -----------

    if location_mode != 0:
        # modes that require ISO3
        if location_mode == 301:
            if not iso3_code or len(iso3_code) < 3:
                raise ValueError("iso3_code (>=3 chars) required for location_mode 301")

        elif (location_mode // 100) in (4, 5):
            if latitude is None or longitude is None:
                raise ValueError("latitude and longitude required for location_mode 4xx/5xx")

        elif (location_mode // 100) in (6, 7):
            if iso3_code is None or len(iso3_code) < 3 or latitude is None or longitude is None:
                raise ValueError("iso3_code (>=3 chars), latitude, longitude required for location_mode 6xx/7xx")

        elif location_mode != 0 and (latitude is None or longitude is None):
            raise ValueError("latitude and longitude required for this location_mode")

    # validate lat/lon ranges if provided
    if latitude is not None and not (-90 <= latitude <= 90):
        raise ValueError("latitude must be between -90 and 90")

    if longitude is not None and not (-180 <= longitude <= 180):
        raise ValueError("longitude must be between -180 and 180")

    # ----------- PASSWORD VALIDATION -----------

    if password_str_mode != 0:
        if not isinstance(password_str_mode, int):
            raise ValueError("password_str_mode must be an integer")

        if not password_string:
            raise ValueError("password_string required when password_str_mode != 0")

    # ----------- ALGORITHM VALIDATION -----------

    valid_algorithms = {0, 1, 2, 3, 4, 5, 'sha1', 'sha224', 'sha256', 'sha384', 'sha512', 'sha3-512'}
    if algorithm not in valid_algorithms:
        raise ValueError("Invalid algorithm")

    # ----------- RETURN DICT -----------

    return {
        'main_key': main_key,
        'otp_mode': otp_mode,
        'n_chars': n_chars,
        'time_binning': time_binning,
        'location_mode': location_mode,
        'latitude': latitude,
        'longitude': longitude,
        'iso3_code': iso3_code,
        'password_str_mode': password_str_mode,
        'password_string': password_string,
        'algorithm': algorithm
    }


def get_OTP_from_dict(data_dict: dict, use_version: str | None = None) -> str:
    """Generate an OTP from a configuration dictionary.

    Accepts a dictionary compatible with `get_data_dict`,
    applies default values for missing keys, and forwards
    the configuration to `get_OTP`.

    Unknown keys are ignored.

    Args:
        data_dict (dict): OTP configuration dictionary.
        use_version (str | None): Algorithm version to use.  ``None``
            (default) falls back to a ``version`` key in `data_dict`,
            then to the current line; legacy versions such as
            ``"v0.2"`` are dispatched to the legacy implementation.

    Returns:
        str: Generated OTP.

    Raises:
        TypeError: If `data_dict` is not a dictionary.
        ValueError: If `main_key` is missing or any configuration
            value is invalid.
    """
    if not isinstance(data_dict, dict):
        raise TypeError("data_dict must be a dictionary")

    if use_version is None:
        use_version = data_dict.get('version')

    # allowed keys (to prevent garbage input)
    allowed_keys = {
        'main_key',
        'otp_mode',
        'n_chars',
        'time_binning',
        'location_mode',
        'latitude',
        'longitude',
        'iso3_code',
        'password_str_mode',
        'password_string',
        'algorithm'
    }

    # filter unknown keys (optional: you can raise instead)
    filtered = {k: v for k, v in data_dict.items() if k in allowed_keys}

    # defaults (match get_OTP signature)
    defaults = {
        'main_key': None,
        'otp_mode': 0,
        'n_chars': 6,
        'time_binning': 30,
        'location_mode': 0,
        'latitude': None,
        'longitude': None,
        'iso3_code': None,
        'password_str_mode': 0,
        'password_string': None,
        'algorithm': 0
    }

    # merge: dict overrides defaults
    final_args = {**defaults, **filtered}

    # main_key is mandatory
    if not final_args['main_key']:
        raise ValueError("main_key is required")

    # validate (mode-required arguments must be present) and
    # normalize before generating
    validated = get_data_dict(**final_args)
    return get_OTP(
        main_key=validated['main_key'],
        otp_mode=validated['otp_mode'],
        n_chars=validated['n_chars'],
        time_binning=validated['time_binning'],
        location_mode=validated['location_mode'],
        latitude=validated['latitude'],
        longitude=validated['longitude'],
        iso3_code=validated['iso3_code'],
        password_str_mode=validated['password_str_mode'],
        password_string=validated['password_string'],
        algorithm=validated['algorithm'],
        use_version=use_version,
    )


_ALGO_NAMES = {0: 'sha1', 1: 'sha224', 2: 'sha256', 3: 'sha384', 4: 'sha512', 5: 'sha3-512'}
_ALGO_FROM_NAME = {v: k for k, v in _ALGO_NAMES.items()}


def _algo_to_str(algorithm: int | str) -> str:
    if isinstance(algorithm, str):
        return algorithm
    return _ALGO_NAMES.get(algorithm, 'sha1')


def get_OTP_uri(
    main_key: str,
    otp_mode: int = 0,
    n_chars: int = 6,
    time_binning: int = 30,
    location_mode: int = 0,
    password_str_mode: int = 0,
    algorithm: int | str = 0,
    version: str | None = None,
) -> str:
    """Generate a TLSOTP:// URI encoding the OTP configuration.

    Runtime-only values (latitude, longitude, iso3_code, password_string)
    are **not** stored in the URI; they must be supplied when calling
    ``get_otp_from_uri`` or ``verify_otp_from_uri``.

    The URI records the algorithm `version` (default: the current line).
    Legacy URIs (e.g. ``version="v0.2"``) reproduce the older algorithm
    when the URI is later used with ``get_otp_from_uri`` or
    ``verify_otp_from_uri``.

    Args:
        main_key (str): Secret key.
        otp_mode (int): OTP format mode.
        n_chars (int): OTP length.
        time_binning (int): Time window in seconds.
        location_mode (int): Location encoding mode.
        password_str_mode (int): Password encoding mode.
        algorithm (int | str): Hash algorithm.
        version (str | None): Algorithm version to record in the URI;
            ``None`` uses the current line.

    Returns:
        str: ``TLSOTP://key=value&...`` URI string.

    Raises:
        TypeError: If `location_mode` or `password_str_mode` is not an
            int, or `algorithm` is neither an int nor a str.
        ValueError: If `main_key` is missing/empty, `otp_mode` is not
            0/1/2, `n_chars` is not in 1..128, `time_binning` is not a
            positive integer, `algorithm` is unknown, or `version` is
            malformed.
    """
    if not isinstance(main_key, str) or not main_key:
        raise ValueError("main_key is required and must be a non-empty string")
    if not isinstance(otp_mode, int) or otp_mode not in (0, 1, 2):
        raise ValueError(f"Invalid otp_mode: {otp_mode!r}")
    if not isinstance(n_chars, int) or not 1 <= n_chars <= 128:
        raise ValueError(f"n_chars must be between 1 and 128, got {n_chars!r}")
    if not isinstance(time_binning, int) or time_binning < 1:
        raise ValueError(f"time_binning must be a positive integer, got {time_binning!r}")
    if not isinstance(location_mode, int):
        raise TypeError(f"location_mode must be an int, got {type(location_mode).__name__}")
    if not isinstance(password_str_mode, int):
        raise TypeError(f"password_str_mode must be an int, got {type(password_str_mode).__name__}")

    algo_int: int
    if isinstance(algorithm, int):
        if algorithm not in _ALGO_NAMES:
            raise ValueError(f"Invalid algorithm: {algorithm!r}")
        algo_int = algorithm
    elif isinstance(algorithm, str):
        if algorithm not in _ALGO_FROM_NAME:
            raise ValueError(f"Unknown algorithm: {algorithm!r}")
        algo_int = _ALGO_FROM_NAME[algorithm]
    else:
        raise TypeError(f"algorithm must be int or str, got {type(algorithm).__name__}")

    if version is None:
        version_str = _legacy.CURRENT_VERSION
    else:
        try:
            version_str = _legacy.normalize_version(version)
        except ValueError as exc:
            raise ValueError(f"Invalid version: {version!r}") from exc

    params = urllib.parse.urlencode({
        'main_key': main_key,
        'otp_mode': str(otp_mode),
        'n_chars': str(n_chars),
        'time_binning': str(time_binning),
        'location_mode': str(location_mode),
        'password_str_mode': str(password_str_mode),
        'algorithm': _algo_to_str(algo_int),
        'version': version_str,
    }, doseq=True)

    return f"TLSOTP://{params}"


def get_OTP_uri_from_dict(data_dict: dict, version: str | None = None) -> str:
    """Generate a TLSOTP:// URI from a configuration dictionary.

    Only the URI-serializable keys (``main_key``, ``otp_mode``,
    ``n_chars``, ``time_binning``, ``location_mode``,
    ``password_str_mode``, ``algorithm``) are used; runtime-only values
    (``latitude``, ``longitude``, ``iso3_code``, ``password_string``)
    are ignored.  A ``version`` key in the dictionary is honored
    (overridden by the explicit `version` argument).

    Args:
        data_dict (dict): OTP configuration dictionary.
        version (str | None): Algorithm version to record in the URI;
            falls back to a ``version`` key in `data_dict`, then to the
            current line.

    Returns:
        str: URI string.

    Raises:
        AttributeError: If `data_dict` is not a dictionary.
        TypeError: If a parameter has the wrong type (see
            `get_OTP_uri`).
        ValueError: If `main_key` is missing or any parameter is
            invalid (see `get_OTP_uri`).
    """
    known_keys = {
        'main_key', 'otp_mode', 'n_chars', 'time_binning',
        'location_mode', 'password_str_mode', 'algorithm',
    }
    filtered = {k: v for k, v in data_dict.items() if k in known_keys}

    if version is None:
        version = data_dict.get('version')

    return get_OTP_uri(**filtered, version=version)


def get_dict_from_uri(uri: str) -> dict:
    """Parse a ``TLSOTP://`` URI back into a configuration dict.

    Runtime-only keys (``latitude``, ``longitude``, ``iso3_code``,
    ``password_string``) are set to ``None``.  The dict can be passed
    directly to ``get_OTP_uri_from_dict``.  For ``get_OTP_from_dict``
    and ``verify_otp_from_dict`` it works as-is only when the
    configuration does not require runtime values; otherwise those
    values must be supplied first (e.g. via ``get_otp_from_uri`` or
    ``verify_otp_from_uri``).

    Args:
        uri (str): A valid ``TLSOTP://`` URI.

    Returns:
        dict: OTP configuration dictionary.

    Raises:
        ValueError: If the URI does not start with ``TLSOTP://``, does
            not contain a ``main_key`` parameter, or contains an
            invalid integer parameter value.
    """
    if not uri.startswith('TLSOTP://'):
        raise ValueError("URI must start with 'TLSOTP://'")

    qs = urllib.parse.parse_qs(uri[len('TLSOTP://'):], keep_blank_values=True)

    def first(key, default=None):
        vals = qs.get(key)
        return vals[0] if vals else default

    def first_int(key, default=None):
        v = first(key)
        if v is None:
            return default
        try:
            return int(v)
        except (ValueError, TypeError):
            raise ValueError(f"Invalid integer value for '{key}': {v!r}")

    main_key = first('main_key')
    if not main_key:
        raise ValueError("URI must contain a 'main_key' parameter")

    raw_algo = first('algorithm', 'sha1')
    # try to interpret as known string algorithm first, then as int
    algo: int | str = raw_algo
    if raw_algo in _ALGO_FROM_NAME:
        algo = _ALGO_FROM_NAME[raw_algo]
    elif raw_algo.isdigit():
        algo = int(raw_algo)

    raw_version = first('version', _legacy.CURRENT_VERSION)
    try:
        version = _legacy.normalize_version(raw_version)
    except ValueError as exc:
        raise ValueError(f"Invalid version in URI: {raw_version!r}") from exc

    return {
        'main_key': main_key,
        'otp_mode': first_int('otp_mode', 0),
        'n_chars': first_int('n_chars', 6),
        'time_binning': first_int('time_binning', 30),
        'location_mode': first_int('location_mode', 0),
        'latitude': None,
        'longitude': None,
        'iso3_code': None,
        'password_str_mode': first_int('password_str_mode', 0),
        'password_string': None,
        'algorithm': algo,
        'version': version,
    }


def get_otp_from_uri(
    uri: str,
    *,
    latitude: float | None = None,
    longitude: float | None = None,
    iso3_code: str | None = None,
    password_string: str | None = None,
    override_dict: dict | None = None,
    adder_dict: dict | None = None,
) -> str:
    """Generate an OTP directly from a ``TLSOTP://`` URI.

    The algorithm version recorded in the URI (default: current line) is
    honored automatically; legacy URIs reproduce the older algorithm.

    Args:
        uri (str): TLSOTP URI string.
        latitude (float | None): Runtime latitude (not stored in URI).
        longitude (float | None): Runtime longitude (not stored in URI).
        iso3_code (str | None): Runtime ISO3 country code (not stored in URI).
        password_string (str | None): Runtime password (not stored in URI).
        override_dict (dict | None): Values to forcibly override.
        adder_dict (dict | None): Values to add only if missing.

    Returns:
        str: Generated OTP.

    Raises:
        ValueError: If the URI is malformed, or if the location/password
            mode requires a value that was not provided.
    """
    config = get_dict_from_uri(uri)

    if latitude is not None:
        config['latitude'] = latitude
    if longitude is not None:
        config['longitude'] = longitude
    if iso3_code is not None:
        config['iso3_code'] = iso3_code
    if password_string is not None:
        config['password_string'] = password_string

    if override_dict is not None:
        config.update(override_dict)

    if adder_dict is not None:
        for key, value in adder_dict.items():
            if key not in config or config[key] is None:
                config[key] = value

    return get_OTP_from_dict(config, use_version=config.get('version'))


def verify_otp(
    main_key: str,
    user_otp: str,
    drift_windows: int = 1,
    use_version: str | None = None,
    **kwargs: Any,
) -> bool:
    """Verify a user-provided OTP with time-window drift tolerance.

    Generates expected OTPs for the current time window as well as
    ``drift_windows`` windows into the past and future.  Returns
    ``True`` if any of them match ``user_otp``.

    Args:
        main_key (str): Secret key.
        user_otp (str): The OTP provided by the user.
        drift_windows (int): Number of additional time windows to
            check in each direction (default 1 → 3 total windows).
        use_version (str | None): Algorithm version to verify against;
            ``None`` uses the current line (see `get_OTP`).
        **kwargs: Remaining arguments forwarded to ``get_OTP``.

    Returns:
        bool: Whether the OTP is valid.
    """
    if not isinstance(user_otp, str) or not user_otp:
        return False

    time_binning = kwargs.get('time_binning', 30)
    n_chars = kwargs.get('n_chars', 6)

    if len(user_otp) != n_chars:
        return False

    now = kwargs.pop('now', None)
    if now is None:
        now = int(time.time())
    base_window = now // time_binning

    for drift in range(-drift_windows, drift_windows + 1):
        adjusted_time = (base_window + drift) * time_binning
        expected = get_OTP(
            main_key=main_key,
            now=adjusted_time,
            use_version=use_version,
            **kwargs,
        )
        if hmac.compare_digest(expected, user_otp):
            return True

    return False


def verify_otp_from_dict(
    data_dict: dict,
    user_otp: str,
    drift_windows: int = 1,
    use_version: str | None = None,
) -> bool:
    """Verify a user-provided OTP from a configuration dictionary.

    Args:
        data_dict (dict): OTP configuration dictionary.
        user_otp (str): The OTP provided by the user.
        drift_windows (int): Time-window drift tolerance.
        use_version (str | None): Algorithm version to verify against;
            falls back to a ``version`` key in `data_dict`, then to the
            current line (see `get_OTP`).

    Returns:
        bool: Whether the OTP is valid.

    Raises:
        TypeError: If `data_dict` is not a dictionary, or if a required
            configuration key (e.g. `main_key`) is missing.
        ValueError: If any configuration value is invalid.
    """
    if not isinstance(data_dict, dict):
        raise TypeError("data_dict must be a dictionary")

    known_keys = {
        'main_key', 'otp_mode', 'n_chars', 'time_binning',
        'location_mode', 'latitude', 'longitude', 'iso3_code',
        'password_str_mode', 'password_string', 'algorithm',
    }
    filtered = {k: v for k, v in data_dict.items() if k in known_keys}
    config = get_data_dict(**filtered)

    if use_version is None:
        use_version = data_dict.get('version')

    return verify_otp(
        main_key=config['main_key'],
        user_otp=user_otp,
        drift_windows=drift_windows,
        use_version=use_version,
        otp_mode=config['otp_mode'],
        n_chars=config['n_chars'],
        time_binning=config['time_binning'],
        location_mode=config['location_mode'],
        latitude=config['latitude'],
        longitude=config['longitude'],
        iso3_code=config['iso3_code'],
        password_str_mode=config['password_str_mode'],
        password_string=config['password_string'],
        algorithm=config['algorithm'],
    )


def verify_otp_from_uri(
    user_otp: str,
    uri: str,
    drift_windows: int = 1,
    *,
    latitude: float | None = None,
    longitude: float | None = None,
    iso3_code: str | None = None,
    password_string: str | None = None,
) -> bool:
    """Verify a user-provided OTP from a ``TLSOTP://`` URI.

    The algorithm version recorded in the URI (default: current line) is
    honored automatically; legacy URIs are verified against the older
    algorithm.

    Args:
        user_otp (str): The OTP provided by the user.
        uri (str): TLSOTP URI string.
        drift_windows (int): Time-window drift tolerance.
        latitude (float | None): Runtime latitude (not stored in URI).
        longitude (float | None): Runtime longitude (not stored in URI).
        iso3_code (str | None): Runtime ISO3 country code (not stored in URI).
        password_string (str | None): Runtime password (not stored in URI).

    Returns:
        bool: Whether the OTP is valid.

    Raises:
        ValueError: If the URI is malformed (e.g. does not start with
            ``TLSOTP://``), or if the location/password mode requires a
            value that was not provided.
    """
    config = get_dict_from_uri(uri)

    if latitude is not None:
        config['latitude'] = latitude
    if longitude is not None:
        config['longitude'] = longitude
    if iso3_code is not None:
        config['iso3_code'] = iso3_code
    if password_string is not None:
        config['password_string'] = password_string

    return verify_otp_from_dict(config, user_otp, drift_windows=drift_windows)
