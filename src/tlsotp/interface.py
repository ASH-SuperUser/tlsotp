from .core import get_OTP
import secrets


def key_gen(length=32):
    return secrets.token_urlsafe(length)


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
            if iso3_code is None or latitude is None or longitude is None:
                raise ValueError("iso3_code, latitude, longitude required for location_mode 4xx/5xx")

        elif location_mode != 0:
            # general lat/lon usage
            if latitude is None or longitude is None:
                raise ValueError("latitude and longitude required for this location_mode")

    # validate lat/lon ranges if provided
    if latitude is not None:
        if not (-90 <= latitude <= 90):
            raise ValueError("latitude must be between -90 and 90")

    if longitude is not None:
        if not (-180 <= longitude <= 180):
            raise ValueError("longitude must be between -180 and 180")

    # ----------- PASSWORD VALIDATION -----------

    if password_str_mode != 0:
        if not password_string:
            raise ValueError("password_string required when password_str_mode != 0")

        if not isinstance(password_str_mode, int):
            raise ValueError("password_str_mode must be an integer")

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


def get_OTP_from_dict(data_dict: dict) -> str:
    if not isinstance(data_dict, dict):
        raise ValueError("data_dict must be a dictionary")

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

    # delegate to your main function
    return get_OTP(
        main_key=final_args['main_key'],
        otp_mode=final_args['otp_mode'],
        n_chars=final_args['n_chars'],
        time_binning=final_args['time_binning'],
        location_mode=final_args['location_mode'],
        latitude=final_args['latitude'],
        longitude=final_args['longitude'],
        iso3_code=final_args['iso3_code'],
        password_str_mode=final_args['password_str_mode'],
        password_string=final_args['password_string'],
        algorithm=final_args['algorithm']
    )


