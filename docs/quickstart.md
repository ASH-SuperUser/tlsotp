# Quickstart Guide

Get a working OTP in under 2 minutes.

---

## 1. Generate a Key

```python
from tlsotp import key_gen

key = key_gen(32)           # 32-byte URL-safe key (default)
print(key)                  # e.g. "xK8…3fA"
```

`key_gen()` uses Python's `secrets` module — cryptographically secure.

---

## 2. Generate a Basic OTP

```python
from tlsotp import get_OTP

otp = get_OTP(main_key=key)
print(otp)                  # 6-digit number, e.g. "847291"
```

Every call within the same 30-second window returns the same OTP.
After 30 seconds a new OTP is generated.

---

## 3. Change the Output Format

```python
# Alphabetic OTP (A-Z, a-z), 8 characters
otp = get_OTP(main_key=key, otp_mode=1, n_chars=8)
print(otp)                  # e.g. "aFmXqRtZ"

# Alphanumeric OTP (digits + letters), 10 characters
otp = get_OTP(main_key=key, otp_mode=2, n_chars=10)
print(otp)                  # e.g. "4kD9mP2xQ7"
```

| `otp_mode` | Output set            |
|------------|-----------------------|
| 0          | `0` – `9`             |
| 1          | `A–Z` + `a–z` (52)    |
| 2          | `0–9` + `A–Z` + `a–z` (62) |

---

## 4. Location-Aware OTP

Bind the OTP to a specific country or coordinates. The same key **at a different location** produces a different OTP.

```python
otp = get_OTP(
    main_key=key,
    location_mode=301,          # ISO3 country code
    iso3_code="IND",            # India
)
print(otp)
```

---

## 5. Use the Dictionary API

Easier to manage — pass a dict instead of individual arguments:

```python
from tlsotp import get_OTP_from_dict

config = {
    "main_key": key,
    "otp_mode": 2,
    "n_chars": 8,
    "location_mode": 301,
    "iso3_code": "IND",
}
otp = get_OTP_from_dict(config)
print(otp)
```

`get_data_dict()` validates and fills defaults:

```python
from tlsotp import get_data_dict

validated = get_data_dict(main_key=key, otp_mode=1)
print(validated)
# {
#     'main_key': '…',
#     'otp_mode': 1,
#     'n_chars': 6,
#     'time_binning': 30,
#     'location_mode': 0,
#     'latitude': None,
#     'longitude': None,
#     'iso3_code': None,
#     'password_str_mode': 0,
#     'password_string': None,
#     'algorithm': 0,
# }
```

---

## 6. Share Config via URI

Encode the non‑sensitive config into a `TLSOTP://` URI.
Runtime values (latitude, longitude, ISO3 code, password) are **not** stored in the URI — they're supplied when generating the OTP.

**Server side — create the URI:**

```python
from tlsotp import get_OTP_uri, get_otp_from_uri

uri = get_OTP_uri(main_key=key, otp_mode=2, location_mode=301)
# "TLSOTP://main_key=…&otp_mode=2&n_chars=6&time_binning=30&location_mode=301&password_str_mode=0&algorithm=sha1&version=v1.0"
```

**Client side — generate OTP from URI + runtime values:**

```python
otp = get_otp_from_uri(uri, iso3_code="IND")
print(otp)
```

---

## 7. Verify an OTP with Drift Tolerance

```python
from tlsotp import verify_otp

# Suppose the user typed "847291"
is_valid = verify_otp(main_key=key, user_otp="847291", drift_windows=1)
print(is_valid)     # True or False
```

`drift_windows=1` checks the current, previous, and next time window
(3 windows total). This tolerates minor clock skew.

---

## 8. Next Steps

- Browse **[Examples](examples.md)** for every feature and mode.
- Read the **[Modes Reference](modes-reference.md)** for detailed tables of all arguments, location modes, and password modes.
- Check the **[API Reference](api/interface.md)** for full function signatures.
- Reproducing OTPs from older releases? Use `use_version="v0.2"` or a `version="v0.2"` URI — see [Algorithm Versions](modes-reference.md#algorithm-versions).
