# Examples

This page covers every feature and every function in `tlsotp` with
run‑nable examples. All examples assume a variable `key` exists:

```python
from tlsotp import key_gen
key = key_gen()
```

---

## 1. Key Generation

```python
from tlsotp import key_gen

# Default 32-byte URL-safe token
key = key_gen()
print(key)                     # "xK8s…3fA"

# Custom length
key_64 = key_gen(64)
print(key_64)                  # longer key
```

> Keys are generated with `secrets.token_urlsafe()` — cryptographically
> secure and URL‑safe.

---

## 2. Basic OTP Generation

### 2.1 Default (6-digit numeric)

```python
from tlsotp import get_OTP

otp = get_OTP(main_key=key)
print(otp)                     # "847291"
```

### 2.2 Numeric, 8 characters

```python
otp = get_OTP(main_key=key, otp_mode=0, n_chars=8)
print(otp)                     # "84729165"
```

### 2.3 Alphabetic, 8 characters

```python
otp = get_OTP(main_key=key, otp_mode=1, n_chars=8)
print(otp)                     # "aFmXqRtZ"
```

### 2.4 Alphanumeric, 10 characters

```python
otp = get_OTP(main_key=key, otp_mode=2, n_chars=10)
print(otp)                     # "4kD9mP2xQ7"
```

---

## 3. Location-Aware OTP

### 3.1 ISO3 Country Binding (mode 301)

```python
otp_india = get_OTP(main_key=key, location_mode=301, iso3_code="IND")
otp_usa  = get_OTP(main_key=key, location_mode=301, iso3_code="USA")
print(otp_india, otp_usa)      # different values
```

### 3.2 Precision Rounding without ISO3 (mode 4xx)

```python
# 2 decimal places (402 → 402-400 = 2)
otp = get_OTP(
    main_key=key,
    location_mode=402,
    latitude=35.6762,
    longitude=139.6503,
)
print(otp)
```

> `location_mode=400` is allowed and rounds to 0 decimal places.
> `iso3_code` is not required for `4xx` modes.

### 3.3 Grid Snapping without ISO3 (mode 5xx)

```python
# 20° grid (520 → 520-500 = 20)
otp = get_OTP(
    main_key=key,
    location_mode=520,
    latitude=28.6139,
    longitude=77.2090,
)
print(otp)
```

> `location_mode` must **not** be `500` — step 0 yields an empty location
> segment (the OTP is generated with no location binding).
> `iso3_code` is not required for `5xx` modes.

### 3.4 Precision Rounding with ISO3 (mode 6xx)

```python
# 3 decimal places + country (603 → 603-600 = 3)
otp = get_OTP(
    main_key=key,
    location_mode=603,
    iso3_code="JPN",
    latitude=35.6762,
    longitude=139.6503,
)
print(otp)
```

> Requires `iso3_code`, `latitude`, and `longitude`.
> `location_mode=600` is allowed and rounds to 0 decimal places.

### 3.5 Grid Snapping with ISO3 (mode 7xx)

```python
# 20° grid + country (720 → 720-700 = 20)
otp = get_OTP(
    main_key=key,
    location_mode=720,
    iso3_code="IND",
    latitude=28.6139,
    longitude=77.2090,
)
print(otp)
```

> Requires `iso3_code`, `latitude`, and `longitude`.
> `location_mode` must **not** be `700` — step 0 yields an empty location
> segment (the OTP is generated with no location binding).

### 3.6 Coarse Grid (negative mode)

```python
# Snap down to a 10° grid
otp = get_OTP(
    main_key=key,
    location_mode=-10,
    latitude=28.6139,
    longitude=77.2090,
)
print(otp)
```

### 3.7 Precision Rounding (positive, non-301/non-4xx/non-5xx/non-6xx/non-7xx)

```python
# 4 decimal places (capped at 6)
otp = get_OTP(
    main_key=key,
    location_mode=4,
    latitude=28.6139,
    longitude=77.2090,
)
print(otp)
```

> Precision is capped at 6 decimal places to prevent resource abuse.

---

## 4. Password-Enhanced OTP

### 4.1 Full Password (negative mode)

```python
otp = get_OTP(
    main_key=key,
    password_str_mode=-1,
    password_string="MySecurePass123",
)
print(otp)
```

### 4.2 Truncated Password (positive mode)

```python
# First 4 characters only
otp = get_OTP(
    main_key=key,
    password_str_mode=4,
    password_string="DelhiSecurePass",
)
print(otp)
```

---

## 5. Hash Algorithm Selection

```python
otp_sha1   = get_OTP(main_key=key, algorithm="sha1")
otp_sha256 = get_OTP(main_key=key, algorithm="sha256")
otp_sha512 = get_OTP(main_key=key, algorithm="sha512")
otp_sha3   = get_OTP(main_key=key, algorithm="sha3-512")

# Integer IDs also work
otp_sha256 = get_OTP(main_key=key, algorithm=2)
```

> **Recommendation:** Use SHA‑256 or stronger for production.

---

## 6. Custom Time Binning

```python
# OTP changes every 60 seconds instead of 30
otp = get_OTP(main_key=key, time_binning=60)

# Every 5 minutes
otp = get_OTP(main_key=key, time_binning=300)
```

---

## 7. Full Combination

All features together:

```python
otp = get_OTP(
    main_key=key,
    otp_mode=2,
    n_chars=10,
    time_binning=30,
    location_mode=402,
    latitude=28.6139,
    longitude=77.2090,
    iso3_code="IND",
    password_str_mode=4,
    password_string="OfficePass",
    algorithm="sha256",
)
print(otp)
```

---

## 8. Dictionary API

### 8.1 Validate & Build a Config Dict

```python
from tlsotp import get_data_dict

config = get_data_dict(
    main_key=key,
    otp_mode=2,
    n_chars=8,
    location_mode=301,
    iso3_code="IND",
    algorithm="sha256",
)
print(config)
# {
#     'main_key': '...',
#     'otp_mode': 2,
#     'n_chars': 8,
#     'time_binning': 30,
#     'location_mode': 301,
#     'latitude': None,
#     'longitude': None,
#     'iso3_code': 'IND',
#     'password_str_mode': 0,
#     'password_string': None,
#     'algorithm': 'sha256',
# }
```

> `get_data_dict()` validates all arguments and returns a normalized
> dictionary with defaults filled in. It raises `ValueError` on
> invalid input (e.g., missing `iso3_code` when `location_mode=301`,
> latitude out of range, etc.).

### 8.2 Generate OTP from Dict

```python
from tlsotp import get_OTP_from_dict

otp = get_OTP_from_dict(config)
print(otp)
```

### 8.3 Partial Override / Adder

`get_OTP_from_dict` only looks at known keys — unknown keys are silently
ignored. Use it with a base config and override specific fields:

```python
base = {"main_key": key, "otp_mode": 2, "n_chars": 8}

# Override n_chars
otp = get_OTP_from_dict({**base, "n_chars": 10})
print(len(otp))                # 10
```

---

## 9. URI Sharing

### 9.1 Create a URI

```python
from tlsotp import get_OTP_uri

uri = get_OTP_uri(
    main_key=key,
    otp_mode=2,
    n_chars=8,
    time_binning=60,
    location_mode=301,
    password_str_mode=0,
    algorithm="sha256",
)
print(uri)
# "TLSOTP://main_key=...&otp_mode=2&n_chars=8&time_binning=60&location_mode=301&password_str_mode=0&algorithm=sha256&version=v1.0"
```

> All parameters are **always** included (even defaults), plus the algorithm
> `version`. Runtime values (latitude, longitude, iso3_code, password_string)
> are **never** stored in the URI.

### 9.2 Create URI from Dict

```python
from tlsotp import get_OTP_uri_from_dict

uri = get_OTP_uri_from_dict({
    "main_key": key,
    "otp_mode": 2,
    "location_mode": 301,
    "algorithm": "sha256",
})
print(uri)
```

### 9.3 Parse URI Back to Dict

```python
from tlsotp import get_dict_from_uri

parsed = get_dict_from_uri(uri)
print(parsed)
# {
#     'main_key': '...',
#     'otp_mode': 2,
#     'n_chars': 6,
#     'time_binning': 30,
#     'location_mode': 301,
#     'latitude': None,        # not in URI
#     'longitude': None,
#     'iso3_code': None,
#     'password_str_mode': 0,
#     'password_string': None,
#     'algorithm': 2,
#     'version': 'v1.0',
# }
```

### 9.4 Generate OTP from URI + Runtime Values

```python
from tlsotp import get_otp_from_uri

otp = get_otp_from_uri(uri, iso3_code="IND")
print(otp)
```

You can also override or add values:

```python
# Override n_chars (takes precedence over URI value)
otp = get_otp_from_uri(uri, iso3_code="IND", override_dict={"n_chars": 10})

# Add a value only if missing (adder_dict never replaces a non-None
# value). Here password_string is None in the parsed config, so it is
# added; password_str_mode is already 0, so the factor stays disabled.
otp = get_otp_from_uri(uri, iso3_code="IND", adder_dict={"password_string": "secret"})

# To actually enable the password factor, override the mode:
otp = get_otp_from_uri(
    uri, iso3_code="IND",
    override_dict={"password_str_mode": -1, "password_string": "secret"},
)
```

### 9.5 Verify OTP from URI

```python
from tlsotp import verify_otp_from_uri

result = verify_otp_from_uri(user_otp="847291", uri=uri, iso3_code="IND", drift_windows=1)
print(result)                  # True or False
```

---

## 10. OTP Verification

### 10.1 Verify Directly

```python
from tlsotp import verify_otp

current = get_OTP(main_key=key)
result = verify_otp(main_key=key, user_otp=current, drift_windows=0)
print(result)                  # True

# Wrong OTP
result = verify_otp(main_key=key, user_otp="000000", drift_windows=0)
print(result)                  # False
```

### 10.2 With Drift Tolerance

```python
# Drift checking 2 windows in each direction = 5 total windows
result = verify_otp(main_key=key, user_otp=current, drift_windows=2)
```

### 10.3 Verify from Dict

```python
from tlsotp import verify_otp_from_dict

config = {"main_key": key, "otp_mode": 2, "n_chars": 8}
result = verify_otp_from_dict(config, user_otp=current, drift_windows=1)
print(result)
```

### 10.4 Verify with Custom Params

```python
result = verify_otp(
    main_key=key,
    user_otp=current,
    drift_windows=1,
    otp_mode=2,
    n_chars=10,
    algorithm="sha256",
)
```

> All verification uses **constant-time comparison** (`hmac.compare_digest`)
> to prevent timing side-channel attacks.

---

## 11. Location Validation Rules

If `location_mode` is non-zero, the following rules are enforced by
`get_data_dict()`:

| `location_mode` | Required arguments |
|-----------------|-------------------|
| `301` | `iso3_code` (≥3 chars) |
| `4xx` | `latitude`, `longitude` |
| `5xx` | `latitude`, `longitude` |
| `6xx` | `iso3_code`, `latitude`, `longitude` |
| `7xx` | `iso3_code`, `latitude`, `longitude` |
| `< 0` (negative) | `latitude`, `longitude` |
| `> 0` (not 301/4xx/5xx/6xx/7xx) | `latitude`, `longitude` |

Latitude must be between `-90` and `90`. Longitude between `-180` and `180`.

```python
# Raises ValueError: missing iso3_code for location_mode 301
get_data_dict(main_key=key, location_mode=301)

# Raises ValueError: latitude out of range
get_data_dict(main_key=key, location_mode=1, latitude=100, longitude=0)
```

---

## 12. Error Handling Examples

```python
from tlsotp import get_data_dict, get_OTP_from_dict

# Empty key
try:
    get_data_dict(main_key="")
except ValueError as e:
    print(e)                   # "main_key must be a non-empty string"

# Invalid OTP mode
try:
    get_data_dict(main_key=key, otp_mode=99)
except ValueError as e:
    print(e)                   # "otp_mode must be 0, 1, or 2"

# Missing required location data
try:
    get_data_dict(main_key=key, location_mode=301)
except ValueError as e:
    print(e)                   # "iso3_code (>=3 chars) required for location_mode 301"

# Missing password
try:
    get_data_dict(main_key=key, password_str_mode=2)
except ValueError as e:
    print(e)                   # "password_string required when password_str_mode != 0"
```

---

## 13. Multi-City Comparison

```python
from tlsotp import get_OTP

cities = {
    "Delhi":    (28.6139, 77.2090),
    "Mumbai":   (19.0760, 72.8777),
    "Tokyo":    (35.6762, 139.6503),
    "New York": (40.7128, -74.0060),
}

for name, (lat, lon) in cities.items():
    otp = get_OTP(
        main_key=key,
        otp_mode=2,
        location_mode=402,
        latitude=lat, longitude=lon,
        iso3_code="IND" if name in ("Delhi", "Mumbai") else "JPN",
    )
    print(f"{name:>10}  {otp}")
```

---

## 14. Algorithm Speed Comparison

```python
from tlsotp import get_OTP
import time

for algo in ("sha1", "sha224", "sha256", "sha384", "sha512", "sha3-512"):
    t0 = time.time()
    otp = get_OTP(main_key=key, algorithm=algo)
    dt = time.time() - t0
    print(f"{algo:>10}  {otp}  ({dt*1000:.1f} ms)")
```

---

## 15. Production Setup Checklist

| Step | Recommendation |
|------|---------------|
| Key length | 32 bytes or more |
| OTP length | 6 or more characters |
| Algorithm | SHA‑256 or SHA‑512 |
| Time binning | 30 or 60 seconds |
| Location | Use `301` for country‑level binding |
| Password | Use a strong shared passphrase |
| Verification | Use `drift_windows=1` to tolerate clock skew |
| Key storage | Never hardcode; use env vars / vault / HSM |
| Transmission | Always use TLS for transport |

---

## 16. Algorithm Versions & Legacy Compatibility

Every OTP call is version‑aware. `None` (default) and any `v1.x` request use
the current algorithm; `v0.1` / `v0.2` are dispatched to the `legacy` module so
OTPs produced by older TLSOTP releases keep verifying after an upgrade.
Backwards compatibility is **not guaranteed** — the legacy module is a
*mostly* compatible reproduction of the old releases, validated against them.

### 16.1 Select a Version for Generation

```python
from tlsotp import get_OTP

otp_current = get_OTP(main_key=key)                    # v1.0 (default)
otp_v02     = get_OTP(main_key=key, use_version="v0.2")
otp_v01     = get_OTP(main_key=key, use_version="0.1.0")  # normalized to v0.1
```

Version strings are normalized — `"v0.2"`, `"0.2"`, `"0.2.0"` are equivalent.
`get_OTP_from_dict`, `verify_otp`, and `verify_otp_from_dict` accept the same
`use_version` argument.

### 16.2 Verify Against a Legacy Version

```python
from tlsotp import verify_otp

ok = verify_otp(main_key=key, user_otp=otp_v02, use_version="v0.2")
print(ok)                      # True
```

### 16.3 Legacy URIs

A URI records the algorithm version. Create one with `version="v0.2"` and the
v0.2 algorithm is reproduced automatically — even on a newer TLSOTP install:

```python
from tlsotp import get_OTP_uri, get_otp_from_uri, get_dict_from_uri

uri_v02 = get_OTP_uri(main_key=key, otp_mode=2, n_chars=8, version="v0.2")
print(uri_v02)                 # "...&algorithm=sha1&version=v0.2"

otp = get_otp_from_uri(uri_v02)
parsed = get_dict_from_uri(uri_v02)
print(parsed['version'])       # 'v0.2'
```

### 16.4 Direct `tlsotp.legacy` Access

```python
from tlsotp.legacy import get_otp_legacy, supported_legacy_versions, normalize_version

supported_legacy_versions()    # ('v0.1', 'v0.2')
normalize_version("0.2.0")     # 'v0.2'

otp = get_otp_legacy(key, version="v0.2", otp_mode=2, n_chars=8)
```

> **Legacy differences.** Compared to v1.0, the legacy algorithm uses a cyclic
> per‑byte `OTP_gen`, embeds the ISO3 code in the 4xx/5xx location modes
> (*and requires* `iso3_code`), and does **not** cap positive location
> precision at 6 decimals.
