# TLSOTP Examples

This document covers **all features, modes, and usage patterns** of `TLSOTP` with real-world examples.

---

## 1. Key Generation

### 1.1 Generate Secure Key

```python title="Generate Key" linenums="1" hl_lines="1 3"
from tlsotp import key_gen  # (1)!

key = key_gen(32)  # (2)!
print(key)
```

1. Import secure key generator
2. Generates URL-safe cryptographic key

#### Explanation

* Creates cryptographically secure random key
* Used as `main_key` in all OTP generation

---

## 2. Basic OTP Generation

### 2.1 Numeric OTP

```python title="Numeric OTP" linenums="1" hl_lines="1 5"
from tlsotp import get_OTP

otp = get_OTP(
    main_key="delhi-secret",
    otp_mode=0,              # (1)!
    n_chars=6,
    latitude=28.6139,        # Delhi
    longitude=77.2090,
    location_mode=1
)

print(otp)
```

1. `0` means numeric `digits only` OTP

#### Use Case

* Banking OTP
* Login verification

---

### 2.2 Alphabet OTP

```python title="Alphabet OTP" linenums="1" hl_lines="3-3"
otp = get_OTP(
    main_key="mumbai-key",
    otp_mode=1,              # (1)!
    n_chars=8,
    latitude=19.0760,       # Mumbai
    longitude=72.8777,
    location_mode=1
)

print(otp)
```

1. `1` means alphabet `A–Z + a–z` OTP

---

### 2.3 Alphanumeric OTP

```python title="Alphanumeric OTP (Dehradun)" linenums="1" hl_lines="3-3"
otp = get_OTP(
    main_key="dehradun-key",
    otp_mode=2,              # (1)!
    n_chars=10,
    latitude=30.3165,
    longitude=78.0322,
    location_mode=1
)

print(otp)
```

1. `2` means alphanumeric `digits + letters` OTP

---

## 3. Time-Based OTP (TOTP Style, but not exactly TOTP)

### 3.1 SHA1 (Default)

```python title="TOTP SHA1" linenums="1" hl_lines="4-4"
otp = get_OTP(
    main_key="time-key",
    time_binning=30,
    algorithm="sha1",  # (1)!
    otp_mode=0
)
```

1. SHA1 algorithm

---

### 3.2 SHA256

```python title="SHA256 OTP" linenums="1" hl_lines="3-3"
otp = get_OTP(
    main_key="mumbai-secure",
    algorithm="sha256",  # (1)!
    time_binning=60,
    latitude=19.0760,
    longitude=72.8777
)
```

1. Uses SHA256 hashing

---

### 3.3 SHA512 (High security)

```python title="SHA512 OTP" linenums="1" hl_lines="3-3"
otp = get_OTP(
    main_key="andaman-secure",
    algorithm="sha512",  # (1)!
    otp_mode=2,
    latitude=11.7401,
    longitude=92.6586
)
```

1. Uses SHA512 hashing

---

## 4. Location-Based OTP

### 4.1 ISO3 Mode (India - IND)

```python title="ISO3 Mode" linenums="1" hl_lines="4-4"
otp = get_OTP(
    main_key="india-key",
    location_mode=301,   # (1)!
    iso3_code="IND"
)
```

1. ISO3 country binding

---

### 4.2 High Precision Location

```python title="High precision location" linenums="1" hl_lines="3-3"
otp = get_OTP(
    main_key="geo-delhi",
    location_mode=403,     # (1)!
    latitude=28.6139,
    longitude=77.2090,
    iso3_code="IND"
)
```

1. 4xx = precision-based encoding

!!! warning "location_mode arguement warning"

    arguement `location_mode` must never be 400, it will lead to zero division error

---

### 4.3 Grid Location Mode

```python title="Grid location mode" linenums="1" hl_lines="3-3"
otp = get_OTP(
    main_key="grid-mumbai",
    location_mode=520,     # (1)!
    latitude=19.0760,
    longitude=72.8777,
    iso3_code="IND"
)
```

1. 5xx = grid snapping

!!! warning "location_mode arguement warning"

    arguement `location_mode` must never be 500, it will lead to zero division error

---

### 4.4 Negative Location Mode

```python title="Negative location mode" linenums="1" hl_lines="3-3"
otp = get_OTP(
    main_key="hill-lock",
    location_mode=-5,      # (1)!
    latitude=30.3165,
    longitude=78.0322
)
```

1. Negative = coarse geographic grouping

---

## 5. Password Enhanced OTP

### 5.1 Full Password Inclusion

```python title="Full password OTP" linenums="1" hl_lines="3-3"
otp = get_OTP(
    main_key="bank-key",
    password_str_mode=-1,  # (1)!
    password_string="SecurePass123",
    latitude=19.0760,
    longitude=72.8777
)
```

1. Full password included

---

### 5.2 Partial Password

```python title="Partial password OTP" linenums="1" hl_lines="3-3"
otp = get_OTP(
    main_key="login-key",
    password_str_mode=4,  # (1)!
    password_string="DelhiSecurePass",
    latitude=28.6139,
    longitude=77.2090
)
```

1. First 4 characters only

---

## 6. Dictionary API (Recommended)

### 6.1 Build Dictionary

```python title="Build OTP dictionary" linenums="1" hl_lines="3-10"
from tlsotp import get_data_dict

data = get_data_dict(
    main_key="dict-key",
    otp_mode=2,
    n_chars=8,
    latitude=28.6139,
    longitude=77.2090,
    iso3_code="IND"
)

print(data)
```

---

### 6.2 Generate OTP from Dictionary

```python title="OTP from dict" linenums="1" hl_lines="3-10"
from tlsotp import get_OTP_from_dict

otp = get_OTP_from_dict({
    "main_key": "dict-key",
    "otp_mode": 2,
    "n_chars": 10,
    "latitude": 19.0760,
    "longitude": 72.8777,
    "iso3_code": "IND"
})

print(otp)
```

---

### 6.3 Partial Override

```python title="Partial override dict" linenums="1"
otp = get_OTP_from_dict({
    "main_key": "override-key",
    "otp_mode": 1,
    "latitude": 30.3165,
    "longitude": 78.0322,
    "password_string": "HillPass",
    "password_str_mode": 4
})
```

---

## 7. Multi-City OTP Comparison

```python title="Multi-city OTP comparison" linenums="1"
cities = {
    "Delhi": (28.6139, 77.2090),
    "Mumbai": (19.0760, 72.8777),
    "Dehradun": (30.3165, 78.0322),
    "Andaman": (11.7401, 92.6586)
}

for city, (lat, lon) in cities.items():
    otp = get_OTP(
        main_key="multi-key",
        otp_mode=2,
        location_mode=1,
        latitude=lat,
        longitude=lon,
        iso3_code="IND"
    )
    print(city, otp)
```

---

## 8. Algorithm Comparison

```python title="Algorithm comparison" linenums="1" hl_lines="4-5"
otp1 = get_OTP("key", algorithm="sha1")
otp2 = get_OTP("key", algorithm="sha512")

print(otp1, otp2)
```

---

## 9. Production Example

```python title="Production OTP setup" linenums="1" hl_lines="2-8"
otp = get_OTP(
    main_key="prod-secret",
    otp_mode=0,
    n_chars=6,
    time_binning=30,
    location_mode=301,
    iso3_code="IND",
    algorithm="sha256"
)
```

---

## 10. Key Concepts Summary

!!! info
- Time changes OTP every `time_binning`
- Location binds OTP to geography (Delhi, Mumbai, etc.)
- Password increases entropy
- Algorithm changes cryptographic strength
- Dictionary API ensures structured usage

---

## 11. Best Practices

* Use `sha256` or higher for production
* Prefer `time_binning = 30 or 60`
* Use `location_mode=301` for country-level binding
* Avoid storing raw passwords in logs
* Always validate lat/lon before production use

