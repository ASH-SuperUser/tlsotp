# TLSOTP

```
_________ _       _______  _______ _________ _______ 
\__   __/( \     (  ____ \(  ___  )\__   __/(  ____ )
   ) (   | (     | (    \/| (   ) |   ) (   | (    )|
   | |   | |     | (_____ | |   | |   | |   | (____)|
   | |   | |     (_____  )| |   | |   | |   |  _____)
   | |   | |           ) || |   | |   | |   | (      
   | |   | (____/Y\____) || (___) |   | |   | )      
   )_(   (_______|_______)(_______)   )_(   |/       

```

> **T**ime **L**ocation **S**tring **O**ne-**T**ime **P**assword

TLSOTP is a flexible, deterministic OTP (One-Time Password) generation library built in Python.
It extends the idea of time-based OTPs by allowing **additional contextual entropy sources** such as location and passwords.

⚠️ **Note:** This is system is **not RFC-compliant**. It is **not compatible with standard TOTP apps** like Google Authenticator.

---

## ✨ Features

* Time-based OTP generation (TOTP-like behavior)

* Optional location-based entropy

* Optional password-based entropy

* Multiple output formats:
  * Numeric
  * Alphabetic
  * Alphanumeric

* Deterministic OTP generation (same inputs → same OTP)

* Multiple cryptographic hash algorithms:
  * SHA1
  * SHA224
  * SHA256
  * SHA384
  * SHA512
  * SHA3-512

---

## 📦 Installation

### Install from PyPI (recommended)

```bash
pip install tlsotp
```

### Development install from PyPI

```bash
pip install tlsotp[dev]
```

### Install from source

```bash
git clone https://github.com/ASH-SuperUser/tlsotp.git
cd tlsotp
pip install .
```

### Development install

```bash
git clone https://github.com/ASH-SuperUser/tlsotp.git
cd tlsotp
pip install -e .[dev]
```

---

## 🚀 Quick Start

```python
from tlsotp import get_OTP, key_gen

# Generate a secret key
key = key_gen()

# Basic time-based OTP
otp = get_OTP(main_key=key)
print(otp)
```

### With additional context

```python
otp = get_OTP(
    main_key="my_secret_key",
    otp_mode=2,
    n_chars=8,
    time_binning=30,
    location_mode=3,
    latitude=30.3165,
    longitude=78.0322,
    iso3_code="IND",
    password_str_mode=-1,
    password_string="mypassword",
    algorithm="sha256"
)

print(otp)
```

---

## Core Concept

TLSOTP generates OTPs using an HMAC-based construction:

```
HMAC(secret_key, time + location + password)
```

Each component contributes independently:

* **Time** → ensures periodic OTP rotation
* **Location** → binds OTP to a geographic region (optional)
* **Password** → adds an additional secret layer (optional)

The final HMAC digest is mapped into a deterministic OTP string.

---

## ⚙️ Configuration Overview

### OTP Modes

| Mode | Description           |
| ---- | --------------------- |
| 0    | Numeric only (0–9)    |
| 1    | Alphabetic (A–Z, a–z) |
| 2    | Alphanumeric          |

---

### Location Modes (Simplified)

| Mode Type | Description                    |
| --------- | ------------------------------ |
| 0         | Disabled                       |
| 301       | ISO3 country code only         |
| 4xx       | Rounded lat/lon with precision |
| 5xx       | Binned lat/lon                 |
| <0        | Coarse binning without ISO     |
| >0        | Rounded lat/lon                |

---

### Password Modes

| Mode | Description            |
| ---- | ---------------------- |
| 0    | Disabled               |
| >0   | Use first N characters |
| <0   | Use full password      |

---

### Supported Algorithms

* `sha1` (default)
* `sha224`
* `sha256`
* `sha384`
* `sha512`
* `sha3-512`

---

## Advanced Usage

### Using dictionary interface

```python
from tlsotp import get_data_dict, get_OTP_from_dict

data = get_data_dict(
    main_key="secret",
    otp_mode=2,
    n_chars=8
)

otp = get_OTP_from_dict(data)
print(otp)
```

---

## Use Cases

* Context-aware authentication systems
* Geo-restricted access control prototypes
* Multi-factor authentication experiments
* Offline OTP verification
* Custom security token generation

---

## ⚠️ Disclaimer

This project is provided **"as is"**, without warranties of any kind.

The author is not responsible for:

* Security vulnerabilities
* System failures
* Data loss
* Financial damages

Use at your own risk.

---

## License

Licensed under the **Apache License 2.0**.

---

## Summary

TLSOTP is a flexible Python library for generating deterministic OTPs using:

* Time
* Optional location
* Optional password / string

It is designed for experimentation and custom authentication systems, offering more flexibility than traditional TOTP approaches—at the cost of standard compatibility.


[![Github Repo](https://img.shields.io/badge/github-repo-blue?logo=github)](https://github.com/ASH-SuperUser/tlsotp)