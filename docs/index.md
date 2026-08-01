# TLSOTP

> **T**ime-**L**ocation-**S**tring **O**ne-**T**ime **P**assword

A Python library for generating cryptographically strong, context-aware one-time passwords that bind to **time**, **geographic location**, and **passphrases**.

---

## Features

- **Time‑windowed** — OTP changes every `N` seconds (default 30s)
- **Location‑aware** — bind OTPs to country (ISO3), coordinates, or grid cells
- **Password‑enhanced** — layer a shared passphrase into the HMAC seed
- **Version‑aware** — `use_version=` selects the current or a legacy algorithm; URIs record the algorithm version
- **Legacy compatibility** — v0.1 / v0.2 mostly compatible via `tlsotp.legacy`
- **Multiple output modes** — numeric (digits), alphabetic, or alphanumeric
- **Pluggable hashing** — SHA‑1, SHA‑224, SHA‑256, SHA‑384, SHA‑512, SHA3‑512
- **URI sharing** — encode the static config into `TLSOTP://` URIs (runtime values like lat/lon/password supplied separately)
- **Time‑drift tolerant** — `verify_otp()` checks past **and** future windows
- **Constant‑time verification** — uses `hmac.compare_digest` to prevent timing side‑channels

---

## Installation

```bash
pip install tlsotp
```

Development install with test dependencies:

```bash
git clone https://github.com/ASH-SuperUser/tlsotp.git
cd tlsotp
pip install -e .[dev]
```

Verify:

```bash
python -c "import tlsotp; print(tlsotp.__version__)"
```

---

## Project Links

- GitHub: [https://github.com/ASH-SuperUser/tlsotp](https://github.com/ASH-SuperUser/tlsotp)
- PyPI: [https://pypi.org/project/tlsotp/](https://pypi.org/project/tlsotp/)

---

## Quick Start

```python
from tlsotp import key_gen, get_OTP

# 1. Generate a secret key
key = key_gen()

# 2. Generate a 6‑digit OTP (default)
otp = get_OTP(main_key=key)
print(otp)   # e.g. "847291"
```

See the [Quickstart Guide](quickstart.md) for a longer walkthrough and the [Examples](examples.md) page for every use case.

Every OTP call is version‑aware: pass `use_version="v0.2"` (or create a
`version="v0.2"` URI) to reproduce the legacy v0.1/v0.2 algorithms so old OTPs
keep working after upgrades — see [Modes & Arguments](modes-reference.md).

For a deep technical comparison against the standard TOTP (RFC 6238), see [TLSOTP vs TOTP](comparison-with-totp.md).

---

## License

Apache License 2.0 — see [`LICENSE`](https://github.com/ASH-SuperUser/tlsotp/blob/main/LICENSE).

---

## Disclaimer

**TLSOTP is provided as-is.** The author is not responsible for security misuse, data loss, system failures, or incorrect implementation.

**Once a key is lost there is no way to recover the correct OTP.** Store keys securely.
