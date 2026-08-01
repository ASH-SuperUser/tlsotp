# TLSOTP vs TOTP (RFC 6238) — Technical Comparison

> A factual, side-by-side comparison of TLSOTP against the standard TOTP
> algorithm (RFC 6238, built on HOTP RFC 4226). Both schemes generate
> deterministic, time-rotating one-time passwords from a shared secret using
> HMAC. They differ in seed construction, output mapping, and optional context
> factors. **They are not interoperable:** TLSOTP is a non-RFC custom scheme.

---

## 1. Capability Comparison

| Capability | TOTP (RFC 6238) | TLSOTP |
|------------|-----------------|--------|
| Time window | `X` seconds, configurable (default 30s) | `time_binning` seconds, configurable (default 30s) |
| Time origin offset | ✓ `T0` parameter (default Unix epoch) | ✗ epoch-absolute only |
| Location binding | ✗ | ✓ ISO3 / precision rounding / grid snapping (modes 301, 4xx–7xx, ±) |
| Password layer | ✗ | ✓ full or truncated shared passphrase in seed |
| Output charset | Digits only (numeric) | ✓ Digits / alpha / alphanumeric (10/52/62) |
| OTP length | `digits`, 6–8 per RFC 4226 (6 typical) | ✓ 1–128 chars |
| Hash algorithms | 3 — HMAC-SHA-1 (MUST), HMAC-SHA-256/512 (MAY) | 6 — SHA-1/224/256/384/512/SHA3-512 |
| Config-as-URI | `otpauth://totp/…` (secret embedded, universal) | `TLSOTP://` (runtime secrets location/password excluded) |
| Verification window | Server policy (RFC recommends ≤ 1 step); configurable in practice | `drift_windows = N` → `2N+1` windows |
| Constant-time compare | ✓ (implementation-dependent) | ✓ `hmac.compare_digest` |
| Secret key encoding | Base32 (RFC 4648), ~160-bit typical | URL-safe Base64 (`token_urlsafe`), ~256-bit default |
| Secret strength | ≥ 128-bit, 160-bit recommended | ~256-bit default; user-specified strings |
| Modulo bias (truncation) | Very small — 31-bit mod 10⁶: ~4.7×10⁻⁴ per code (RFC 4226) | Very small — 32-bit mod alphabet: mode 0 ≈ 2.3×10⁻⁹, mode 1 ≈ 1.2×10⁻⁸, mode 2 ≈ 1.4×10⁻⁸ per char; ~3.2×10⁴–2.0×10⁵× smaller than TOTP |
| Long-output generation | Single 31-bit dynamic truncation | Continues deriving bytes via chained SHA-256 when additional output is needed |
| Authenticator-app interop | ✓ (Base32 + otpauth, universal) | ✗ by design |
| Test vectors | ✓ RFC 6238 appendix (SHA-1/256/512) | ✗ (no published known-answer vectors; covered by Hypothesis/fuzz and internal unit tests) |
| Standalone verification lib | ✓ (e.g. pyotp, oath-toolkit) | ✓ `verify_otp*` built-in |

**Reading the table:** the two schemes overlap on the core time-windowed HMAC
idea. TOTP is the standardised, interoperable baseline; TLSOTP adds context
factors (location, password), wider output/length/hash choices, and a cleaner
truncation bias, at the cost of compatibility with TOTP apps and a `T0` offset.

**Note on `T0`:** TLSOTP's algorithm itself has no `T0` parameter — time
bins are always anchored to the Unix epoch (`core.py:63`). However, the
`get_*`/`verify_*` functions accept an explicit `now` timestamp, so a caller
can emulate a `T0` shift by passing `now + offset`. The scheme's default is
still epoch-absolute.

---

## 2. High-Level Architecture

### Standard TOTP (RFC 6238 / RFC 4226)

```
T ──(T0, X)──▶ counter C = floor((T - T0) / X)     // 8-byte big-endian integer
                │
                ▼
           HMAC-SHA1(secret, C)  ──▶ 20-byte digest
                │
                ▼
        Dynamic truncation (RFC 4226 §5.3)          // offset = digest[19] & 0x0F
        binary = (digest[o] & 0x7F) << 24 | ...     // 31-bit window
                │
                ▼
           binary mod 10^digits  ──▶ numeric OTP
```

- **Seed** = raw binary 8-byte counter. No context inputs.
- **Truncation** = RFC 4226 dynamic truncation (fixed, universally implemented).
- **Verified parameters** (RFC 6238): `X` default 30s, `T0` default 0,
  HMAC-SHA-1/256/512; implementations MUST support a time value `T` larger
  than a 32-bit integer once past the year 2038 (RFC 6238 §4.2).

### TLSOTP

```
T ──(time_binning)──▶ time_str   = f"-{(T // bin) * bin}-"     // ASCII, core.py:63
L ──(location_mode)─▶ location_str = "IND" | "12.35-77.99" | ... // core.py:84
P ──(password_mode)▶ password_str = "-mypass-"                 // core.py:188
                          │
                          ▼
msg = time_str + location_str + password_str                    // UTF-8 bytes
                          │
                          ▼
     HMAC_<algo>(main_key, msg) ──▶ digest                      // core.py:268
                          │
                          ▼
   OTP_gen(digest, otp_mode, n_chars)                           // core.py:8
   · consume 4-byte big-endian chunks
   · chunk mod alphabet_size (10 / 52 / 62)
   · when exhausted → data = sha256(data) chaining (no cycles)
                          │
                          ▼
                       OTP string
```

- **Seed** = context-aware string (time + optional location + optional password).
- **Truncation** = 4-byte-chunk mapping with SHA-256 chaining.

> **Versioning note.** TLSOTP is *version-aware*: `use_version` (or the
> `version` recorded in a `TLSOTP://` URI) selects the algorithm family. The
> live `v1.0` line is described above; `v0.1` / `v0.2` are reproduced by the
> `legacy` module (mostly compatible, not guaranteed) so old OTPs keep working
> after upgrades. This is a library-compatibility feature — the comparisons
> here describe the current `v1.0` algorithm.

---

## 3. Cryptographic Notes

### 3.1 Entropy

A 6-digit numeric OTP is `10^6 ≈ 19.93 bits` in **both** schemes — the default
offers identical brute-force resistance. TLSOTP additionally supports
alphanumeric output: an 8-char code is `62^8 ≈ 47.6 bits`, and lengths scale to
128 chars, a space TOTP's `10^digits` cannot express. In both schemes, online
brute-force protection (rate-limiting / lockout) remains the server's
responsibility.

### 3.2 Truncation and modulo bias

- **RFC 4226**: a 31-bit value is reduced `mod 10^d`.
  `2³¹ = 2 147 483 648 = 2147×10⁶ + 483 648`, so values `0…483647` occur one
  extra time: relative bias ≈ `1/2147 ≈ 4.7×10⁻⁴`. Accepted by the standard.
- **TLSOTP**: each 32-bit chunk is reduced `mod range_size`. The per-character
  bias depends on the output mode:

  | Mode | Alphabet size | `2³² mod size` | Relative bias per char |
  |------|---------------|----------------|------------------------|
  | 0 (digits) | 10 | 6 | `1/429 496 729 ≈ 2.3×10⁻⁹` (digits 0–5 one extra occurrence) |
  | 1 (alpha) | 52 | 48 | `1/82 595 524 ≈ 1.2×10⁻⁸` (48 chars one extra occurrence) |
  | 2 (alphanumeric) | 62 | 4 | `1/69 273 666 ≈ 1.4×10⁻⁸` (4 chars one extra occurrence) |

  More precisely, for mode `m` the reduction maps `2³²` values into `size`
  buckets, leaving `2³² mod size` symbols with one extra value. The relative
  bias per character — how much more likely the hottest symbol is than the
  coldest — is `1 / floor(2³² / size)` (the numbers in the table above).
  Per character this is ≈ **2.3×10⁻⁹ (mode 0)**, ≈ **1.2×10⁻⁸ (mode 1)**,
  ≈ **1.4×10⁻⁸ (mode 2)** — roughly **3.2×10⁴–2.0×10⁵× smaller** (per
  character) than RFC 4226's per-code bias of ~4.7×10⁻⁴, and cryptographically
  negligible. An `n`-character code compounds at most `n` such per-character
  biases, so even a 6-digit code keeps a bias roughly 10⁴× smaller than TOTP's.

### 3.3 Digest expansion

TOTP's dynamic truncation uses only 31 bits of the digest and never expands it.
TLSOTP's `OTP_gen` (core.py:8) re-hashes with `sha256(data)` when the digest is
exhausted. With the default config (SHA-1, 6 digits: 24 bytes needed vs 20
available) the last digit is derived from `SHA-256(HMAC-SHA1(K, msg))` — a
deterministic, non-cyclic composition, but a hidden one absent from TOTP.

### 3.4 Context binding

- **Location** provides *geofencing*: the OTP is valid only inside a country
  (ISO3), a coordinate-precision cell, or a snapped grid. TOTP has no spatial
  concept. The binding is only as strong as the server's trust in the client's
  claimed coordinates.
- **Password** adds a genuinely secret factor *inside* the HMAC seed — a third
  factor TOTP cannot model. TLSOTP deliberately keeps it out of the
  `TLSOTP://` URI (runtime-only value), so a shared URI leaks the key but not
  the password factor.

### 3.5 Timing

Generation in both schemes is fixed-work with no secret-dependent branches.
Verification in TLSOTP uses `hmac.compare_digest` on every checked window
(interface.py:472); constant-time comparison in TOTP verifiers is
implementation-dependent. Residual leak in both: an early return on match can
reveal which window matched via wall-clock timing.

---

## 4. Strengths

| Scheme | Strengths |
|--------|-----------|
| **TOTP** | Ratified and audited (RFC 4226/6238/4648); lossless binary counter; universal interop (Base32 + otpauth); published test vectors; huge ecosystem. |
| **TLSOTP** | Context factors (location/password); wider hash/output/length choice; negligible modulo bias; stronger default key (~256-bit); centralized input validation; built-in drift-tolerant verification; runtime secrets excluded from URIs. |

---

## 5. When to Use Which

| Scenario | Choose |
|----------|--------|
| Production 2FA with authenticator apps / compliance | TOTP |
| Geo-restricted / context-aware access control | TLSOTP |
| Multi-factor experiments (time + location + password) | TLSOTP |
| Offline verification with an extra shared secret | TLSOTP |
| Non-numeric or long OTP tokens | TLSOTP |
| Universal provisioning via otpauth URIs | TOTP |

---

## 6. Summary

TLSOTP and TOTP share the same HMAC-based, time-windowed core. **TOTP** is the
standardised, interoperable baseline with published test vectors — the right
choice wherever third-party authenticator apps or compliance matter. **TLSOTP**
is a superset on inputs (location, password) and output options (charset,
length, 6 hash algorithms), with a cleaner truncation bias and stronger default
key size, but it is non-standard, lacks a `T0` offset, and cannot be used with
standard OTP apps. The choice is a trade-off between **interoperability and
standardisation (TOTP)** versus **flexibility and context binding (TLSOTP)**.

---

## Appendix: Code References

| Component | Location |
|-----------|----------|
| `OTP_gen` chunking / SHA-256 chaining | `src/tlsotp/core.py:8` |
| `time_str` ASCII binning | `src/tlsotp/core.py:63` |
| `location_str` encoding modes | `src/tlsotp/core.py:84` |
| `password_str` wrapping | `src/tlsotp/core.py:188` |
| `get_OTP` HMAC construction | `src/tlsotp/core.py:268` |
| Algorithm dispatch | `src/tlsotp/core.py:328` |
| `key_gen` Base64 URL-safe | `src/tlsotp/interface.py:27` |
| `get_data_dict` validation | `src/tlsotp/interface.py:131` |
| `TLSOTP://` URI handling | `src/tlsotp/interface.py:346` |
| `verify_otp` drift + `compare_digest` | `src/tlsotp/interface.py:601` |

Standards: RFC 4226 (HOTP), RFC 6238 (TOTP), RFC 4648 (Base32), Key Uri Format.
