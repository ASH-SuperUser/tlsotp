# Modes & Arguments Reference

## OTP Format Modes (`otp_mode`)

Controls the character set used for the generated OTP.

| Mode | Output set | Range size | Example |
|------|-----------|------------|---------|
| `0` | Digits (`0`–`9`) | 10 | `847291` |
| `1` | Letters (`A–Z`, `a–z`) | 52 | `aFmXqRtZ` |
| `2` | Alphanumeric (`0–9`, `A–Z`, `a–z`) | 62 | `4kD9mP2xQ7` |

> **Warning:** Only modes `0`, `1`, and `2` are valid. Mode `3` is not supported.

---

## Location Modes (`location_mode`)

Binds the OTP to a geographic location. The table below shows the format
of the location string that gets mixed into the HMAC seed.

| Mode range | Mode values | Description | Format | Required args |
|-----------|-------------|-------------|--------|---------------|
| `0` | `0` | Disabled — no location binding | *(empty string)* | none |
| `301` | `301` | ISO3 country code | `XXX` | `iso3_code` (≥3 chars) |
| `4xx` | `400`–`499` | Precision rounding — round lat/lon to `xx` decimal places (capped at 6; `400` → 0 decimals) | `lat-lon` | `latitude`, `longitude` |
| `5xx` | `501`–`599`<br>(not 500) | Grid snapping — floor lat/lon down to a multiple of `xx` | `lat-lon` | `latitude`, `longitude` |
| `6xx` | `600`–`699` | Precision rounding with ISO3 — like `4xx` but includes country | `XXX-lat-lon` | `iso3_code`, `latitude`, `longitude` |
| `7xx` | `701`–`799`<br>(not 700) | Grid snapping with ISO3 — like `5xx` but includes country | `XXX-lat-lon` | `iso3_code`, `latitude`, `longitude` |
| Negative | `< 0` | Coarse grid — floor lat/lon down to multiples of `abs(mode)` | `lat-lon` | `latitude`, `longitude` |
| Positive (>0, not 301/4xx/5xx/6xx/7xx) | e.g. `1`–`300`, `302`–`399` | Precision rounding (capped at 6 decimal places) | `lat-lon` | `latitude`, `longitude` |

### Mode 301 — ISO3 Country Binding

```python
get_OTP(main_key="k", location_mode=301, iso3_code="IND")
# Location string → "IND"
```

- OTP is valid only at the specified country.
- `iso3_code` must be at least 3 characters; only the first 3 are used.

### Mode 4xx — Precision Rounding (no ISO3)

```python
get_OTP(main_key="k", location_mode=403,
        latitude=35.6762, longitude=139.6503)
# Location string → "35.676-139.650"
```

- `xx` = mode value minus 400 (e.g. `403` → 3 decimal places).
- Precision is **capped at 6** to prevent resource abuse.
- `location_mode=400` is allowed and rounds to 0 decimal places.
- `iso3_code` is **not** required and is ignored.

### Mode 5xx — Grid Snapping (no ISO3)

```python
get_OTP(main_key="k", location_mode=520,
        latitude=28.6139, longitude=77.2090)
# Location string → "20-60"  (floored down to a 20° grid)
```

- `xx` = mode value minus 500 (e.g. `520` → 20° grid).
- `location_mode=500` is a degenerate case (step 0): the location segment is
  empty, so the OTP is generated with **no location binding** (no error raised).
- `iso3_code` is **not** required and is ignored.

### Mode 6xx — Precision Rounding with ISO3

```python
get_OTP(main_key="k", location_mode=603, iso3_code="JPN",
        latitude=35.6762, longitude=139.6503)
# Location string → "JPN-35.676-139.650"
```

- `xx` = mode value minus 600 (e.g. `603` → 3 decimal places).
- Precision is **capped at 6** to prevent resource abuse.
- `location_mode=600` is allowed and rounds to 0 decimal places.
- Requires `iso3_code`, `latitude`, and `longitude`.

### Mode 7xx — Grid Snapping with ISO3

```python
get_OTP(main_key="k", location_mode=720, iso3_code="IND",
        latitude=28.6139, longitude=77.2090)
# Location string → "IND-20-60"  (floored down to a 20° grid)
```

- `xx` = mode value minus 700 (e.g. `720` → 20° grid).
- `location_mode=700` is a degenerate case (step 0): the location segment is
  empty, so the OTP is generated with **no location binding** (no error raised).
- Requires `iso3_code`, `latitude`, and `longitude`.

### Negative Modes — Coarse Grid

```python
get_OTP(main_key="k", location_mode=-5, latitude=28.6139, longitude=77.2090)
# Location string → "25-75"
```

- `step = abs(location_mode)` (e.g. `-5` → 5° grid).
- Latitude and longitude are floored down to a multiple of `step`.
- No ISO3 code is used.

### Positive Modes (>0, not 301, not 4xx, not 5xx, not 6xx, not 7xx)

```python
get_OTP(main_key="k", location_mode=3, latitude=28.6139, longitude=77.2090)
# Location string → "28.614-77.209"
```

- Rounds lat/lon to `location_mode` decimal places.
- Precision is **capped at 6**.
- No ISO3 code is used.

---

## Password Modes (`password_str_mode`)

Layers an extra shared secret into the OTP seed.

| Mode | Behaviour | Example |
|------|-----------|---------|
| `0` | Disabled | *(password omitted)* |
| `> 0` | First `N` characters of password | `mode=4, pwd="DelhiSecure"` → `-Delh-` |
| `< 0` | Full password included | `pwd="MyPass"` → `-MyPass-` |

> **Note:** `get_data_dict()` (and therefore `get_OTP_from_dict` /
> `verify_otp_from_dict`) raises `ValueError` when a non-zero
> `password_str_mode` has no `password_string`. Calling `get_OTP`
> directly silently omits the password segment instead.

---

## Hash Algorithms (`algorithm`)

| ID | Name | `algorithm` param |
|----|------|-------------------|
| `0` | SHA‑1 | `0` or `"sha1"` |
| `1` | SHA‑224 | `1` or `"sha224"` |
| `2` | SHA‑256 | `2` or `"sha256"` |
| `3` | SHA‑384 | `3` or `"sha384"` |
| `4` | SHA‑512 | `4` or `"sha512"` |
| `5` | SHA3‑512 | `5` or `"sha3-512"` |

> **Recommendation:** Use SHA‑256 (`2` / `"sha256"`) or stronger for production.

---

## OTP Length (`n_chars`)

| Minimum | Maximum | Default |
|---------|---------|---------|
| 1 | 128 | 6 |

> **Note:** `1`–`128` is the validated range enforced by
> `get_data_dict()` and `get_OTP_uri`. `get_OTP` / `OTP_gen` do not
> enforce it (e.g. `n_chars=0` returns an empty string). Shorter OTPs
> are easier to brute-force — use at least `6` for production.

---

## Time Binning (`time_binning`)

| Minimum | Default |
|---------|---------|
| 1 second | 30 seconds |

Must be a positive integer. The OTP changes every `time_binning` seconds.

---

## Full Arguments Table

| Argument | Type | Default | Description |
|----------|------|---------|-------------|
| `main_key` | `str` | *(required)* | Secret key for HMAC |
| `otp_mode` | `int` | `0` | OTP character set (`0`=digits, `1`=alpha, `2`=alnum) |
| `n_chars` | `int` | `6` | Length of generated OTP (validated range `1`–`128`) |
| `time_binning` | `int` | `30` | Time window in seconds |
| `location_mode` | `int` | `0` | Location encoding strategy |
| `latitude` | `float \| None` | `None` | Latitude (-90 to 90) |
| `longitude` | `float \| None` | `None` | Longitude (-180 to 180) |
| `iso3_code` | `str \| None` | `None` | ISO3 country code (≥3 chars) |
| `password_str_mode` | `int` | `0` | Password mode (`0`=off, `>0`=truncate, `<0`=full) |
| `password_string` | `str \| None` | `None` | Shared password string |
| `algorithm` | `int \| str` | `0` (SHA‑1) | Hash algorithm |
| `now` | `float \| None` | `None` | Explicit timestamp override (for deterministic generation / tests) |
| `use_version` | `str \| None` | `None` | Algorithm version — `None` or any `v1.x` = current line; `v0.1` / `v0.2` = legacy |

---

## Algorithm Versions

Every OTP call is version‑aware. The `use_version` argument (on
`get_OTP`, `get_OTP_from_dict`, `verify_otp`, `verify_otp_from_dict`) and the
`version` parameter (on `get_OTP_uri`, `get_OTP_uri_from_dict`, and recorded
in every `TLSOTP://` URI) select which algorithm family runs.

| Version | Status | Behaviour |
|---------|--------|-----------|
| `v1.0` | **Current** (default) | Live algorithm — 4‑byte chunked `OTP_gen` with SHA‑256 chaining, ISO3‑free 4xx/5xx, location precision capped at 6 decimals |
| `v0.2` | Legacy | Cyclic per‑byte `OTP_gen`, ISO3 **embedded** in 4xx/5xx modes, positive precision **not** capped |
| `v0.1` | Legacy | Identical core to v0.2 |

Version strings are normalized: `"v0.2"`, `"0.2"`, `"0.2.0"` are equivalent.
`None` and any `v1.x` request use the current algorithm; `v0.1` / `v0.2` are
dispatched to `tlsotp.legacy`. Backwards compatibility is **not guaranteed** —
the legacy module reproduces the old releases and is validated against them,
but is *mostly* compatible, not byte‑exact by contract.

---

## URI Format (`TLSOTP://`)

```text
TLSOTP://main_key=KEY&otp_mode=0&n_chars=6&time_binning=30&location_mode=0&password_str_mode=0&algorithm=sha1&version=v1.0
```

- **All** parameters are always present in the URI, even when set to their default values — including the algorithm `version`.
- **Runtime values** (`latitude`, `longitude`, `iso3_code`, `password_string`) are **never** stored in the URI.
- They must be supplied as keyword arguments to `get_otp_from_uri()` or `verify_otp_from_uri()`.
- The `version` recorded in the URI (default `v1.0`) is honored automatically: a URI created with `version="v0.2"` reproduces the legacy algorithm on any TLSOTP install.

### URI function summary

| Function | Purpose |
|----------|---------|
| `get_OTP_uri(...)` | Create a `TLSOTP://` URI from individual args (records `version`, default current line) |
| `get_OTP_uri_from_dict(dict)` | Create a `TLSOTP://` URI from a config dict (honors a `version` key) |
| `get_dict_from_uri(uri)` | Parse a `TLSOTP://` URI back into a config dict (runtime fields are `None`, includes `version`) |
| `get_otp_from_uri(uri, *, iso3_code=..., password_string=...)` | Generate OTP from URI + runtime values (honors URI `version`) |
| `verify_otp_from_uri(otp, uri, *, iso3_code=...)` | Verify OTP from URI + runtime values (honors URI `version`) |

---

## Verification & Drift Tolerance

| Function | Description |
|----------|-------------|
| `verify_otp(main_key, user_otp, drift_windows=1, use_version=None, **kwargs)` | Verify OTP directly (optionally against a legacy version) |
| `verify_otp_from_dict(data_dict, user_otp, drift_windows=1, use_version=None)` | Verify OTP from config dict (honors a `version` key) |
| `verify_otp_from_uri(user_otp, uri, drift_windows=1, *, ...)` | Verify OTP from URI (honors the URI's `version`) |

`drift_windows=1` checks **3** windows: past, current, and future.
`drift_windows=N` checks `2N + 1` windows.

All verification uses **constant-time comparison** (`hmac.compare_digest`)
to prevent timing side-channel attacks.
