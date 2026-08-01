# Changelog

All notable changes to this project will be documented in this file.

The format is based on [Keep a Changelog](https://keepachangelog.com/en/1.1.0/),
and this project adheres to [Semantic Versioning](https://semver.org/spec/v2.0.0.html).

## [Unreleased]

### ➕ Added — algorithm versions & legacy compatibility

- **Version-aware OTP calls.** `get_OTP`, `get_OTP_from_dict`, `verify_otp`, and
  `verify_otp_from_dict` accept a `use_version` parameter. `None` (default) and
  any `v1.x` request use the current algorithm; `v0.1` / `v0.2` route to the
  legacy implementation.
- **Version-aware URIs.** `get_OTP_uri` / `get_OTP_uri_from_dict` take a
  `version` parameter (default: current line) and every `TLSOTP://` URI now
  records `version=v1.0`. `get_otp_from_uri` / `verify_otp_from_uri` and
  `get_dict_from_uri` honor the recorded version automatically; URIs without a
  `version` parameter still parse (defaulting to the current line).
- **New `tlsotp.legacy` module.** Reproduces the `v0.1.0` / `v0.2.0` algorithms
  so OTPs minted by older releases keep verifying after upgrading:
  `get_otp_legacy`, `supported_legacy_versions`, `normalize_version`,
  `is_current_version`, and per-version classes.
- **Version normalization.** Version strings like `"0.2"`, `"v0.2"`,
  `"v0.2.0"` are normalized to the two-level form `v<major>.<minor>`.

> **Compatibility note.** The `legacy` module is validated against the original
> `v0.1.0` / `v0.2.0` releases across millions of configurations, but backwards
> compatibility is **not guaranteed** — it is *mostly* compatible. Legacy 4xx/5xx
> location modes require `iso3_code`, and positive location precision is not
> capped at 6 decimals as in v1.0.

## [1.0.0] - 2026-07-31

### ⚠️ Breaking changes

- **OTP output changed.** `OTP_gen` was rewritten from a `(value * size) // 256`
  mapping with cyclic input reuse to 4-byte big-endian chunking with SHA-256
  chaining. For the **same key and time window**, v1.0.0 produces a
  **different OTP than v0.2.0**. OTPs minted under v0.2.0 will **not** verify
  under v1.0.0 — re-enrol any stored codes.
- **Location modes `4xx`/`5xx` no longer embed the ISO3 code.** They now emit
  `lat-lon` only. The ISO3-combined variants moved to the new **`6xx`**
  (precision + country) and **`7xx`** (grid + country) modes. Configs that
  passed `iso3_code` together with `4xx`/`5xx` now produce different OTPs.
- **`get_OTP_from_dict` now validates through `get_data_dict`.** Configs that
  are missing mode-required arguments (e.g. `iso3_code` for `location_mode=301`)
  now raise `ValueError` instead of silently generating.
- **`get_OTP_from_dict` raises `TypeError`** (was `ValueError`) for non-dict
  input.

### ➕ Added functions

- **`verify_otp(main_key, user_otp, drift_windows=1, **kwargs) -> bool`** —
  constant-time verification across `2N+1` time windows using
  `hmac.compare_digest`.
- **`verify_otp_from_dict(data_dict, user_otp, drift_windows=1) -> bool`** —
  verify from a config dict.
- **`verify_otp_from_uri(user_otp, uri, drift_windows=1, *, ...) -> bool`** —
  verify from a `TLSOTP://` URI plus runtime values.
- **`get_OTP_uri(main_key, otp_mode=0, n_chars=6, time_binning=30,
  location_mode=0, password_str_mode=0, algorithm=0) -> str`** — serialize
  static config into a `TLSOTP://` URI (runtime secrets excluded).
- **`get_OTP_uri_from_dict(data_dict) -> str`** — build a URI from a config dict.
- **`get_dict_from_uri(uri) -> dict`** — parse a URI back into a config dict
  (runtime fields → `None`).
- **`get_otp_from_uri(uri, *, latitude=None, longitude=None, iso3_code=None,
  password_string=None, override_dict=None, adder_dict=None) -> str`** — generate
  an OTP from a URI plus runtime values, with override/adder support.
- New **location modes `6xx`/`7xx`** (precision/grid rounding **with** ISO3
  country) in `location_str`/`get_OTP`/`get_data_dict`.

### ➕ Added parameters

- **`now` parameter** on `time_str`, `get_time_OTP`, and `get_OTP` — explicit
  timestamp for testing and `T0`-style offsets.
- **`now` support in `verify_otp`** via `**kwargs`.
- **`override_dict` / `adder_dict`** on `get_otp_from_uri` for merging runtime
  config on top of a parsed URI.

### ➕ Added behaviour / improvements

- **Location precision capped at 6 decimal places** in all `4xx`/`6xx`/positive
  modes to prevent resource abuse.
- **Mode-100/200-style validation**: grid modes `5xx`/`7xx` with step 0
  (`500`/`700`) return an empty location string instead of dividing by zero.
- **`get_data_dict`** now requires `password_str_mode` to be an `int` when
  non-zero, and validates `6xx`/`7xx` argument requirements.
- **`OTP_gen` modulo bias reduced** to ≈10⁻⁹–10⁻⁸ per char (~10⁵× smaller than
  RFC 4226 truncation).
- **Constant-time verification** built in via `hmac.compare_digest`.
- **Deterministic, non-cyclic digest expansion** (SHA-256 chaining) for OTPs
  longer than a single digest.

### ➖ Removed functions

Replaced by the URI-based sharing API (`get_OTP_uri*`, `get_dict_from_uri`,
`get_otp_from_uri`, `verify_otp_from_uri`):

- **`get_shareable_dict(data_dict) -> dict`** — removed.
- **`get_shareable_str(data_dict) -> str`** — removed.
- **`get_OTP_from_shareable_str(...)`** — removed.

> Migration: `get_shareable_str(config)` ≈ `get_OTP_uri(**shareable_keys)` and
> `get_OTP_from_shareable_str(s)` ≈ `get_otp_from_uri(s, ...)`.

### 🔧 Other changes

- **Fixed wheel packaging** — build config corrected to
  `packages = ["src/tlsotp"]`; wheels now ship the `tlsotp` package. The v0.2.0
  wheel shipped metadata only, making `import tlsotp` fail after `pip install`.
- **Typing** — `mypy src` now passes (added `list[str]`, `-> str` on `key_gen`,
  `**kwargs: Any` on `verify_otp`); added `[tool.mypy]` config.
- **Docs** — corrected stale source-line references in
  `docs/comparison-with-totp.md`; removed dead config from `pyproject.toml`.
- **Repo** — added `CHANGELOG.md`, `SECURITY.md`, `CONTRIBUTING.md`, and a
  GitHub Actions CI workflow (pytest, ruff, mypy, mkdocs, wheel) across Python
  3.8–3.13 on Linux, Windows, and macOS.

## [0.2.0] - 2026-05-08

Changes relative to the hosted **v0.1.0** initial release
([PyPI](https://pypi.org/project/tlsotp/) /
[GitHub](https://github.com/ASH-SuperUser/tlsotp)).

### ➕ Added functions

- **`get_shareable_dict(data_dict) -> dict`** — create a minimal shareable
  config dict, stripping runtime/sensitive values (`latitude`, `longitude`,
  `password_string`) so the result can be safely stored or transmitted.
- **`get_shareable_str(data_dict) -> str`** — serialize the shareable config
  as a JSON string.
- **`get_OTP_from_shareable_str(shareable_str, override_dict=None,
  adder_dict=None) -> str`** — regenerate an OTP from a JSON shareable config,
  with `override_dict` (forcibly replace keys) and `adder_dict` (only add
  missing keys) support.

### ➕ Added documentation

- Google-style docstrings added to the existing public functions
  (`key_gen`, `get_data_dict`, `get_OTP_from_dict`).

### 🔧 Other changes

- Version bumped `0.1.0` → `0.2.0` (in `pyproject.toml` and `__init__.py`).
- Development status classifier changed from `4 - Beta` to
  `5 - Production/Stable`.

### ➖ Removed functions

- None — the v0.1.0 public API is fully preserved.

## [0.1.0] - 2026-04-26

Initial release on PyPI.

Public API: `key_gen`, `get_data_dict`, `get_OTP_from_dict`, plus the
core primitives `OTP_gen`, `time_str`, `location_str`, `password_str`,
`get_time_OTP`, and `get_OTP`.

[1.0.0]: https://github.com/ASH-SuperUser/tlsotp/releases/tag/v1.0.0
[0.2.0]: https://github.com/ASH-SuperUser/tlsotp/releases/tag/v0.2.0
[0.1.0]: https://github.com/ASH-SuperUser/tlsotp/releases/tag/v0.1.0
