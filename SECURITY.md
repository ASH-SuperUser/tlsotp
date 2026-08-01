# Security Policy

## Supported Versions

Only the latest release is supported with security updates.

| Version | Supported          |
| ------- | ------------------ |
| 1.0.x   | :white_check_mark: |
| < 1.0   | :x:                |

> **Legacy releases.** TLSOTP ships a `legacy` module that reproduces older
> release algorithms (e.g. `v0.1` / `v0.2`) for backward compatibility. It is
> tested against those releases and generally produces the same OTPs — but
> outputs are **not guaranteed** to match in every case. The module exists only
> so existing programs can migrate without breakage; update them to the current
> version as soon as possible. Legacy versions are **not** supported with
> security updates — use the current line for anything new.

## Reporting a Vulnerability

Please **do not** open a public issue for security vulnerabilities.

Instead, report vulnerabilities privately by opening a
[private security advisory][advisories] on GitHub.

Please include:

- A description of the vulnerability and its impact.
- Steps to reproduce it (if possible).
- The affected version(s).

You should receive an acknowledgement within 48 hours. If the issue is
confirmed, a fix will be released as soon as possible and the disclosure will
be coordinated with you.

## Security Notes for Users

- TLSOTP is a **custom, non-RFC** OTP scheme. Use standard TOTP (RFC 6238) if
  authenticator-app interop or compliance is required.
- Store keys with `key_gen(32)` or larger and keep them in a secret store
  (env vars / vault / HSM). Never hardcode keys.
- Enforce rate-limiting and lockout server-side; `verify_otp` alone does not
  protect against online brute-force.
- A `TLSOTP://` URI contains the key — treat it as a secret. Runtime factors
  (latitude, longitude, ISO3 code, password) are intentionally never stored
  in the URI.
- Always serve OTP exchange over TLS.

[advisories]: https://github.com/ASH-SuperUser/tlsotp/security/advisories/new
