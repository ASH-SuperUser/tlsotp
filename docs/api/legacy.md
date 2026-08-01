# Legacy API

Mostly compatible reproduction of the OTP algorithms shipped in the `v0.1.0`
and `v0.2.0` releases. Use it directly, or let the version‑aware entry points
(`get_OTP(..., use_version="v0.2")`, URIs with `version=v0.2`) dispatch for you.

Backwards compatibility is **not guaranteed** — the module is validated against
the original releases but is *mostly* compatible, not byte‑exact by contract.

::: tlsotp.legacy
    options:
      show_source: true
      show_root_heading: true
      show_signature: true
      members_order: source
