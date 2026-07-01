CHANGELOG
=========

All notable changes to obsigil (the pure-Python implementation) will
be documented in this file.

The format is based on [Keep a Changelog](https://keepachangelog.com/),
but note that pre-1.0 releases may not adhere strictly to all
guidelines. Releases before 0.2.0 predate this changelog; see the
`v*` git tags.


[Unreleased]
------------


[0.2.0] - 2026-07-01
--------------------

Hex is now the default key representation, aligning with the spec's
Key format (§6.2) and the sibling oboron package. No wire-format
change: keys never appear on the wire, so existing tokens are
unaffected.

### Breaking

- `generate_key()` now returns a `str` — a fresh key as 128 lowercase
  hex digits, the form to store as a secret (an environment variable)
  — instead of `bytes`. Use `generate_key_bytes()` for the raw 64
  bytes.

### Added

- `generate_key_bytes()` returns a fresh key as 64 raw bytes (the
  raw-octet alternative to `generate_key`).
- `mint` and `clauses` (and the `Obsigil` view, `clauses_unchecked`,
  `mandate_plaintext`) accept a mandate key as a canonical hex string
  (the default) or as raw bytes. A malformed key raises a distinct
  `ValueError` — a configuration error, never the uniform
  `ObsigilError` a bearer sees.
