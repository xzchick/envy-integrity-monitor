# Changelog

All notable changes to this project. This project adheres to semantic versioning.

## v0.2.3 — 2026-11-24

- Window: one baseline can cover several folders, with optional ignore globs, from a new "New baseline" dialog
- Window: Schedule… shows a ready cron line or launchd job (with the passphrase caveat) and copies it
- Window: Changes view gains a type filter, a change summary, and a Root column for multi-folder baselines
- Offscreen GUI tests that drive the real window
- Add a verified one-line Linux installer (`install.sh`)

## v0.2.2 — 2026-11-16

- Attach a CycloneDX SBOM to each release (covered by the signed checksums)

## v0.2.1 — 2026-11-15

- Sign release checksums with Sigstore (keyless) and attach the `.sigstore.json` bundle
- Add property/fuzz hardening tests for the AES-256-GCM + scrypt envelope

## v0.2.0 — 2026-11-14

- Watch multiple roots in one baseline
- Read exported files as UTF-8 in tests (Windows cp1252 fix)
- Add a schedule helper for cron/launchd checks
- Add --exit-detail bitmask to check for CI gating
- Add Markdown export of the change report
- Persist the ignore globs in the baseline
- Add ignore globs to check
- Add --json output to the check command
- Docs: point install at the live v0.1.0 release

## v0.1.0

- Initial public release.
