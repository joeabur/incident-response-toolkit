# Changelog

## Unreleased

- `verify-manifest --expected-manifest-sha256 HEX` checks `manifest.json` against a hash recorded elsewhere (exit 3 on mismatch).
- Tests now fail if a shipped detection rule has neither a firing test nor a hit on the synthetic case; added positive samples for the rules that had none.

## 0.1.0

Initial release: read-only collectors (inventory, processes, network, persistence incl. launchd, unified logs, files),
evidence manifest and verification, IOC matching, declarative detection rules, JSON/CSV/Markdown reporting, synthetic
fixtures, documentation, and CI.
