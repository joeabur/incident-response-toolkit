# Changelog

## Unreleased

- `Test-IREvidenceManifest -ExpectedManifestSha256` and `winir.ps1 -Command Verify -ExpectedManifestSha256` check `manifest.json` against a hash recorded elsewhere (exit 3 on mismatch, 2 if malformed).
- Tests now fail if a shipped detection rule has neither a firing test nor a hit on the synthetic case; added positive samples for the rules that had none.

## 0.1.0

Initial release: read-only collectors (host, processes, network, accounts, persistence, events), SHA-256 evidence
manifest and verification, JSON IOC matching, declarative JSON detection rules, JSON/CSV/safely escaped HTML reports,
synthetic sample data, Pester tests, documentation and CI.
