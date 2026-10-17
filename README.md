# Incident Response Toolkit

Three **read-only**, open-source toolkits for authorised incident-response triage, one per operating system. Each collects
host evidence, inspects persistence, matches IOCs, applies explainable detection rules, verifies evidence integrity with a
SHA-256 manifest, and writes reports. They share one design so that evidence from any platform is analysed the same way.

| Toolkit | Language | Folder | Start here |
|---|---|---|---|
| **Linux** (`linux-ir-toolkit`) | Python ≥ 3.11 (stdlib-first; PyYAML only) | [`linux/`](linux) | [README](linux/README.md) · [walkthrough](linux/docs/walkthrough.md) |
| **macOS** (`macos-ir-toolkit`) | Python ≥ 3.11 | [`macos/`](macos) | [README](macos/README.md) · [walkthrough](macos/docs/walkthrough.md) |
| **Windows** (`WinIRToolkit`) | PowerShell 5.1 / 7 | [`windows/`](windows) | [README](windows/README.md) · [walkthrough](windows/docs/walkthrough.md) |

## Shared principles

- **Read-only.** No process killing, remediation, setting changes, privilege escalation, evidence upload, or execution of
  discovered files/commands/IOC content. The tools never call `sudo`/elevate themselves.
- **Honest coverage.** Every collector records what it could *not* read (permission, missing utility, protected location). Reports
  separate confirmed observations, heuristic findings, IOC matches, collection errors and areas not assessed. **No findings is
  never "clean".**
- **Integrity.** New owner-only output directories, exclusive file creation, SHA-256 manifest and `verify` command. A manifest
  stored beside evidence is not tamper-proof: store its hash elsewhere.
- **Explainable detections.** Declarative rules (data, not code) with stable IDs, separate severity and confidence, known false
  positives, next steps and ATT&CK mapping only where justified.
- **Synthetic demos.** Every toolkit ships invented evidence (RFC 5737 IPs, `*.example.test`, a harmless text file instead of
  malware) and a walkthrough that needs no elevated privileges, production data or network access.

## Validation status (what was and was not run)

| | Linux | macOS | Windows |
|---|---|---|---|
| Automated tests | pytest: passing locally (Python 3.13) and in CI (Ubuntu x64/arm64, Python 3.11-3.13) | pytest: passing locally on Linux; macOS-only tests passing in CI on `macos-latest` and `macos-15-intel` (Python 3.11-3.13) | 109 unit tests passing locally through the bundled subset runner (PowerShell 7.4 / Linux) and in CI through real Pester on Windows PowerShell 5.1 and PowerShell 7 (Windows, macOS, Ubuntu) |
| Lint / type checks | Ruff, mypy: passing | Ruff, mypy: passing | PSScriptAnalyzer: passing in CI |
| Live collection on the target OS | Run on an Ubuntu 24.04 container (root, non-systemd) | Integration tests run on GitHub-hosted macOS runners only; **not tried on a real investigation target or every macOS version** | Integration tests run on GitHub-hosted Windows runners (PowerShell 5.1 and 7) only; **not tried on a real investigation target, other Windows versions or elevated** |
| Synthetic walkthrough commands | Run | Run (on Linux) | Run (on PowerShell 7 / Linux) |
| GitHub Actions | Executed on the pull request; all jobs green at merge (dependency-review skipped, see below) | Same | Same |

See each toolkit's `docs/security-and-limitations.md` for details and blind spots.

The `dependency-review` jobs are skipped until the repository's dependency graph is enabled and the repository variable
`DEPENDENCY_REVIEW_ENABLED` is set to `true`; `pip-audit` and secret scanning run regardless.

## Repository layout

```
incident-response-toolkit/
├── linux/    macos/    windows/        one self-contained project each (src, tests, docs, examples, scripts)
└── README.md                           this file
```

CI definitions live in [`.github/workflows/`](.github/workflows) (`*-tests.yml`, `*-security.yml` per toolkit).

## Use responsibly

Only use these tools on systems you are authorised to investigate. Collected data contains personal and organisational
information: handle it under your organisation's policies and never commit it to version control.
