# ai-pen-test

ai-pen-test is an LLM-backed semantic static analysis (SAST) tool. It reads a
codebase, sends source files to a language model for semantic review, combines
that with pattern-based detection, and flags likely OWASP Top 10 and CWE issues.
Each finding carries a CVSS severity, a file and line, and a remediation note.
The tool applies false-positive filters before reporting, and writes results as
JSON, HTML, or Markdown. Scanning can run one file at a time or, with `--parallel`,
across several files concurrently over asyncio. A pair of GitHub Actions
workflows run the same engine on pull requests and on a weekly schedule.

This is a defensive code-analysis tool. It reads source; it does not run,
exploit, or reach out to live targets.

## Requirements

- Python 3.9 or newer.
- An `OPENROUTER_API_KEY`, or an `ANTHROPIC_API_KEY`. Every scan makes real
  model API calls, so every scan costs real tokens. Larger codebases and higher
  `--parallel` values cost more.

## Install

```bash
python3 -m venv .venv
source .venv/bin/activate
pip install -e .
```

## Quickstart

The repository ships a local set of intentionally vulnerable code samples and a
smaller set of secure counterparts under `tests/fixtures`. Scan them first. They
are self-contained, reproducible, and reach no external system.

```bash
export OPENROUTER_API_KEY=...
ai-pen-test scan tests/fixtures/vulnerable
```

To scan the vulnerable fixtures and write an HTML report:

```bash
ai-pen-test scan tests/fixtures/vulnerable --report --format html
```

The `tests/fixtures/vulnerable` directory contains 26 flawed samples spanning
authentication, SQL injection, cross-site scripting, IDOR, SSRF, XXE, path
traversal, command injection, deserialization, weak cryptography, and CSRF.
`tests/fixtures/secure` holds five corrected versions for contrast.

## Usage

```
ai-pen-test scan <directory>        Run a SAST code scan
ai-pen-test report <findings.json>  Generate a report from an existing findings file
ai-pen-test init                    Write a starter configuration to ~/.ai-pen-test
ai-pen-test version                 Print the version
ai-pen-test help                    Print help
```

Common `scan` options:

```
--scope {changed_files,full_codebase}   Limit the scan to changed files or run the whole tree
--severity {CRITICAL,HIGH,MEDIUM,LOW,INFO}   Minimum severity to report
--output, -o <file>                      Where to write findings (default: findings.json)
--report, -r                             Also generate a report
--format {html,json,markdown,pdf}        Report format
--parallel, -p <N>                       Number of files to scan concurrently
--api-key <key>                          Pass a key instead of using the environment
```

## Configuration

`ai-pen-test init` writes a starter configuration to `~/.ai-pen-test`. The API
key is read from `OPENROUTER_API_KEY` or `ANTHROPIC_API_KEY` in the environment,
or passed per-command with `--api-key`.

## GitHub Actions

Two workflows in `.github/workflows` run the engine in CI:

- `pen-test-pr.yml` scans the files changed in a pull request, comments the
  findings on the PR, uploads them as an artifact, and fails the check when a
  CRITICAL issue is found.
- `pen-test-scheduled.yml` runs a full scan on a weekly cron and can be
  triggered manually with a chosen severity threshold.

Both read the model key from the `OPENROUTER_API_KEY` repository secret.

## Responsible use

Scan only code you own or have explicit written permission to assess. This tool
is for authorized, defensive security work: reviewing your own codebase,
hardening a project before release, or evaluating open-source code you are
entitled to inspect. Do not use it against systems or code you do not control.

The tool performs static analysis of source files. It does not execute the code
under review, send traffic to running services, or attempt exploitation.

## History

Originally built in November 2025 as a private tool. Published here in 2026 as
a clean-room extraction, with engagement-specific material removed.

## Prior art

The categories, severity model, and review methodology follow well-documented
public standards: the OWASP Top 10, the CWE list, and CVSS. This project claims
no affiliation with, or endorsement by, the organizations behind those
standards.

## Security

To report a vulnerability in ai-pen-test itself, see [SECURITY.md](SECURITY.md).

## License

MIT. Copyright (c) 2026 Ian Kar. See [LICENSE](LICENSE).
