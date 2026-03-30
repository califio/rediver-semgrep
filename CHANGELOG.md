# Changelog

All notable changes to this project will be documented in this file.

The format is based on [Keep a Changelog](https://keepachangelog.com/en/1.1.0/),
and this project adheres to [Semantic Versioning](https://semver.org/spec/v2.0.0.html).

## [0.0.5] - 2026-03-30

### Changed
- Bump rediver-sdk-go v1.2.6 → v1.2.7: resolve HEAD SHA after clone for jobs without CommitSHA

## [0.0.4] - 2026-03-30

### Changed
- Bump rediver-sdk-go v1.2.5 → v1.2.6: fallback to branch checkout when CommitSHA is empty

## [0.0.3] - 2026-03-29

### Fixed
- Finding file paths included temp directory prefix (e.g. `/tmp/repo_XXXX/src/...`) instead of relative paths

## [0.0.2] - 2026-03-26

### Fixed
- Semgrep stderr not captured — error messages were always empty on exit code 2+

## [0.0.1] - 2026-03-09

### Added
- SAST scanner using [semgrep](https://semgrep.dev/)
- Run modes: `worker` (long-running poll loop), `ci` (auto-detect CI, scan, exit), `task` (single job, exit)
- Configurable semgrep ruleset via `semgrep_config` parameter (default: `auto`)
- Severity mapping combining semgrep severity + impact for accurate prioritization
- CWE and OWASP reference extraction from semgrep metadata
- Multi-stage Docker build (golang:1.25 → python:3.12-slim + semgrep)
- GitHub Actions CI/CD: test → build & push to GHCR → create GitHub Release on tag
- Multi-platform Docker images (linux/amd64, linux/arm64)
- Semantic version tagging (v1.2.3 → `1.2.3`, `1.2`, `1`, `latest`)
- Built on [rediver-sdk-go v1.0.0](https://github.com/califio/rediver-sdk-go)
- CLI powered by [Kong](https://github.com/alecthomas/kong)
