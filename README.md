# rediver-semgrep

[Rediver](https://rediver.ai) integration for [Semgrep](https://semgrep.dev/) SAST scanner.

Scans git repositories for security vulnerabilities, code quality issues, and best practice violations, then reports findings to the Rediver platform.

## Quick Start

### Docker (recommended)

```bash
docker run --rm \
  -e REDIVER_TOKEN=your-cluster-token \
  -e MODE=ci \
  ghcr.io/califio/rediver-semgrep:latest
```

### Binary

```bash
go install github.com/califio/rediver-semgrep@latest

REDIVER_TOKEN=your-cluster-token rediver-semgrep
```

## Getting REDIVER_TOKEN

1. Log in to [Rediver](https://app.rediver.ai)
2. Go to **Agent Clusters** page: `https://app.rediver.ai/tenant/{your-tenant}/agents`
3. Create a new agent cluster (or select an existing one)
4. Copy the generated token — this is your `REDIVER_TOKEN`

## Configuration

All options can be set via CLI flags or environment variables.

| Env Variable | Flag | Default | Description |
|-------------|------|---------|-------------|
| `REDIVER_URL` | `--url` | `https://api.rediver.ai` | Rediver API URL |
| `REDIVER_TOKEN` | `--token` | _(required)_ | Cluster authentication token |
| `MODE` | `--mode` | `ci` | Run mode: `worker`, `ci`, or `task` |
| `MAX_CONCURRENT_JOB` | `--max-concurrent-job` | `1` | Max parallel scan jobs |
| `POLLING_INTERVAL` | `--polling-interval` | `10` | Poll interval in seconds (worker mode) |
| `REPO_DIR` | `--repo-dir` | | Override repository directory |
| `SEMGREP_CONFIG` | `--semgrep-config` | `auto` | Semgrep ruleset or path |

### Run Modes

- **`worker`** — Long-running process that polls for scan jobs
- **`ci`** — Auto-detects CI environment, scans the current repo, exits
- **`task`** — Runs a single assigned job, then exits

### Semgrep Config

The `semgrep_config` parameter accepts any valid semgrep config value:

| Value | Description |
|-------|-------------|
| `auto` | Semgrep's recommended rules (default) |
| `p/default` | Default ruleset |
| `p/owasp-top-ten` | OWASP Top 10 rules |
| `p/security-audit` | Security audit rules |
| `path/to/rules.yaml` | Custom rules file |

## Scanner Parameters

These parameters are configurable per scan job from the Rediver platform:

| Parameter | Type | Default | Description |
|-----------|------|---------|-------------|
| `semgrep_config` | string | `auto` | Semgrep ruleset or path |

## Severity Mapping

Semgrep findings are mapped to Rediver severity levels using both severity and impact:

| Semgrep Severity | Impact | Rediver Severity |
|-----------------|--------|-----------------|
| ERROR | HIGH | High |
| ERROR | MEDIUM/LOW | Medium |
| WARNING | HIGH | Medium |
| WARNING | MEDIUM/LOW | Low |
| NOTE/INFO | any | Info |

## CI/CD Integration

### GitHub Actions

Add to `.github/workflows/semgrep.yml` in your repository:

```yaml
name: SAST Scan

on:
  push:
    branches: [main]
  pull_request:
    branches: [main]

jobs:
  semgrep:
    runs-on: ubuntu-latest
    container:
      image: ghcr.io/califio/rediver-semgrep:latest
      env:
        REDIVER_TOKEN: ${{ secrets.REDIVER_TOKEN }}
        MODE: ci
```

To use a custom semgrep ruleset:

```yaml
jobs:
  semgrep:
    runs-on: ubuntu-latest
    container:
      image: ghcr.io/califio/rediver-semgrep:latest
      env:
        REDIVER_TOKEN: ${{ secrets.REDIVER_TOKEN }}
        MODE: ci
        SEMGREP_CONFIG: p/owasp-top-ten
```

### GitLab CI

Add to `.gitlab-ci.yml` in your repository:

```yaml
semgrep:
  stage: test
  image:
    name: ghcr.io/califio/rediver-semgrep:latest
    entrypoint: [""]
  variables:
    REDIVER_TOKEN: $REDIVER_TOKEN
    MODE: ci
  script:
    - /usr/bin/rediver-semgrep
  rules:
    - if: $CI_PIPELINE_SOURCE == "merge_request_event"
    - if: $CI_COMMIT_BRANCH == $CI_DEFAULT_BRANCH
```

To use a custom semgrep ruleset:

```yaml
semgrep:
  stage: test
  image:
    name: ghcr.io/califio/rediver-semgrep:latest
    entrypoint: [""]
  variables:
    REDIVER_TOKEN: $REDIVER_TOKEN
    MODE: ci
    SEMGREP_CONFIG: p/owasp-top-ten
  script:
    - /usr/bin/rediver-semgrep
  rules:
    - if: $CI_PIPELINE_SOURCE == "merge_request_event"
    - if: $CI_COMMIT_BRANCH == $CI_DEFAULT_BRANCH
```

> **Note:** Add `REDIVER_TOKEN` as a CI/CD variable in your project settings (GitHub: repository secrets, GitLab: Settings → CI/CD → Variables).

## Development

```bash
# Run tests
go test -v ./...

# Build
go build -o rediver-semgrep

# Run locally with .env
cp .env.example .env  # edit with your token
go run .
```

## License

Proprietary — see [Rediver](https://rediver.ai) for licensing details.
