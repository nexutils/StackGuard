# StackGuard

Production-readiness scanner for infrastructure and deployment configuration.

[![License](https://img.shields.io/badge/license-Apache--2.0-green)](LICENSE)
[![Go](https://img.shields.io/badge/built%20with-Go-00ADD8)](https://go.dev)

StackGuard checks your Dockerfiles, Compose files, Kubernetes manifests, Helm charts,
Terraform modules, GitHub Actions workflows, Jenkinsfiles, Ansible playbooks and nginx
configs against a built-in set of rules covering security, reliability, performance and
operational best practices. It prints findings with line numbers and gives you a
production-readiness score out of 100.

## What it scans

- Dockerfile
- Docker Compose
- Kubernetes
- Helm
- Terraform
- GitHub Actions
- Jenkins
- Ansible
- nginx

Each target has its own parser and rule set. StackGuard detects file types
automatically — just point it at a directory and it figures out the rest.

## Install

### Homebrew

```sh
brew install nexutils/tap/stackguard
```

### Scoop (Windows)

```sh
scoop bucket add nexutils https://github.com/nexutils/scoop-bucket
scoop install stackguard
```

### Go

```sh
go install github.com/nexutils/StackGuard/cmd/stackguard@latest
```

### From source

```sh
git clone https://github.com/nexutils/StackGuard.git
cd StackGuard
go build -o stackguard ./cmd/stackguard
```

Pre-built binaries for Linux, macOS and Windows are attached to each
[GitHub release](https://github.com/nexutils/StackGuard/releases).

## Quick start

```sh
# scan the current directory
$ stackguard scan .

# scan specific files
$ stackguard scan docker-compose.yml k8s/

# strict profile, fail on warnings
$ stackguard scan . --profile strict --fail-on warning

# output SARIF for CI integration
$ stackguard scan . --format sarif --output results.sarif

# look up a specific rule
$ stackguard explain DOCK_SEC_002
```

## Example output

```
examples/dockerfile/Dockerfile
  ⚠ No .dockerignore was found next to the Dockerfile  DOCK_BUILD_010 · line 1
  ✗ A stage pins only a channel tag, with no digest      DOCK_IMG_002 · line 1
  ⚠ The final image defines no HEALTHCHECK               DOCK_RUNTIME_001 · line 8
  ⚠ The final image sets no USER, so it runs as root      DOCK_SEC_002 · line 8

✓ 45 passed  dockerfile 45
  [###############---------]  45/70 · 64%

Score: 11/100  2 errors · 23 warnings · 0 info
```

## Configuration

Drop a `.stackguard.yaml` in your repo root. StackGuard picks it up automatically.

```yaml
# .stackguard.yaml
disabled_rules:
  - JENK_SEC_001

severity_overrides:
  COMP_REL_001: ERROR
  K8S_REL_003: WARNING

exclude:
  - "**/vendor/**"
  - "*.generated.yaml"

fail_on: ERROR
min_score: 0
```

## Scan profiles

| Profile    | What it does                                                       |
|------------|--------------------------------------------------------------------|
| `quick`    | Runs the highest-signal rules only. Good for local iteration.      |
| `standard` | The default. Covers security, reliability and operational rules.   |
| `strict`   | Everything, including style and informational checks.              |

```sh
stackguard scan . --profile strict
```

## Output formats

| Format  | Flag               | Notes                                                 |
|---------|--------------------|-------------------------------------------------------|
| Console | `--format console` | Default. Colored terminal output.                     |
| JSON    | `--format json`    | Machine-readable. Pipe to jq, feed into dashboards.   |
| SARIF   | `--format sarif`   | Upload to GitHub Code Scanning, VS Code, etc.         |
| HTML    | `--format html`    | Self-contained report you can open in a browser.      |

Use `--output report.json` to write to a file instead of stdout.

## CI usage

### GitHub Actions

```yaml
- name: Run StackGuard
  run: |
    stackguard scan . \
      --format sarif \
      --output stackguard.sarif \
      --fail-on warning

- name: Upload SARIF
  uses: github/codeql-action/upload-sarif@v3
  with:
    sarif_file: stackguard.sarif
```

The exit code is non-zero when findings meet or exceed the `--fail-on` severity,
or when the score drops below `--min-score`. Set `--fail-on none` if you only want
the report without failing the build.

## Custom rules

Point `--rules-dir` at a directory of YAML rule files to add your own policies.
Rules in that directory override built-in rules with the same ID.

```sh
stackguard scan . --rules-dir ./policies
```

See [docs/rule-authoring.md](docs/rule-authoring.md) for the rule format.

## Commands

| Command   | Description                                 |
|-----------|---------------------------------------------|
| `scan`    | Scan files or directories for issues.       |
| `explain` | Show details and remediation for a rule.    |
| `rules`   | List all available rules.                   |
| `score`   | Print the production-readiness score.       |
| `version` | Print version information.                  |

## Contributing

Contributions are welcome. See [CONTRIBUTING.md](CONTRIBUTING.md) for guidelines.

## License

Apache-2.0. See [LICENSE](LICENSE) for the full text.
