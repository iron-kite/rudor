# Contributing to Rudor

Thank you for your interest in contributing to Rudor! This document provides guidelines and instructions for contributing.

## Code of Conduct

By participating in this project, you agree to abide by our [Code of Conduct](CODE_OF_CONDUCT.md).

## How to Contribute

### Reporting Bugs

Before creating a bug report, please check existing issues to avoid duplicates.

When creating a bug report, include:

- **Clear title** describing the issue
- **Steps to reproduce** the behavior
- **Expected behavior** vs actual behavior
- **Environment details** (OS, Go version, Rudor version)
- **Logs or error messages** (if applicable)

### Suggesting Features

Feature requests are welcome! Please provide:

- **Clear description** of the proposed feature
- **Use case** explaining why this feature would be useful
- **Possible implementation** approach (optional)

### Pull Requests

1. **Fork the repository** and create your branch from `main`
2. **Follow the commit convention** (see below)
3. **Add tests** for new functionality
4. **Ensure CI passes** before requesting review
5. **Update documentation** if needed

## Development Setup

### Prerequisites

- Go 1.24 or later
- Docker (for testing container builds)
- Git

### Building from Source

```bash
# Clone the repository
git clone https://github.com/iron-kite/rudor.git
cd rudor

# Build the binary
cd src
go build -o ../rudor .

# Run tests
go test ./...
```

### Running Linters

```bash
# Install golangci-lint
go install github.com/golangci/golangci-lint/cmd/golangci-lint@latest

# Run linter
cd src
golangci-lint run
```

### Security Scanning

```bash
# Install security tools
go install github.com/securego/gosec/v2/cmd/gosec@latest
go install golang.org/x/vuln/cmd/govulncheck@latest

# Run security scans
cd src
gosec ./...
govulncheck ./...
```

## Commit Convention

We use [Conventional Commits](https://www.conventionalcommits.org/) for clear and organized history.

### Format

```
<type>: <Subject>

[optional body]

[optional footer]
```

### Types

| Type       | Description                                      |
|------------|--------------------------------------------------|
| `feat`     | New feature                                      |
| `fix`      | Bug fix                                          |
| `perf`     | Performance improvement                          |
| `docs`     | Documentation changes                            |
| `test`     | Adding or updating tests                         |
| `refactor` | Code refactoring (no feature/fix)                |
| `chore`    | Maintenance tasks                                |
| `ci`       | CI/CD changes                                    |
| `build`    | Build system or dependency changes               |

### Examples

```bash
# Feature
git commit -m "feat: Add support for Rust projects"

# Bug fix
git commit -m "fix: Resolve parsing error for Go modules"

# Performance
git commit -m "perf: Optimize CVE scanning with parallel requests"

# Documentation
git commit -m "docs: Update installation instructions"
```

### Rules

- Subject line must start with **uppercase letter**
- Subject line must be **50 characters or less**
- Do not end subject line with a period
- Use imperative mood ("Add feature" not "Added feature")

## Pull Request Process

### Branch Naming

Use descriptive branch names:

- `feature/add-rust-support`
- `fix/parsing-error`
- `docs/update-readme`

### PR Title

PR titles must follow the same commit convention format:

```
feat: Add support for Rust projects
fix: Resolve parsing error for Go modules
```

### PR Description

Include:

- **Summary** of changes
- **Motivation** for the change
- **Testing** performed
- **Breaking changes** (if any)

### Review Process

1. All PRs require at least one approval
2. CI must pass before merging
3. Address all review comments
4. Squash commits when merging (unless commits are meaningful)

## Release Process

Releases are automated via GitHub Actions when version tags are pushed:

```bash
# After your PR is merged
git checkout main
git pull origin main
git tag v1.2.0
git push origin v1.2.0
```

The release workflow will:

- Build binaries for all platforms
- Generate checksums
- Create GitHub release with changelog
- Push Docker images to GHCR

## Project Structure

```
rudor/
├── .github/
│   ├── actions/          # Composite GitHub Actions
│   └── workflows/        # CI/CD workflows
├── src/
│   ├── main.go           # CLI entry point
│   ├── sbom.go           # SBOM generation logic
│   ├── cve.go            # CVE scanning logic
│   ├── embed_*.go        # Platform-specific binary embedding
│   └── resources/        # Embedded binaries
├── .goreleaser.yaml      # Release configuration
├── Dockerfile            # Container build
└── README.md             # Documentation
```

## Getting Help

- **Issues**: Open a GitHub issue for bugs or features
- **Discussions**: Use GitHub Discussions for questions
- **Email**: Contact info@ironkite.com for other inquiries

## License

By contributing, you agree that your contributions will be licensed under the MIT License.