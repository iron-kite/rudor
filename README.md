# Rudor

A lightweight CLI tool for generating Software Bill of Materials (SBOM) using embedded cdxgen binaries. Rudor simplifies SBOM generation by bundling cdxgen directly into a single executable, eliminating the need for Node.js or external dependencies.

## Features

- 📦 **Zero Dependencies** - Single executable with embedded cdxgen binary
- 🚀 **Cross-Platform** - Works on Windows, Linux, and macOS
- 🔍 **Auto-Detection** - Automatically detects project types
- 📋 **CycloneDX Format** - Generates industry-standard SBOM format
- 🛡️ **CVE Detection** - Automatic vulnerability scanning using OSV database
- ⚡ **Simple CLI** - Intuitive command-line interface

## Installation

### Using Docker

Pull the pre-built multi-architecture Docker image:
```bash
docker pull ghcr.io/iron-kite/rudor:latest
```

### Download Binary

Download the latest release for your platform from the [releases page](https://github.com/iron-kite/rudor/releases).

### Build from Source

```bash
git clone https://github.com/iron-kite/rudor.git
cd rudor
go build -o rudor
```

## Usage

### Basic SBOM Generation

Generate SBOM for the current directory:
```bash
rudor generate
```

Generate SBOM for a specific project:
```bash
rudor generate /path/to/project
```

### Options

- `-o, --output <path>` - Output file path (default: `bom.json`)
- `-t, --type <type>` - Project type (auto-detected if not specified)
- `-v, --verbose` - Enable verbose output
- `-n, --no-cve` - Disable automatic CVE vulnerability scanning

### Examples

Generate SBOM with custom output file:
```bash
rudor generate -o my-sbom.json
```

Generate SBOM for a specific project type:
```bash
rudor generate -t dotnet /path/to/project
```

Enable verbose output for debugging:
```bash
rudor generate -v
```

Disable CVE scanning (only generate SBOM):
```bash
rudor generate --no-cve
```

### Using Docker

Run Rudor using the pre-built Docker image (supports both ARM64 and AMD64):

Generate SBOM for the current directory:
```bash
docker run --rm -v $(pwd):/workspace -w /workspace ghcr.io/iron-kite/rudor:latest generate
```

Generate SBOM with custom output file:
```bash
docker run --rm -v $(pwd):/workspace -w /workspace ghcr.io/iron-kite/rudor:latest generate -o my-sbom.json
```

Scan a specific subdirectory:
```bash
docker run --rm -v $(pwd):/workspace -w /workspace ghcr.io/iron-kite/rudor:latest generate /workspace/my-project
```

Run with all options:
```bash
docker run --rm -v $(pwd):/workspace -w /workspace ghcr.io/iron-kite/rudor:latest generate -v -o sbom.json -t python
```

If you encounter permission issues with output files, run with your user ID:
```bash
docker run --rm --user $(id -u):$(id -g) -v $(pwd):/workspace -w /workspace ghcr.io/iron-kite/rudor:latest generate
```

Build the Docker image locally:
```bash
docker build -t rudor:latest .

# Multi-architecture build
docker buildx build --platform linux/amd64,linux/arm64 -t rudor:latest .
```

## GitHub Action

Rudor is available as a GitHub Action for seamless integration into your CI/CD pipelines.

### Basic Usage

```yaml
- name: Generate SBOM
  uses: iron-kite/rudor@v1
```

### Full Configuration

```yaml
- name: Generate SBOM and scan for vulnerabilities
  uses: iron-kite/rudor@v1
  id: rudor
  with:
    # Path to scan (default: '.')
    path: '.'

    # Output file path (default: 'bom.json')
    output: 'sbom.json'

    # Project type - auto-detected if not specified
    # Options: dotnet, nodejs, python, java, go, rust, etc.
    project-type: ''

    # Disable CVE vulnerability scanning (default: 'false')
    disable-cve: 'false'

    # Enable verbose output (default: 'false')
    verbose: 'false'

    # Fail if vulnerabilities at or above severity found
    # Options: critical, high, medium, low (default: '' - no failure)
    fail-on-severity: 'high'

    # Upload SBOM as artifact (default: 'false')
    upload-sbom: 'true'

    # Upload CVE report as artifact (default: 'false')
    upload-cve-report: 'true'

    # Generate GitHub job summary (default: 'true')
    summary: 'true'
```

### Outputs

| Output | Description |
|--------|-------------|
| `sbom-path` | Path to the generated SBOM file |
| `vulnerabilities-found` | Whether vulnerabilities were found (`true`/`false`) |
| `critical-count` | Number of critical severity vulnerabilities |
| `high-count` | Number of high severity vulnerabilities |
| `medium-count` | Number of medium severity vulnerabilities |
| `low-count` | Number of low severity vulnerabilities |

### Examples

#### Generate SBOM and fail on critical vulnerabilities

```yaml
jobs:
  security-scan:
    runs-on: ubuntu-latest
    steps:
      - uses: actions/checkout@v4

      - name: Generate SBOM
        uses: iron-kite/rudor@v1
        with:
          fail-on-severity: 'critical'
          upload-sbom: 'true'
          upload-cve-report: 'true'
```

#### Use outputs in subsequent steps

```yaml
jobs:
  security-scan:
    runs-on: ubuntu-latest
    steps:
      - uses: actions/checkout@v4

      - name: Generate SBOM
        uses: iron-kite/rudor@v1
        id: rudor

      - name: Check results
        run: |
          echo "SBOM: ${{ steps.rudor.outputs.sbom-path }}"
          echo "Vulnerabilities found: ${{ steps.rudor.outputs.vulnerabilities-found }}"
          echo "Critical: ${{ steps.rudor.outputs.critical-count }}"
          echo "High: ${{ steps.rudor.outputs.high-count }}"
```

#### Scan specific subdirectory

```yaml
- name: Generate SBOM for backend
  uses: iron-kite/rudor@v1
  with:
    path: './backend'
    output: 'backend-sbom.json'
    project-type: 'go'
```

## Supported Project Types

Rudor leverages cdxgen's extensive project type support, including:

- .NET / C# projects
- Node.js / JavaScript
- Python
- Java / Maven / Gradle
- Go
- Rust
- Ruby
- PHP
- And many more...

## How It Works

Rudor embeds platform-specific cdxgen binaries as resources within the CLI executable. When you run a command:

1. The appropriate cdxgen binary is extracted to a temporary location
2. Cdxgen is executed with your specified parameters
3. The SBOM is generated in CycloneDX format
4. Components are automatically scanned for vulnerabilities using the OSV API
5. A CVE report is generated showing security findings by severity
6. Temporary files are automatically cleaned up

### CVE Vulnerability Scanning

By default, Rudor automatically checks all components in your SBOM for known vulnerabilities using the [OSV (Open Source Vulnerabilities)](https://osv.dev/) database. The scanner:

- Uses Package URLs (PURLs) from the SBOM for accurate component identification
- Performs parallel vulnerability checks for fast scanning
- Queries the OSV API for real-time vulnerability data
- Categorizes findings by severity: Critical, High, Medium, and Low
- Generates a detailed JSON report (`cve-report.json`) with all findings
- Displays a summary with color-coded severity indicators

The vulnerability report includes:
- CVE/vulnerability identifiers
- Affected components and versions
- Severity ratings and CVSS scores
- Vulnerability descriptions
- Reference links for remediation

## Requirements

- Go 1.21+ (for building from source)
- No external dependencies required for the compiled executable

## Development

### Release Process

Rudor uses automated semantic versioning with GoReleaser. Releases are triggered by pushing version tags to the repository.

**Creating a new release:**

```bash
# Create and push a version tag
git tag v1.0.0
git push origin v1.0.0
```

The GitHub Actions workflow will automatically:
- Build binaries for all supported platforms (Linux, macOS amd64/arm64, Windows)
- Generate checksums
- Create a GitHub release with changelog
- Upload all artifacts

**Commit Convention**

To maintain a clean and organized changelog, please follow conventional commit format:

- `feat:` - New features (e.g., `feat: add JSON output format`)
- `fix:` - Bug fixes (e.g., `fix: resolve parsing error for Go modules`)
- `perf:` - Performance improvements (e.g., `perf: optimize CVE scanning`)
- `docs:` - Documentation changes (e.g., `docs: update installation guide`)
- `chore:` - Maintenance tasks (e.g., `chore: update dependencies`)
- `test:` - Test additions or changes (e.g., `test: add unit tests for SBOM parser`)

Commits with `feat:`, `fix:`, and `perf:` prefixes will be automatically included in the release changelog, grouped by category.

**Example workflow:**
```bash
# Create a feature branch
git checkout -b feature/rust-support

# Make changes
git add .
git commit -m "feat: add support for Rust projects"
git push origin feature/rust-support

# Open a pull request with a conventional commit title
# PR title: "feat: Add support for Rust projects"

# After PR is merged to main, create a release
git checkout main
git pull origin main
git tag v1.1.0
git push origin v1.1.0
```

### CI/CD Pipeline

The project uses GitHub Actions for continuous integration:

- **Lint**: Code quality checks with golangci-lint
- **Build**: Cross-platform compilation for all supported architectures
- **Docker**: Multi-architecture Docker image builds (linux/amd64, linux/arm64)
- **Security**: Static analysis with Gosec and Trivy
- **Dependency Check**: Vulnerability scanning with govulncheck
- **Release**: Automated releases with GoReleaser on version tags

## License

See the [LICENSE](LICENSE) file for details.

## Acknowledgments

- Built on top of [cdxgen](https://github.com/CycloneDX/cdxgen) by CycloneDX
- Uses [Cobra](https://github.com/spf13/cobra) for CLI parsing

## Support

For issues, questions, or suggestions, please open an issue on the [GitHub repository](https://github.com/iron-kite/rudor/issues).