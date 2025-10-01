# Rudor

A lightweight CLI tool for generating Software Bill of Materials (SBOM) using embedded cdxgen binaries. Rudor simplifies SBOM generation by bundling cdxgen directly into a single executable, eliminating the need for Node.js or external dependencies.

## Features

- 📦 **Zero Dependencies** - Single executable with embedded cdxgen binary
- 🚀 **Cross-Platform** - Works on Windows, Linux, and macOS
- 🔍 **Auto-Detection** - Automatically detects project types
- 📋 **CycloneDX Format** - Generates industry-standard SBOM format
- ⚡ **Simple CLI** - Intuitive command-line interface

## Installation

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
4. Temporary files are automatically cleaned up

## Requirements

- Go 1.21+ (for building from source)
- No external dependencies required for the compiled executable

## License

See the [LICENSE](LICENSE) file for details.

## Acknowledgments

- Built on top of [cdxgen](https://github.com/CycloneDX/cdxgen) by CycloneDX
- Uses [Cobra](https://github.com/spf13/cobra) for CLI parsing

## Support

For issues, questions, or suggestions, please open an issue on the [GitHub repository](https://github.com/iron-kite/rudor/issues).