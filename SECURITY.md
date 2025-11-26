# Security Policy

## Supported Versions

| Version | Supported          |
| ------- | ------------------ |
| latest  | :white_check_mark: |
| < 1.0   | :x:                |

## Reporting a Vulnerability

We take security vulnerabilities seriously. If you discover a security issue, please report it responsibly.

### How to Report

**Please do NOT report security vulnerabilities through public GitHub issues.**

Instead, please report them via email to: **info@ironkite.com**

Include the following information in your report:

- Type of vulnerability (e.g., remote code execution, information disclosure, etc.)
- Full path of the affected source file(s)
- Location of the affected code (tag/branch/commit or direct URL)
- Step-by-step instructions to reproduce the issue
- Proof-of-concept or exploit code (if possible)
- Impact assessment of the vulnerability

### What to Expect

- **Acknowledgment**: We will acknowledge receipt of your report within 48 hours.
- **Assessment**: We will investigate and assess the vulnerability within 7 days.
- **Resolution**: We aim to release a fix within 30 days for critical vulnerabilities.
- **Disclosure**: We will coordinate with you on the public disclosure timeline.

### Safe Harbor

We consider security research conducted in accordance with this policy to be:

- Authorized concerning any applicable anti-hacking laws
- Exempt from restrictions in our Terms of Service that would interfere with conducting security research

We will not pursue legal action against researchers who:

- Act in good faith and follow this policy
- Avoid privacy violations, data destruction, and service disruption
- Report vulnerabilities promptly and allow reasonable time for resolution

## Security Best Practices

When using Rudor:

1. **Verify Downloads**: Always verify checksums when downloading release binaries
2. **Use Latest Version**: Keep Rudor updated to receive security patches
3. **Review SBOMs**: Regularly review generated SBOMs for vulnerable dependencies
4. **Secure CI/CD**: Use environment variables for sensitive data in CI/CD pipelines

## Security Features

Rudor includes several security features:

- **No External Dependencies**: Single binary with embedded tools reduces supply chain risk
- **CVE Scanning**: Automatic vulnerability detection using OSV database
- **Secure Defaults**: Non-root Docker container, minimal base image (distroless)
- **Code Signing**: Release binaries include checksums for verification

## Third-Party Dependencies

Rudor uses the following third-party components:

- [cdxgen](https://github.com/CycloneDX/cdxgen) - SBOM generation (embedded binary)
- [CycloneDX Go Library](https://github.com/CycloneDX/cyclonedx-go) - SBOM parsing
- [Cobra](https://github.com/spf13/cobra) - CLI framework
- [go-cvss](https://github.com/pandatix/go-cvss) - CVSS score parsing

We regularly update dependencies and monitor for security advisories.