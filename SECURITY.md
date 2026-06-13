# Security Policy

## Supported Versions

The following versions of HOS-LS are currently receiving security updates:

| Version | Supported          |
| ------- | ------------------ |
| 0.3.x   | :white_check_mark: |
| < 0.3   | :x:                |

We recommend always using the latest stable version to benefit from the most recent security patches.

## Reporting a Vulnerability

We take the security of HOS-LS seriously. If you believe you have found a security vulnerability, please report it to us as described below.

**Please do NOT report security vulnerabilities through public GitHub issues.**

Instead, please report them via email to:

- **Security Email:** [security@hos-ls.com](mailto:security@hos-ls.com)

Please include the following information in your report:

- Type of issue (e.g., buffer overflow, SQL injection, cross-site scripting, etc.)
- Full paths of source file(s) related to the manifestation of the issue
- The location of the affected source code (tag/branch/commit or direct URL)
- Any special configuration required to reproduce the issue
- Step-by-step instructions to reproduce the issue
- Proof-of-concept or exploit code (if possible)
- Impact of the issue, including how an attacker might exploit the issue

## Response Timeline

- **Acknowledgment:** We will acknowledge receipt of your vulnerability report within **48 hours**.
- **Assessment:** Our security team will assess the vulnerability and determine its severity within 5 business days.
- **Resolution:** We aim to release a patch for critical vulnerabilities within 30 days of confirmation.
- **Disclosure:** We will coordinate with you on the disclosure timeline and credit you (if you wish) in our release notes.

## Security Best Practices

When using HOS-LS, we recommend the following security practices:

### 1. API Key Management
- **Never commit API keys to version control.** Use `.env` files or environment variables.
- The `.gitignore` file is configured to exclude `.env` files.
- Rotate your API keys regularly.

### 2. Sandboxed Execution
- Use the `--sandbox` flag when scanning untrusted code.
- Review scan results before executing any suggested fixes.

### 3. Dependency Management
- Keep HOS-LS and its dependencies up to date.
- Run `pip audit` or `safety check` regularly to identify vulnerable dependencies.

### 4. Network Security
- When using remote scanning features, ensure secure SSH connections.
- Use firewalls to restrict access to scanning endpoints.

### 5. Data Privacy
- HOS-LS may send code snippets to AI providers for analysis. Review our privacy policy and configure the `provider` settings accordingly.
- Do not scan code containing sensitive credentials or proprietary secrets without proper authorization.

## Disclosure Policy

We follow a responsible disclosure process:

1. Reporter submits vulnerability details
2. HOS-LS team acknowledges and assesses
3. Fix is developed and tested
4. Security release is published
5. Public disclosure after 30 days or by mutual agreement

## Security Advisories

Security advisories will be published via:

- GitHub Security Advisories
- Release notes with `[Security]` prefix
- Direct notification to reporters (when contact information is provided)

## Scope

This security policy covers:

- The HOS-LS command-line tool
- Core scanning modules
- AI integration components
- Plugin system
- Configuration file handling

## Contact

For any questions regarding this security policy, please contact:

- **Email:** [security@hos-ls.com](mailto:security@hos-ls.com)
