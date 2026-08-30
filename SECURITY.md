# Security Policy

harbore is a self-hosted security and compliance scanning platform developed by
CB-Advisory. We take the security of the product and of our users seriously.

## Supported Versions

harbore is currently in active pre-release development and does not yet publish
numbered stable releases. Until a `1.0` release is tagged, **only the latest
commit on the `main` branch** receives security fixes.

| Version            | Supported          |
| ------------------ | ------------------ |
| `main` (latest)    | :white_check_mark: |
| Older commits/tags | :x:                |

Once stable releases are published, this table will be updated to list the
specific version lines that receive security updates.

<!--
Example table to use once versioned releases exist:

| Version | Supported          |
| ------- | ------------------ |
| 1.1.x   | :white_check_mark: |
| 1.0.x   | :white_check_mark: |
| < 1.0   | :x:                |
-->

## Reporting a Vulnerability

**Please do not report security vulnerabilities through public GitHub issues,
pull requests, or discussions.**

Instead, report them privately using either of the following:

- **GitHub Security Advisories** — go to the
  [Security tab](https://github.com/djdubeyji/harbore/security/advisories) of
  this repository and choose **"Report a vulnerability"** (preferred), or
- **Email** — [SECURITY_CONTACT_EMAIL] (optionally encrypt with our PGP key:
  [PGP_KEY_LINK_OR_FINGERPRINT — or remove this line]).

To help us triage quickly, please include as much of the following as you can:

- A description of the vulnerability and its impact.
- The component affected (orchestrator, worker, AI/report engine, frontend,
  or infrastructure) and the version/commit hash.
- Step-by-step reproduction instructions or a proof-of-concept.
- Any relevant logs, requests, or screenshots.
- Your assessment of severity (e.g. CVSS vector), if you have one.

### What to expect

- **Acknowledgement:** within **3 business days** of your report.
- **Status updates:** at least once every **7 business days** until resolution.
- **Assessment:** we will confirm whether
