# Security Policy

## Supported Versions

Only the latest release receives security fixes.

| Version | Supported |
|---------|-----------|
| latest  | ✅        |
| older   | ❌        |

## Reporting a Vulnerability

If you find a security issue in PortHawk itself (not a scan result — the tool, the code):

1. **Do not open a public GitHub issue.** That exposes the vulnerability before a fix is ready.
2. Email **jakob.bartoschek@proton.me** with the subject line `[SECURITY] porthawk — <short description>`.
3. Include: what the issue is, how to reproduce it, and what impact you think it has.

I'll respond within 72 hours and aim to ship a fix within 2 weeks for serious issues.

## Scope

PortHawk is a **port scanner**. What's in scope for vulnerability reports:

- Code execution via malicious scan targets (e.g. banner injection)
- Insecure handling of NVD API responses
- Dependency vulnerabilities (report if `pip audit` or Safety flags something critical)
- Path traversal or file write issues in report output

Out of scope:
- "PortHawk can scan hosts" — that's what it's for (authorized use only)
- Issues in optional dependencies (Scapy, Streamlit, etc.) — report those upstream

## Responsible Use

PortHawk is built for **authorized security testing only**. Scanning hosts without
permission is illegal in most jurisdictions. See [DISCLAIMER.md](DISCLAIMER.md).
