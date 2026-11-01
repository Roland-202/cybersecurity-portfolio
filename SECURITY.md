# Security Policy

## Responsible use

The tools in this repository are intended for education and **authorised** security assessment. You are responsible for ensuring you have written permission before scanning, probing or auditing any system you do not own. The authors accept no liability for misuse.

Intentionally vulnerable material (for example the simulated services in `02-network-scanner/lab/` and the misconfigured samples in `01-firewall-rule-auditor/samples/`) contains no real exploits. It only produces banners and configuration text that resemble vulnerable systems, for demonstration and testing.

## Reporting a vulnerability in these tools

If you find a security issue in the code (for example, a parsing flaw or unsafe handling of untrusted input in a report), please report it privately using GitHub's **"Report a vulnerability"** option on the repository's Security tab rather than opening a public issue. I aim to acknowledge reports within a few days.

## Scope

In scope: the Python packages and CLIs in this repository.
Out of scope: findings that depend on running the tools against systems without authorisation, and the deliberately vulnerable sample data noted above.
