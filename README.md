<div align="center">

# Cybersecurity Portfolio

**Security engineering, IT audit and GRC tooling, built the way it is done in enterprise environments.**

[![CI](https://github.com/Roland-202/cybersecurity-portfolio/actions/workflows/ci.yml/badge.svg)](https://github.com/YOUR-Roland-202/cybersecurity-portfolio/actions/workflows/ci.yml)
![Python](https://img.shields.io/badge/python-3.10%2B-blue)
![Dependencies](https://img.shields.io/badge/runtime%20dependencies-none-brightgreen)
[![License: MIT](https://img.shields.io/badge/license-MIT-lightgrey.svg)](LICENSE)

</div>

## About

I work at the intersection of networking, backend development and security assurance. This repository is a growing collection of tools that automate the checks I would otherwise do by hand when reviewing infrastructure: firewall rule sets, exposed services, logs, configuration baselines and access controls.

Each project is self-contained and follows the same standard:

Explainable output. Every finding includes the evidence, why it matters, how to fix it, and (where relevant) a framework reference such as NIST SP 800-53, ISO/IEC 27001:2022, PCI DSS or CIS Controls.
- Tested. Unit tests plus realistic fixtures, including regression tests for hostile input.
- CI on every push across Python 3.10 to 3.12.
- Standard library first. Minimal dependencies keep the tools easy to audit and run.
- Honest scope. Each README ends with a Known limitation section.

## Projects

| # | Project | Domain | Highlights | Status |
|---|---------|--------|------------|--------|
| 01 | [**fwaudit**: Firewall Rule Validator & Hardening Auditor](01-firewall-rule-auditor) | Network and infrastructure security, ITGC | Cisco IOS ACL and iptables parsing, shadowed-rule detection using real subnet maths, risky-service checks, scored HTML/JSON reports, CI gate | Done |
| 02 | [**netrecon**: Async Network Scanner & Service Mapper](02-network-scanner) | Network security, vulnerability management | asyncio connect scan, banner grabbing and fingerprinting, version-range CVE matching with confidence levels, authorisation scope guard, built-in safe lab | Done |
| 03 | Log Parser & SIEM Threat Hunting Toolkit | Blue team / SOC | Detections for brute force, spraying and privilege escalation, mapped to MITRE ATT&CK | Planned |
| 04 | SSH/RDP Brute-Force Detector & Auto-Blocker | Detection and response | Log tailing, thresholds, simulated firewall blocking | Planned |
| 05 | Linux CIS Benchmark Auditor | IT audit / GRC | Baseline checks with pass/fail scoring | Planned |
| 06 | RBAC & Immutable Audit-Log Middleware | Application security | Django, role-based access control, tamper-evident audit trail | Planned |
| 07 | OWASP Vulnerability & Sanitization Sandbox | Application security | Vulnerable vs. fixed code with tests proving the fix | Planned |
| 08 | Cloud IAM Policy Auditor | Cloud security | Wildcard permissions, public storage, missing MFA | Planned |
| 09 | IT Risk Assessment Matrix Generator | Risk / GRC | Likelihood x impact scoring, prioritised remediation roadmap | Planned |
| 10 | DFIR Artifact Timeline Parser | Digital forensics | Browser and log artifacts into a chronological timeline | Planned |

## Quick start

```bash
git clone https://github.com/Roland-202/cybersecurity-portfolio.git
cd cybersecurity-portfolio

# Project 01: audit a deliberately misconfigured router
cd 01-firewall-rule-auditor
pip install -e .
fwaudit audit samples/cisco_edge_bad.cfg
cd ..

# Project 02: scan the built-in lab (harmless simulated services on 127.0.0.1)
cd 02-network-scanner
pip install -e .
python lab/fake_services.py &
netrecon scan 127.0.0.1 -p 2121,2222,2323,2525,3307,6380,8080
```

Each project folder has its own README with full usage, design notes and limitations.

## Repository layout

```text
cybersecurity-portfolio/
├── 01-firewall-rule-auditor/     # fwaudit: package, tests, samples, docs
├── 02-network-scanner/           # netrecon: package, tests, lab, docs
├── .github/
│   ├── workflows/ci.yml          # test matrix + CLI smoke tests
│   └── dependabot.yml
├── LICENSE
├── SECURITY.md
└── README.md
```

## Frameworks referenced

| Framework | Used for |
|-----------|----------|
| NIST SP 800-53 Rev. 5 | Control mapping for audit findings (SC-7, CM-7, AU-12 ...) |
| ISO/IEC 27001:2022 | Annex A control references |
| PCI DSS v4.0 | Network security control requirements |
| CIS Controls v8 | Safeguard references |
| MITRE ATT&CK | Detection mapping (from Project 03 onward) |

Control mappings are indicative starting points for working papers; validate them against your organisation's control library.

## Responsible use

These tools are for **education and authorised security work only**. Only scan or test systems you own or have explicit written permission to assess. Where a tool can touch live systems, it has safeguards (for example, `netrecon` refuses public IP ranges without an explicit authorisation flag) and ships with a safe local lab. See [SECURITY.md](SECURITY.md).

## Running every test suite

```bash
for p in 01-firewall-rule-auditor 02-network-scanner; do
  (cd "$p" && pip install -e ".[dev]" && pytest -q)
done
```

## Contact

- GitHub: [@Roland-202](https://github.com/Roland-202)

## License

[MIT](LICENSE)
