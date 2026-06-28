# Security Policy

## Supported versions

Only the latest minor release receives security fixes.

| Version | Supported          |
|---------|--------------------|
| 0.1.x   | :white_check_mark: |
| < 0.1   | :x:                |

## Reporting a vulnerability

If you discover a security vulnerability in **attack-graph-analysis**
(the `aga` command / `attack_graph` package), please report it
**privately** — do **not** open a public GitHub issue.

1. Email: **mohamedabdelfatah572@aucegypt.edu**
2. Subject line: `[SECURITY] aga — <short summary>`
3. Include: the affected version, steps to reproduce, and the impact.

We will acknowledge within **72 hours** and aim to ship a fix or mitigation
within **30 days**, coordinating a disclosure date with you.

## Scope

This policy covers vulnerabilities in the `attack_graph` package itself —
the analysis engine, CVSS weight derivation, graph construction, and the
nmap/WiFi probes.

It does **not** cover:

- **Misuse of the tool** against networks you do not own or are not
  authorised to assess. Live scans (WiFi/nmap) require the explicit
  `--i-am-authorized` flag; unauthorised scanning is the operator's
  responsibility and is not a software defect.
- Vulnerabilities in **dependencies** (networkx, matplotlib) — report those
  to their upstream maintainers.
- Pre-`0.1.0` development snapshots.

## Safe harbour

`aga` is a defensive-analysis tool. Authorised security research conducted
in good faith and consistent with this policy is welcomed and will not be
met with legal action.

## Acknowledgements

With your permission, responsible reporters are credited (or kept anonymous)
in the release notes. There is currently no bug-bounty programme.
