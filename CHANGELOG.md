# Changelog

All notable changes to **Attack Graph Analysis** (`aga`) are documented here.

The format is based on [Keep a Changelog](https://keepachangelog.com/en/1.1.0/),
and this project adheres to [Semantic Versioning](https://semver.org/spec/v2.0.0.html).

## [0.1.0] - 2026-06-28

First public release.

### Added
- Weighted directed-graph security engine with a from-scratch **Bellman-Ford**
  shortest-path implementation (with negative-cycle detection and an optional
  iteration trace).
- **Menger's Theorem** machinery: maximum vertex-disjoint paths and minimum
  vertex cut, cross-validated three ways (NetworkX flow, explicit
  vertex-splitting max-flow, and exhaustive enumeration).
- **CVSS v3.1 Exploitability**-based edge-weight derivation, so every weight is
  reproducible from a CVE record and explainable factor by factor
  (`aga --explain-cvss`).
- Composite **security score (0-100) + letter grade (A-F)** blending attack
  cost, path diversity, mitigation effort, and exposure.
- **Vulnerability hotspot detection** blending exposure (attacker's view) with
  criticality (defender's view), including single-point-of-failure flagging.
- Pluggable network **domains** (security, transport, supply-chain, social) so
  the same engine analyses any weighted directed network.
- Graph **construction** from access levels (none / minimal / partial / full)
  with observed-vs-inferred provenance tagging.
- Live / offline **probes**: passive WiFi scanning (nmcli/iwlist) and nmap XML
  ingest (the network-interior layer), both authorization-gated.
- Graph **export** to GraphML, Graphviz DOT, and round-trip JSON.
- Optional **Matplotlib** visualisation (auto-layered layout), installed via the
  `plot` extra so the base install stays headless.
- `aga` command-line interface with `--version`/`--help`, `--dir`, `--list`,
  `--explain-cvss`, `--construct`, `--discover`, `--wifi-from-file`,
  `--scan-wifi`, `--nmap`, `--nmap-live`, and `--export`.
- Bundled preset graphs (cyber, transport, supply-chain, social) shipped as
  package data so a bare `aga` works from anywhere.
- `pytest` suite and `ruff` lint in CI; `--version`/`--help` smoke tests
  suitable for Debian/Kali `autopkgtest`.

[0.1.0]: https://github.com/mmohamedkhaled/attack-graph-analysis/releases/tag/v0.1.0
