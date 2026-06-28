#!/usr/bin/env python3
# -*- coding: utf-8 -*-
# PYTHON_ARGCOMPLETE_OK
"""
Attack Graph Analysis -- command-line interface
===============================================

The ``aga`` command (and the ``analyze.py`` shim) drive the toolkit from the
terminal: analyse a graph, construct one from access, scan a real network
(WiFi / nmap), export to standard formats, and explain weights.

Usage
-----
After ``pipx install .`` (or ``pip install -e .``) the ``aga`` command is on
your PATH and works from anywhere; ``python3 analyze.py`` is the in-repo
equivalent.

    aga                                  # analyse the default preset
    aga graphs/highly_redundant.json     # analyse a specific graph
    aga --dir graphs/                    # compare every graph in a folder
    aga --nmap scan.xml                  # build a graph from nmap output
    aga --scan-wifi wlan0 --i-am-authorized
    aga --export out.graphml             # also export to GraphML/DOT/JSON
    aga --explain-cvss "AV:N/AC:L/PR:N/UI:R"

The default preset directory is ``./graphs`` in the current working directory.
"""

from __future__ import annotations

import argparse
import subprocess
import sys
from importlib import resources
from pathlib import Path
from typing import List, Optional

# Dependency guard.
try:
    import networkx as nx  # noqa: F401  (used transitively)
except ImportError:
    print("[ERROR] networkx is required. Install it with 'pip install networkx'.")
    sys.exit(1)

from attack_graph import __version__, graph_io, security
from attack_graph.construction import (
    TEMPLATES,
    ConstructedGraph,
    from_discovery,
    from_template,
)
from attack_graph.domains import get_kind
from attack_graph.export import export as export_graph
from attack_graph.models import SecurityReport
from attack_graph.probes.nmap import from_nmap, parse_nmap_xml, scan_nmap
from attack_graph.probes.wifi import (
    _parse_nmcli_terse,
    from_wifi_scan,
    scan_wifi,
)
from attack_graph.weights import CVSS3_METRICS, CVSS3_VALUE_NAMES, derive_weight


# Resolve presets from the *bundled* package data (attack_graph/data/) so the
# command works identically whether run in-repo (python3 analyze.py), installed
# via pip/pipx, or packaged by Debian/Kali. A ./graphs directory in the current
# working directory takes precedence, which keeps in-repo development natural.
def _bundled_dir(subpath: str) -> Optional[Path]:
    """Return a path under the bundled ``attack_graph/data`` tree, if present."""
    try:
        res = resources.files("attack_graph") / subpath
        if res.is_dir():
            return Path(str(res))
        if res.is_file():
            return Path(str(res))
    except (ModuleNotFoundError, AttributeError, FileNotFoundError):
        pass
    return None


def _default_graphs_dir() -> Path:
    """Prefer ``./graphs`` (dev); fall back to the bundled presets."""
    cwd_graphs = Path.cwd() / "graphs"
    if cwd_graphs.is_dir():
        return cwd_graphs
    return _bundled_dir("data") or Path.cwd() / "graphs"


def _default_preset() -> Path:
    """The paper's campus network -- the graph analysed by a bare ``aga``."""
    cwd_preset = Path.cwd() / "graphs" / "campus_paper.json"
    if cwd_preset.is_file():
        return cwd_preset
    bundled = _bundled_dir("data/campus_paper.json")
    if bundled and bundled.is_file():
        return bundled
    return cwd_preset


DEFAULT_GRAPHS_DIR = _default_graphs_dir()
DEFAULT_PRESET = _default_preset()

# Theoretical bounds of the CVSS Exploitability sub-score, used only to
# annotate the --explain-cvss trace.
_EMAX = 8.22 * (
    CVSS3_METRICS["AV"]["N"] * CVSS3_METRICS["AC"]["L"]
    * CVSS3_METRICS["PR"]["N"] * CVSS3_METRICS["UI"]["N"]
)
_EMIN = 8.22 * (
    CVSS3_METRICS["AV"]["P"] * CVSS3_METRICS["AC"]["H"]
    * CVSS3_METRICS["PR"]["H"] * CVSS3_METRICS["UI"]["R"]
)


# --------------------------------------------------------------------------- #
# Pretty-printing helpers.
# --------------------------------------------------------------------------- #
def _box(title: str, char: str = "=") -> str:
    line = char * 72
    return f"\n{line}\n {title}\n{line}"


def _short_path(path: List[str]) -> str:
    return " -> ".join(path)


def print_report(report: SecurityReport) -> None:
    """Print a full single-graph report card to stdout."""
    spec = report.spec
    m = report.metrics

    print(_box(f"GRAPH: {spec.name}"))
    kind = get_kind(spec.kind)
    print(f"  Domain   : {kind.name}   (kind='{spec.kind}')")
    if spec.description:
        print(f"  {spec.description}")
    print(f"  Vertices : {spec.vertices}   [{kind.vertex_term}]")
    print(f"  Edges    : {len(spec.edges)}    "
          f"{kind.source_term}='{spec.source}'  "
          f"{kind.target_term}='{spec.target}'  "
          f"weight={kind.weight_term}  is_DAG={m.is_dag}")

    print(_box("REACHABILITY & SHORTEST PATHS"))
    if not m.is_reachable:
        print(f"  Target '{spec.target}' is UNREACHABLE from '{spec.source}'.")
    else:
        print(f"  Shortest attack cost  d(s, t) = {m.shortest_path_cost:g}")
        print(f"  Tied shortest paths   = {m.num_shortest_paths}")
        for i, p in enumerate(m.shortest_paths, 1):
            print(f"     {i}. {_short_path(p)}")
        print(f"  Total attack paths    = {m.num_attack_paths}")

    cvss_edges = [e for e in spec.edges if e.cvss]
    if cvss_edges:
        print(_box("EDGE WEIGHTS  (CVSS-derived, auditable)"))
        for e in cvss_edges:
            print(f"  {e.source:>3} -> {e.target:<3}  w={e.weight:>5.2f}   "
                  f"{e.weight_basis}")

    print(_box("CONNECTIVITY  (Menger's Theorem)"))
    print(f"  Max vertex-disjoint paths = {m.max_vertex_disjoint_paths}")
    for i, p in enumerate(m.disjoint_paths, 1):
        print(f"     P{i}: {_short_path(p)}")
    print(f"  Min vertex cut |C*|        = {m.min_vertex_cut_size} "
          f"-> {sorted(m.min_vertex_cut) or '{}'}")
    print(f"  Min edge cut               = {m.min_edge_cut_size}")
    if m.cut_node_betweenness:
        print(f"  Cut-node betweenness       = {m.cut_node_betweenness}")
    print(f"  Menger equality holds      : "
          f"{m.max_vertex_disjoint_paths == m.min_vertex_cut_size}")

    print(_box("SECURITY SCORE"))
    print(f"  Composite score : {report.score:>6} / 100     GRADE: {report.grade}")
    print("  Component breakdown:")
    for c in report.components:
        print(f"     - {c.name:<18} {c.score:6.1f}  (w={c.weight:.2f})  {c.detail}")

    print(_box("FINDINGS & RECOMMENDATIONS"))
    for i, f in enumerate(report.findings, 1):
        print(f"  {i}. {f}")
    print()

    if report.vulnerabilities and report.vulnerabilities.hotspots:
        print(_box("VULNERABILITY HOTSPOTS  (where the weak points are)"))
        vr = report.vulnerabilities
        if vr.has_single_point_of_failure:
            print("  *** SINGLE POINT OF FAILURE DETECTED: a node sits on "
                  "EVERY route. ***")
        severe = [v for v in vr.hotspots if v.reachable][:6]
        for v in severe:
            tags = []
            if v.on_all_paths:
                tags.append("SPOF")
            if v.in_min_cut:
                tags.append("MIN-CUT")
            if v.on_shortest_path:
                tags.append("ON-CHEAPEST-ROUTE")
            tagstr = f" [{', '.join(tags)}]" if tags else ""
            print(f"  {v.severity:<9} {v.node:<6} "
                  f"(score {v.score:>5}){tagstr}  {v.role}")
            for r in v.reasons:
                print(f"             - {r}")
        print()


def print_comparison(reports: List[SecurityReport]) -> None:
    """Print a compact comparison table for several graphs."""
    print(_box("COMPARISON  --  all analysed graphs"))
    header = (
        f"{'Graph':<26} {'Kind':<14} {'Reach':<6} {'d(s,t)':>7} {'#sh':>4} "
        f"{'#atk':>5} {'|C*|':>5} {'Score':>7} {'Grade':>5}"
    )
    print(header)
    print("-" * len(header))
    for r in reports:
        m = r.metrics
        reach = "yes" if m.is_reachable else "NO"
        cost = f"{m.shortest_path_cost:g}" if m.is_reachable else "-"
        print(
            f"{r.spec.name[:26]:<26} {r.spec.kind:<14} {reach:<6} {cost:>7} "
            f"{m.num_shortest_paths:>4} {m.num_attack_paths:>5} "
            f"{m.min_vertex_cut_size:>5} {r.score:>7} {r.grade:>5}"
        )
    print()
    print("Legend: #sh = #shortest paths | #atk = #attack paths | "
          "|C*| = min vertex cut")
    print("All domains are analysed by the same security engine "
          "(Bellman-Ford + Menger + composite score).")
    print()


# --------------------------------------------------------------------------- #
# CVSS weight-derivation explainer.
# --------------------------------------------------------------------------- #
def explain_cvss(vector: str) -> int:
    """Show, step by step, how a CVSS vector becomes an edge weight."""
    try:
        derivation = derive_weight(vector)
    except ValueError as exc:
        print(f"[ERROR] {exc}")
        return 1

    metrics = derivation.breakdown
    print(_box(f"CVSS WEIGHT DERIVATION  --  {vector}"))
    print("  Step 1 -- CVSS v3.1 Exploitability metrics (official values):")
    for metric_code, value in metrics.items():
        name = {
            "AV": "Attack Vector",
            "AC": "Attack Complexity",
            "PR": "Privileges Required",
            "UI": "User Interaction",
        }[metric_code]
        numeric = CVSS3_METRICS[metric_code][value]
        print(
            f"     {metric_code} ({name:<20}) = "
            f"{CVSS3_VALUE_NAMES[metric_code][value]:<10} ({value}, coef {numeric})"
        )

    print("\n  Step 2 -- CVSS Exploitability sub-score  E = 8.22 * AV * AC * PR * UI")
    print(f"     E = {derivation.exploitability:.4f}   "
          f"(range [{_EMIN:.3f}, {_EMAX:.3f}])")

    print("\n  Step 3 -- Normalise to [0,1] and invert into a difficulty:")
    print(f"     normalised = (E - {_EMIN:.3f}) / ({_EMAX:.3f} - {_EMIN:.3f})"
          f" = {derivation.normalized:.4f}   (1 = easiest)")
    print(f"     difficulty = 1 - normalised = {derivation.difficulty:.4f}   "
          f"(1 = hardest)")

    print("\n  Step 4 -- Map difficulty onto the 1..10 edge-weight scale:")
    print(f"     weight = 1 + 9 * difficulty = {derivation.weight:.2f}")
    print()
    print(f"  RESULT: edge weight = {derivation.weight:.2f}")
    print()
    return 0


# --------------------------------------------------------------------------- #
# Plot helper.
# --------------------------------------------------------------------------- #
def maybe_plot(report: SecurityReport, out_dir: Path, no_plot: bool) -> None:
    """Save (and optionally show) a PNG for the report, unless --no-plot."""
    if no_plot:
        return
    try:
        from attack_graph import visualization
    except ImportError as exc:
        print(f"[WARN] Visualisation unavailable: {exc}")
        return
    out_dir.mkdir(parents=True, exist_ok=True)
    safe = "".join(c if c.isalnum() or c in "-_" else "_" for c in report.spec.name)
    out_path = out_dir / f"{safe}.png"
    try:
        visualization.visualize_report(report, output_path=str(out_path), show=False)
        print(f"[Visualisation] Saved -> {out_path}\n")
    except Exception as exc:  # pragma: no cover - graphical env issues
        print(f"[WARN] Could not render plot for '{report.spec.name}': {exc}")


def maybe_export(report: SecurityReport, export_path: Optional[str]) -> None:
    """Export the analysed graph to a standard format, if --export was given."""
    if not export_path:
        return
    try:
        out = export_graph(report.spec, export_path)
        print(f"[Export] Saved {report.spec.name} -> {out}\n")
    except (ValueError, OSError) as exc:
        print(f"[WARN] Could not export: {exc}")


# --------------------------------------------------------------------------- #
# Argument parsing & main.
# --------------------------------------------------------------------------- #
def build_parser() -> argparse.ArgumentParser:
    parser = argparse.ArgumentParser(
        prog="aga",
        description="Attack Graph Analysis (aga): weighted-graph security "
        "toolkit -- analyse, construct, and scan.",
    )
    # Standard version flag (GNU convention: -V/--version).
    parser.add_argument(
        "-V",
        "--version",
        action="version",
        version=f"%(prog)s {__version__}",
    )
    parser.add_argument(
        "config",
        nargs="?",
        default=str(DEFAULT_PRESET),
        help="Path to a JSON graph config (default: the paper's campus network).",
    )
    parser.add_argument(
        "--dir",
        dest="directory",
        default=None,
        help="Analyse every *.json graph config in this directory and compare.",
    )
    parser.add_argument(
        "--no-plot",
        action="store_true",
        help="Skip generating/saving the graph visualisation.",
    )
    parser.add_argument(
        "--list",
        dest="list_only",
        action="store_true",
        help="List available graph presets and exit.",
    )
    parser.add_argument(
        "--graphs-dir",
        default=str(DEFAULT_GRAPHS_DIR),
        help="Directory of preset graph configs (default: ./graphs).",
    )
    parser.add_argument(
        "--explain-cvss",
        dest="explain_cvss",
        metavar="VECTOR",
        default=None,
        help="Explain how a CVSS vector (e.g. 'AV:N/AC:L/PR:N/UI:N') becomes "
        "an edge weight, then exit. No graph is analysed.",
    )
    parser.add_argument(
        "--list-templates",
        dest="list_templates",
        action="store_true",
        help="List the built-in graph-construction templates and exit.",
    )
    parser.add_argument(
        "--construct",
        dest="construct",
        metavar="TEMPLATE",
        default=None,
        help="Construct a graph from a named template (zero access) and "
        "analyse it. Use --list-templates to see names.",
    )
    parser.add_argument(
        "--discover",
        dest="discover",
        metavar="FILE",
        default=None,
        help="Construct a graph from a discovery JSON file (describes what "
        "was observed vs inferred, with an access level) and analyse it.",
    )
    parser.add_argument(
        "--wifi-from-file",
        dest="wifi_from_file",
        metavar="FILE",
        default=None,
        help="Construct a WiFi attack graph from a captured nmcli scan output "
        "(offline; for demos/testing) and analyse it.",
    )
    parser.add_argument(
        "--scan-wifi",
        dest="scan_wifi",
        nargs="?",
        const="auto",
        default=None,
        metavar="IFACE",
        help="Run a LIVE passive WiFi scan on IFACE (or auto-detect), "
        "construct the attack graph, and analyse it. Requires "
        "--i-am-authorized. Only scan networks you own or are authorised to "
        "assess.",
    )
    parser.add_argument(
        "--i-am-authorized",
        dest="i_am_authorized",
        action="store_true",
        help="Authorisation gate for --scan-wifi. By passing this you assert "
        "you are authorised to scan the airspace.",
    )
    parser.add_argument(
        "--wifi-rescan",
        dest="wifi_rescan",
        action="store_true",
        help="With --scan-wifi, trigger a fresh nmcli rescan first.",
    )
    parser.add_argument(
        "--nmap",
        dest="nmap",
        metavar="FILE",
        default=None,
        help="Construct an attack graph from an nmap XML output file "
        "(nmap -oX). Parses hosts/ports/services into a weighted graph "
        "(the network INTERIOR layer). Offline and safe.",
    )
    parser.add_argument(
        "--nmap-live",
        dest="nmap_live",
        metavar="TARGET",
        default=None,
        help="Run nmap LIVE against TARGET (e.g. 10.0.0.0/24), build the "
        "graph, and analyse it. Sends packets -- requires "
        "--i-am-authorized. Only scan networks you own or are authorised "
        "to assess.",
    )
    parser.add_argument(
        "--export",
        dest="export",
        metavar="PATH",
        default=None,
        help="Also export the analysed graph to PATH. Format is chosen from "
        "the extension: .graphml/.xml (GraphML), .dot/.gv (Graphviz), "
        ".json (round-trip config).",
    )
    return parser


def print_construction(cg: ConstructedGraph) -> None:
    """Print the provenance of a constructed graph."""
    print(_box("CONSTRUCTED GRAPH  (provenance)"))
    print(f"  Name      : {cg.spec.name}")
    print(f"  Access    : {cg.access_level.value}")
    print(f"  Confidence: {cg.confidence}  ({cg.summary()})")
    if cg.inferred_nodes:
        print(f"  Inferred nodes : {sorted(cg.inferred_nodes)}")
    print(f"  Observed nodes : {sorted(cg.observed_nodes)}")
    print()


def main(argv=None) -> int:
    # Late import so the 'completions' extra is truly optional. The
    # `# PYTHON_ARGCOMPLETE_OK` marker near the top of this file is what
    # `register-python-argcomplete aga` scans for.
    try:
        import argcomplete

        argcomplete.autocomplete(build_parser())
    except ImportError:
        pass

    args = build_parser().parse_args(argv)

    if args.explain_cvss:
        return explain_cvss(args.explain_cvss)

    graphs_dir = Path(args.graphs_dir)

    if args.list_templates:
        print(_box("Built-in graph-construction templates"))
        for name, factory in TEMPLATES.items():
            cg = factory().build()
            print(f"  {name:<16} {cg.spec.name}  "
                  f"({len(cg.spec.vertices)}V / {len(cg.spec.edges)}E, "
                  f"{cg.access_level.value} access)")
        return 0

    out_dir = Path("plots")

    # --- construct from a template (zero access) -------------------------
    if args.construct:
        try:
            cg = from_template(args.construct)
        except ValueError as exc:
            print(f"[ERROR] {exc}")
            return 1
        print_construction(cg)
        report = security.analyze(cg.spec)
        print_report(report)
        maybe_export(report, args.export)
        maybe_plot(report, out_dir, args.no_plot)
        return 0

    # --- construct from a discovery file (minimal / no access) -----------
    if args.discover:
        try:
            cg = from_discovery(args.discover)
        except (FileNotFoundError, ValueError, KeyError) as exc:
            print(f"[ERROR] Could not load discovery file: {exc}")
            return 1
        print_construction(cg)
        report = security.analyze(cg.spec)
        print_report(report)
        maybe_export(report, args.export)
        maybe_plot(report, out_dir, args.no_plot)
        return 0

    # --- construct a WiFi graph from a captured scan file (offline) ------
    if args.wifi_from_file:
        try:
            text = Path(args.wifi_from_file).read_text(encoding="utf-8")
            aps = [ap for line in text.splitlines()
                   if (ap := _parse_nmcli_terse(line.strip()))]
        except FileNotFoundError as exc:
            print(f"[ERROR] {exc}")
            return 1
        if not aps:
            print(f"[ERROR] No access points parsed from {args.wifi_from_file}.")
            return 1
        cg = from_wifi_scan(aps)
        print_construction(cg)
        report = security.analyze(cg.spec)
        print_report(report)
        maybe_export(report, args.export)
        maybe_plot(report, out_dir, args.no_plot)
        return 0

    # --- LIVE passive WiFi scan ------------------------------------------
    if args.scan_wifi is not None:
        if not args.i_am_authorized:
            print(
                "[REFUSED] Live scanning requires --i-am-authorized.\n"
                "        By adding that flag you assert you are authorised to "
                "scan the airspace.\n"
                "        This probe is PASSIVE ONLY (beacon listening); it does "
                "not deauth, crack, or associate.\n"
                "        To try the pipeline offline, use --wifi-from-file."
            )
            return 1
        iface = None if args.scan_wifi == "auto" else args.scan_wifi
        try:
            aps = scan_wifi(iface, authorized=True, rescan=args.wifi_rescan)
        except (PermissionError, EnvironmentError, subprocess.CalledProcessError) as exc:
            print(f"[ERROR] WiFi scan failed: {exc}")
            return 1
        print(f"[scan] Observed {len(aps)} access point(s).")
        cg = from_wifi_scan(aps, iface_name=iface)
        print_construction(cg)
        report = security.analyze(cg.spec)
        print_report(report)
        maybe_export(report, args.export)
        maybe_plot(report, out_dir, args.no_plot)
        return 0

    # --- construct from an nmap XML file (the interior layer) -----------
    if args.nmap:
        try:
            hosts = parse_nmap_xml(args.nmap)
        except (FileNotFoundError, ValueError) as exc:
            print(f"[ERROR] Could not parse nmap XML: {exc}")
            return 1
        up = [h for h in hosts if h.status == "up" and h.ports]
        if not up:
            print(f"[ERROR] No 'up' hosts with open ports found in {args.nmap}.")
            return 1
        print(f"[nmap] Parsed {len(hosts)} host(s); {len(up)} up with open ports.")
        cg = from_nmap(hosts)
        print_construction(cg)
        report = security.analyze(cg.spec)
        print_report(report)
        maybe_export(report, args.export)
        maybe_plot(report, out_dir, args.no_plot)
        return 0

    # --- LIVE nmap scan (active, authorization-gated) ------------------
    if args.nmap_live is not None:
        if not args.i_am_authorized:
            print(
                "[REFUSED] Live nmap scanning sends packets and requires "
                "--i-am-authorized.\n"
                "        By adding that flag you assert you are authorised to "
                "scan the target.\n"
                "        To parse an existing scan offline, use --nmap FILE."
            )
            return 1
        try:
            hosts = scan_nmap(args.nmap_live, authorized=True)
        except (PermissionError, EnvironmentError, subprocess.CalledProcessError) as exc:
            print(f"[ERROR] nmap scan failed: {exc}")
            return 1
        up = [h for h in hosts if h.status == "up" and h.ports]
        print(f"[nmap] Scanned; {len(up)} up host(s) with open ports.")
        cg = from_nmap(hosts)
        print_construction(cg)
        report = security.analyze(cg.spec)
        print_report(report)
        maybe_export(report, args.export)
        maybe_plot(report, out_dir, args.no_plot)
        return 0

    if args.list_only:
        print(_box(f"Available graph presets in {graphs_dir}"))
        if not graphs_dir.is_dir():
            print(f"  (directory not found: {graphs_dir})")
            return 1
        for path in graph_io.discover_graphs(graphs_dir):
            try:
                spec = graph_io.load_graph(path)
                print(f"  {path.name:<32} {spec.name}  "
                      f"({len(spec.vertices)}V / {len(spec.edges)}E)")
            except Exception as exc:
                print(f"  {path.name:<32} [load error: {exc}]")
        return 0

    out_dir = Path("plots")

    # --- batch mode -------------------------------------------------------
    if args.directory:
        directory = Path(args.directory)
        if not directory.is_dir():
            print(f"[ERROR] Not a directory: {directory}")
            return 1
        reports: List[SecurityReport] = []
        for path in graph_io.discover_graphs(directory):
            try:
                spec = graph_io.load_graph(path)
            except Exception as exc:
                print(f"[ERROR] Could not load {path.name}: {exc}")
                continue
            print(f"Analysing {path.name} ...")
            report = security.analyze(spec)
            reports.append(report)
            maybe_plot(report, out_dir, args.no_plot)
        if not reports:
            print("[ERROR] No valid graph configs found.")
            return 1
        print_comparison(reports)
        return 0

    # --- single mode ------------------------------------------------------
    try:
        spec = graph_io.load_graph(args.config)
    except FileNotFoundError as exc:
        print(f"[ERROR] {exc}")
        return 1
    except ValueError as exc:
        print(f"[ERROR] Invalid graph config: {exc}")
        return 1

    report = security.analyze(spec)
    print_report(report)
    maybe_export(report, args.export)
    maybe_plot(report, out_dir, args.no_plot)
    return 0


if __name__ == "__main__":
    sys.exit(main())
