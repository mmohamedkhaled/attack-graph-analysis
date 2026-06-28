# -*- coding: utf-8 -*-
"""Minimal graph-engine smoke tests.

Proves the public import surface, the data model, a single end-to-end
analysis on a shipped preset, and the CVSS weight derivation bounds. Real
algorithmic tests (Bellman-Ford traces, Menger equality cross-checks)
belong here too as the suite grows.
"""
from __future__ import annotations

from pathlib import Path

import attack_graph
from attack_graph import (
    GraphSpec,
    SecurityReport,
    analyze,
    load_graph,
)


# --------------------------------------------------------------------------- #
# Import surface.
# --------------------------------------------------------------------------- #
def test_package_exports_version() -> None:
    assert hasattr(attack_graph, "__version__")
    assert attack_graph.__version__


def test_public_api_symbols_exist() -> None:
    """Spot-check the documented public API is re-exported from __init__."""
    for name in (
        "analyze",
        "load_graph",
        "derive_weight",
        "from_nmap",
        "parse_nmap_xml",
        "export",
        "compute_vulnerabilities",
    ):
        assert hasattr(attack_graph, name), name


# --------------------------------------------------------------------------- #
# End-to-end on a shipped preset.
# --------------------------------------------------------------------------- #
def test_load_graph_returns_spec(sample_graph: Path) -> None:
    spec = load_graph(str(sample_graph))
    assert isinstance(spec, GraphSpec)
    assert spec.source in spec.vertices
    assert spec.target in spec.vertices


def test_analyze_returns_report(sample_graph: Path) -> None:
    spec = load_graph(str(sample_graph))
    report = analyze(spec)
    assert isinstance(report, SecurityReport)
    assert 0.0 <= report.score <= 100.0
    assert report.grade in {"A", "B", "C", "D", "F"}


# --------------------------------------------------------------------------- #
# CVSS weight derivation bounds (sanity calibration from the README table).
# --------------------------------------------------------------------------- #
def test_weights_derive_within_expected_range() -> None:
    from attack_graph import derive_weight

    # Easiest exploitability vector -> cheapest edge (~1.0).
    easiest = derive_weight("AV:N/AC:L/PR:N/UI:N")
    assert 0.9 <= easiest.weight <= 1.1

    # Hardest exploitability vector -> most expensive edge (~10.0).
    hardest = derive_weight("AV:P/AC:H/PR:H/UI:R")
    assert hardest.weight >= 9.9


def test_weight_monotonic_with_difficulty() -> None:
    """Requiring privileges must make an edge strictly more expensive."""
    from attack_graph import derive_weight

    no_priv = derive_weight("AV:N/AC:L/PR:N/UI:N").weight
    high_priv = derive_weight("AV:N/AC:L/PR:H/UI:N").weight
    assert high_priv > no_priv


# --------------------------------------------------------------------------- #
# Bundled presets (package data) -- the bare `aga` default must work even when
# there is no ./graphs directory, e.g. for a pipx/pip/Debian install.
# --------------------------------------------------------------------------- #
def test_bundled_default_preset_exists() -> None:
    from attack_graph.cli import _bundled_dir, _default_preset

    bundled = _bundled_dir("data/campus_paper.json")
    assert bundled is not None and bundled.is_file()
    # The default resolution must point at a real file regardless of cwd.
    assert _default_preset().is_file()


def test_bundled_default_preset_is_analysable() -> None:
    from attack_graph.cli import _default_preset

    spec = load_graph(str(_default_preset()))
    report = analyze(spec)
    assert isinstance(report, SecurityReport)
    assert 0.0 <= report.score <= 100.0
