"""
attack_graph
============

A modular toolkit for *Attack Graph Analysis* -- modelling a network as a
directed weighted graph and reasoning about its security with graph theory.

Public entry points
-------------------
* :func:`attack_graph.security.analyze`        -- full analysis of one graph
* :func:`attack_graph.graph_io.load_graph`     -- load a graph from JSON
* :mod:`attack_graph.shortest_paths`           -- custom Bellman-Ford
* :mod:`attack_graph.connectivity`             -- Menger's-theorem routines
* :mod:`attack_graph.weights`                  -- CVSS-based edge-weight derivation
"""

from .builder import build_digraph  # noqa: F401
from .construction import (  # noqa: F401
    TEMPLATES,
    AccessLevel,
    ConstructedGraph,
    DiscoveredHost,
    DiscoveredLink,
    GraphBuilder,
    from_adjacency,
    from_discovery,
    from_external_observation,
    from_foothold,
    from_template,
)
from .domains import NETWORK_KINDS, NetworkKind, get_kind  # noqa: F401
from .export import export, write_dot, write_graphml, write_json  # noqa: F401
from .graph_io import discover_graphs, load_graph, save_graph  # noqa: F401
from .models import (  # noqa: F401
    Edge,
    GraphSpec,
    NodeVulnerability,
    ScoreComponent,
    SecurityMetrics,
    SecurityReport,
    VulnerabilityReport,
)
from .probes.nmap import (  # noqa: F401
    SERVICE_ATTACKABILITY,
    NmapHost,
    Port,
    from_nmap,
    host_weight,
    parse_nmap_xml,
    scan_nmap,
)
from .probes.wifi import (  # noqa: F401
    WIFI_SECURITY,
    AccessPoint,
    from_wifi_scan,
    from_wifi_scans,
    merge_scans,
    scan_and_construct,
    scan_wifi,
    wifi_weight,
)
from .security import analyze, compute_metrics, compute_score  # noqa: F401
from .vulnerabilities import compute_vulnerabilities  # noqa: F401
from .weights import (  # noqa: F401
    CVSS3_METRICS,
    WeightDerivation,
    cvss_exploitability,
    derive_edge_weight,
    derive_weight,
    parse_cvss_vector,
)

__all__ = [
    "GraphSpec",
    "Edge",
    "SecurityMetrics",
    "ScoreComponent",
    "SecurityReport",
    "NodeVulnerability",
    "VulnerabilityReport",
    "load_graph",
    "save_graph",
    "discover_graphs",
    "build_digraph",
    "analyze",
    "compute_metrics",
    "compute_score",
    "compute_vulnerabilities",
    "AccessLevel",
    "GraphBuilder",
    "ConstructedGraph",
    "DiscoveredHost",
    "DiscoveredLink",
    "TEMPLATES",
    "from_template",
    "from_external_observation",
    "from_foothold",
    "from_adjacency",
    "from_discovery",
    "NETWORK_KINDS",
    "NetworkKind",
    "get_kind",
    "AccessPoint",
    "WIFI_SECURITY",
    "scan_wifi",
    "wifi_weight",
    "from_wifi_scan",
    "scan_and_construct",
    "merge_scans",
    "from_wifi_scans",
    "Port",
    "NmapHost",
    "SERVICE_ATTACKABILITY",
    "parse_nmap_xml",
    "host_weight",
    "from_nmap",
    "scan_nmap",
    "export",
    "write_graphml",
    "write_dot",
    "write_json",
    "CVSS3_METRICS",
    "derive_weight",
    "derive_edge_weight",
    "parse_cvss_vector",
    "cvss_exploitability",
    "WeightDerivation",
]

__version__ = "0.1.0"
