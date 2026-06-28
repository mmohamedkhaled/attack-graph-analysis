# SPDX-FileCopyrightText: 2026 Mohamed Khaled <mohamedabdelfatah572@aucegypt.edu>
# SPDX-License-Identifier: MIT

"""Core data models for the attack-graph toolkit.

Everything the analyser produces flows through these dataclasses, keeping the
different modules decoupled: ``graph_io`` builds a :class:`GraphSpec`,
``security.analyze`` consumes it and returns a :class:`SecurityReport`.
"""

from __future__ import annotations

from dataclasses import dataclass, field
from typing import Dict, List, Optional, Set


@dataclass(frozen=True)
class Edge:
    """A single weighted directed edge ``(source -> target, weight)``.

    The ``weight`` always carries the numeric cost used by every algorithm.
    When the weight was *derived* from a CVSS vector (rather than written by
    hand), ``cvss`` holds that vector and ``weight_basis`` holds a short
    human-readable justification -- so every number in the graph is auditable.
    """

    source: str
    target: str
    weight: float
    cvss: Optional[str] = None
    weight_basis: Optional[str] = None


@dataclass
class GraphSpec:
    """A complete, serialisable description of an attack graph.

    Attributes
    ----------
    name : str
        Human-readable graph identifier.
    vertices : list of str
        The vertex set ``V``.
    edges : list of Edge
        The weighted directed edge set ``E``.
    source, target : str
        The attacker entry point ``s`` and the protected asset ``t``.
    description : str
        Free-form documentation of what the graph models.
    node_roles : dict, optional
        Mapping ``vertex -> human description`` (e.g. host role).
    """

    name: str
    vertices: List[str]
    edges: List[Edge]
    source: str
    target: str
    description: str = ""
    node_roles: Dict[str, str] = field(default_factory=dict)
    kind: str = "security"  # network domain code; see attack_graph/domains.py

    # -- validation --------------------------------------------------------
    def validate(self) -> None:
        """Sanity-check the spec; raise ``ValueError`` on any inconsistency."""
        if not self.vertices:
            raise ValueError("A graph must have at least one vertex.")
        if len(set(self.vertices)) != len(self.vertices):
            raise ValueError("Duplicate vertex names detected.")
        for endpoint in (self.source, self.target):
            if endpoint not in self.vertices:
                raise ValueError(
                    f"Endpoint '{endpoint}' is not listed in vertices."
                )
        if self.source == self.target:
            raise ValueError("Source and target must be distinct vertices.")
        index = set(self.vertices)
        for edge in self.edges:
            if edge.source not in index or edge.target not in index:
                raise ValueError(
                    f"Edge ({edge.source}, {edge.target}) references an "
                    f"unknown vertex."
                )
            if edge.source == edge.target:
                raise ValueError(f"Self-loop on '{edge.source}' is not allowed.")
            if edge.weight <= 0:
                raise ValueError(
                    f"Edge ({edge.source}, {edge.target}) has non-positive "
                    f"weight {edge.weight}; weights must be positive."
                )
@dataclass
class SecurityMetrics:
    """Raw graph-theoretic measurements computed for one graph."""

    is_reachable: bool
    shortest_path_cost: Optional[float]
    num_shortest_paths: int
    num_attack_paths: int
    shortest_paths: List[List[str]]
    max_vertex_disjoint_paths: int
    disjoint_paths: List[List[str]]
    min_vertex_cut: Set[str]
    min_vertex_cut_size: int
    num_min_vertex_cuts: int        # how many distinct minimum cuts exist
    min_edge_cut_size: int
    cut_node_betweenness: Dict[str, float]
    density: float
    is_dag: bool


@dataclass
class ScoreComponent:
    """One weighted contributor to the overall security score."""

    name: str
    score: float        # 0..100  (higher = more secure)
    weight: float       # 0..1
    detail: str


@dataclass
class NodeVulnerability:
    """A single node assessed as a security hotspot (see vulnerabilities.py)."""

    node: str
    role: str
    reachable: bool
    dist_from_source: Optional[float]
    betweenness: float
    path_coverage: float
    on_shortest_path: bool
    on_all_paths: bool
    in_min_cut: bool
    score: float
    severity: str
    reasons: List[str] = field(default_factory=list)


@dataclass
class VulnerabilityReport:
    """A ranked list of node-level vulnerabilities for one network."""

    hotspots: List[NodeVulnerability]
    attack_path_count: int
    has_single_point_of_failure: bool

    def top(self, n: int = 5) -> List[NodeVulnerability]:
        """Return the ``n`` most severe vulnerabilities."""
        return self.hotspots[:n]


@dataclass
class SecurityReport:
    """The full output of analysing a graph."""

    spec: GraphSpec
    metrics: SecurityMetrics
    components: List[ScoreComponent]
    score: float            # 0..100
    grade: str              # A..F
    findings: List[str]
    vulnerabilities: Optional[VulnerabilityReport] = None
