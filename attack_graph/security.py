# SPDX-FileCopyrightText: 2026 Mohamed Khaled <mohamedabdelfatah572@aucegypt.edu>
# SPDX-License-Identifier: MIT

"""Security analysis -- metrics, composite score, grade, and findings.

The security level of an attack graph is summarised as a single **0-100
composite score** with a **letter grade (A-F)**.  The score is a transparent,
weighted blend of four graph-theoretic dimensions, each normalised so that
*higher = more secure*:

==================  ===========================================  ==================
Component (weight)  What it measures                             Direction
==================  ===========================================  ==================
Attack cost  (35%)  shortest-path cost ``d(s, t)``               higher = more secure
Path diversity (25%) number of *tied* shortest paths             fewer  = more secure
Mitigation effort (25%) minimum vertex-cut cardinality ``|C*|`` lower  = more secure
Exposure  (15%)     number of distinct attack paths              fewer  = more secure
==================  ===========================================  ==================

Interpretation of the directions:

* A **high** cheapest-attack cost means exploitation is expensive.
* **Few** shortest/attack paths means the attacker has limited options.
* A **small** minimum vertex cut means only a handful of patches fully sever
  every attack route (cheap to fully mitigate).  Note this equals the maximum
  number of vertex-disjoint paths (Menger), so a small cut also means the
  attacker enjoys little route redundancy -- both readings agree that *smaller
  is more secure*.

If the target is **unreachable** from the source the network is perfectly
secure and the score is forced to 100 (grade A).
"""

from __future__ import annotations

from typing import List, Tuple

import networkx as nx

from . import connectivity, shortest_paths
from .builder import build_digraph
from .domains import get_kind
from .models import (
    GraphSpec,
    ScoreComponent,
    SecurityMetrics,
    SecurityReport,
)


# --------------------------------------------------------------------------- #
# Scoring configuration (tweakable).
# --------------------------------------------------------------------------- #
class ScoringConfig:
    """Weights and penalties for the composite score.

    All penalties are applied as ``max(0, 100 - penalty * excess)`` where
    ``excess`` is the value *above the best case*.
    """

    WEIGHT_ATTACK_COST = 0.35
    WEIGHT_PATH_DIVERSITY = 0.25
    WEIGHT_MITIGATION = 0.25
    WEIGHT_EXPOSURE = 0.15

    COST_SCALE = 12.0          # d(s,t) that maps to a sub-score of 100
    SHORTEST_PATH_PENALTY = 25.0   # per shortest path beyond the first
    CUT_PENALTY = 30.0             # per vertex in the minimum vertex cut
    ATTACK_PATH_PENALTY = 12.0     # per attack path beyond the first


# Letter-grade thresholds (>= threshold).
_GRADE_BOUNDS: List[Tuple[float, str]] = [
    (85.0, "A"),
    (70.0, "B"),
    (55.0, "C"),
    (40.0, "D"),
    (0.0, "F"),
]


def _grade(score: float) -> str:
    for bound, letter in _GRADE_BOUNDS:
        if score >= bound:
            return letter
    return "F"


def _clamp(x: float) -> float:
    return max(0.0, min(100.0, x))


# --------------------------------------------------------------------------- #
# Metric computation.
# --------------------------------------------------------------------------- #
def compute_metrics(spec: GraphSpec) -> SecurityMetrics:
    """Compute every raw graph-theoretic metric for ``spec``."""
    graph = build_digraph(spec)
    edges = [(u, v, d["weight"]) for u, v, d in graph.edges(data=True)]

    dist, _, _, has_neg_cycle = shortest_paths.bellman_ford(
        spec.vertices, edges, spec.source, verbose=False
    )
    if has_neg_cycle:
        # Attack costs could be driven arbitrarily negative -- treat as a
        # critical misconfiguration but keep the analysis running.
        pass

    is_reachable = dist[spec.target] != float("inf")
    shortest_cost = dist[spec.target] if is_reachable else None
    sp = shortest_paths.all_shortest_paths(dist, edges, spec.source, spec.target)

    attack_paths = shortest_paths.all_attack_paths(
        graph, spec.source, spec.target
    )

    max_k, disjoint = connectivity.max_vertex_disjoint_paths(
        graph, spec.source, spec.target
    )
    cut = connectivity.min_vertex_cut(graph, spec.source, spec.target)
    edge_cut = connectivity.min_edge_cut_size(graph, spec.source, spec.target)

    # Count the distinct minimum vertex cuts (only for small graphs; the
    # exhaustive search is exponential, so guard it).
    num_min_cuts = 1
    if cut and len(spec.vertices) <= 20 and len(cut) <= 5:
        _, alternatives = connectivity.all_minimum_vertex_cuts(
            graph, spec.source, spec.target, max_size=len(cut)
        )
        num_min_cuts = len(alternatives)

    # Betweenness centrality of the cut nodes (how "critical" each is).
    betweenness = nx.betweenness_centrality(graph, weight="weight", normalized=True)
    cut_betweenness = {
        node: round(betweenness.get(node, 0.0), 4) for node in sorted(cut)
    }

    density = nx.density(graph)

    return SecurityMetrics(
        is_reachable=is_reachable,
        shortest_path_cost=(shortest_cost if shortest_cost is not None else None),
        num_shortest_paths=len(sp),
        num_attack_paths=len(attack_paths),
        shortest_paths=sp,
        max_vertex_disjoint_paths=max_k,
        disjoint_paths=disjoint,
        min_vertex_cut=cut,
        min_vertex_cut_size=len(cut),
        num_min_vertex_cuts=num_min_cuts,
        min_edge_cut_size=edge_cut,
        cut_node_betweenness=cut_betweenness,
        density=round(density, 4),
        is_dag=nx.is_directed_acyclic_graph(graph),
    )


# --------------------------------------------------------------------------- #
# Scoring.
# --------------------------------------------------------------------------- #
def compute_score(
    metrics: SecurityMetrics, cfg: ScoringConfig = ScoringConfig()
) -> Tuple[float, List[ScoreComponent]]:
    """Combine the metrics into a 0-100 score with a per-component breakdown."""
    if not metrics.is_reachable:
        # Target unreachable -> perfectly secure.
        comp = [
            ScoreComponent("Attack cost", 100.0, cfg.WEIGHT_ATTACK_COST,
                           "target unreachable from source"),
            ScoreComponent("Path diversity", 100.0, cfg.WEIGHT_PATH_DIVERSITY,
                           "no attack paths exist"),
            ScoreComponent("Mitigation effort", 100.0, cfg.WEIGHT_MITIGATION,
                           "nothing to mitigate"),
            ScoreComponent("Exposure", 100.0, cfg.WEIGHT_EXPOSURE,
                           "zero exposure"),
        ]
        return 100.0, comp

    # 1. Attack cost: higher d(s,t) -> higher score.
    cost = metrics.shortest_path_cost or 0.0
    attack_cost_score = _clamp(cost / cfg.COST_SCALE * 100.0)

    # 2. Path diversity: fewer tied shortest paths -> higher score.
    diversity_score = _clamp(
        100.0 - cfg.SHORTEST_PATH_PENALTY * max(0, metrics.num_shortest_paths - 1)
    )

    # 3. Mitigation effort: smaller min vertex cut -> higher score.
    mitigation_score = _clamp(
        100.0 - cfg.CUT_PENALTY * metrics.min_vertex_cut_size
    )

    # 4. Exposure: fewer total attack paths -> higher score.
    exposure_score = _clamp(
        100.0 - cfg.ATTACK_PATH_PENALTY * max(0, metrics.num_attack_paths - 1)
    )

    components = [
        ScoreComponent(
            "Attack cost", attack_cost_score, cfg.WEIGHT_ATTACK_COST,
            f"d(s,t) = {cost:g}",
        ),
        ScoreComponent(
            "Path diversity", diversity_score, cfg.WEIGHT_PATH_DIVERSITY,
            f"{metrics.num_shortest_paths} shortest path(s)",
        ),
        ScoreComponent(
            "Mitigation effort", mitigation_score, cfg.WEIGHT_MITIGATION,
            f"min vertex cut |C*| = {metrics.min_vertex_cut_size} "
            f"({sorted(metrics.min_vertex_cut) or '-'})",
        ),
        ScoreComponent(
            "Exposure", exposure_score, cfg.WEIGHT_EXPOSURE,
            f"{metrics.num_attack_paths} attack path(s)",
        ),
    ]
    score = sum(c.score * c.weight for c in components)
    return round(score, 2), components


# --------------------------------------------------------------------------- #
# Findings / recommendations.
# --------------------------------------------------------------------------- #
def _build_findings(spec: GraphSpec, metrics: SecurityMetrics,
                    components: List[ScoreComponent]) -> List[str]:
    """Produce plain-language security findings using the network's vocabulary.

    The analysis is identical for every domain; the :class:`NetworkKind`
    supplies the words ("junction" vs "vulnerability", "route" vs "attack
    path") so the findings read naturally for transport, supply-chain,
    social, and cyber networks alike.
    """
    findings: List[str] = []
    kind = get_kind(spec.kind)

    if not metrics.is_reachable:
        findings.append(
            f"{kind.target_term.capitalize()} '{spec.target}' is NOT reachable "
            f"from {kind.source_term} '{spec.source}'. The network is fully "
            f"secured against this threat model."
        )
        return findings

    first_path = (
        ' -> '.join(metrics.shortest_paths[0]) if metrics.shortest_paths else 'n/a'
    )
    findings.append(
        f"{kind.target_term.capitalize()} '{spec.target}' IS reachable from "
        f"{kind.source_term} '{spec.source}'. Cheapest {kind.path_term} costs "
        f"d(s,t) = {metrics.shortest_path_cost:g} "
        f"(lowest-resistance {kind.path_term}: {first_path})."
    )

    if metrics.num_shortest_paths > 1:
        findings.append(
            f"{metrics.num_shortest_paths} distinct shortest {kind.path_term}s "
            f"tie for the minimum cost -- the {kind.threat_term} has equally "
            f"cheap alternatives."
        )

    if metrics.num_attack_paths > 3:
        findings.append(
            f"High path multiplicity: {metrics.num_attack_paths} distinct "
            f"{kind.path_term}s exist. Consider network segmentation to prune "
            f"routes."
        )

    findings.append(
        f"Maximum vertex-disjoint {kind.path_term}s = "
        f"{metrics.max_vertex_disjoint_paths} (Menger). Minimum vertex cut "
        f"|C*| = {metrics.min_vertex_cut_size}: {kind.mitigating} "
        f"{sorted(metrics.min_vertex_cut) or 'nothing'} severs every "
        f"{kind.path_term}. These are the highest-priority mitigations."
    )

    if metrics.num_min_vertex_cuts > 1:
        findings.append(
            f"{metrics.num_min_vertex_cuts} distinct minimum vertex cuts of "
            f"size {metrics.min_vertex_cut_size} exist (the one above is one "
            f"valid choice). Any of them is an equally minimal mitigation set."
        )

    if metrics.min_vertex_cut_size >= 3:
        findings.append(
            f"A large minimum cut ({metrics.min_vertex_cut_size}) means many "
            f"{kind.vertex_term}s must be {kind.mitigate_verb}ed "
            f"simultaneously to fully disconnect the {kind.target_term} -- "
            f"priorise defence-in-depth and monitoring instead."
        )

    if metrics.cut_node_betweenness:
        top_node, top_val = max(
            metrics.cut_node_betweenness.items(), key=lambda kv: kv[1]
        )
        role = spec.node_roles.get(top_node, "unknown role")
        findings.append(
            f"Most critical chokepoint: '{top_node}' ({role}) with betweenness "
            f"centrality {top_val} -- {kind.mitigate_verb} or isolate it first."
        )

    weak = [c.name for c in components if c.score < 40]
    if weak:
        findings.append(
            "Weakest security dimensions: " + ", ".join(weak) + "."
        )
    return findings


# --------------------------------------------------------------------------- #
# Top-level entry point.
# --------------------------------------------------------------------------- #
def analyze(spec: GraphSpec, cfg: ScoringConfig = ScoringConfig()) -> SecurityReport:
    """Run the complete analysis pipeline and return a :class:`SecurityReport`."""
    from .vulnerabilities import compute_vulnerabilities

    metrics = compute_metrics(spec)
    score, components = compute_score(metrics, cfg)
    grade = _grade(score)
    findings = _build_findings(spec, metrics, components)
    vulnerabilities = compute_vulnerabilities(spec, metrics)
    return SecurityReport(
        spec=spec,
        metrics=metrics,
        components=components,
        score=score,
        grade=grade,
        findings=findings,
        vulnerabilities=vulnerabilities,
    )
