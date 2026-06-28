"""Vulnerability hotspot detection -- *where* the weak points are.

The scoring engine answers "how secure is the network overall?" and the
connectivity routines answer "what is the minimum set of nodes to defend?".
This module answers the more pointed question an analyst actually asks:

    *"Where, exactly, are the vulnerabilities -- and why does each one matter?"*

For every node it combines two complementary security views:

* **Exposure** (the attacker's view) -- how cheaply the node can be reached
  from the entry point, and whether it lies on the cheapest attack path. A
  node that is cheap to reach is the *first to fall*.
* **Criticality** (the defender's view) -- whether the node is a chokepoint
  (high betweenness), carries a large fraction of all attack paths, belongs
  to the minimum vertex cut, or is a *single point of failure* (on every
  single attack path). A critical node, once lost, is catastrophic.

A node that is **both cheap to reach and highly critical** is the worst
vulnerability, so each node is given a 0-100 vulnerability score and a
severity (Critical / High / Medium / Low), together with plain-language
reasons in the network domain's own vocabulary.

The same detector runs unchanged on cyber, transport, supply-chain, and
social networks -- "where is the vulnerability" is a universal question.
"""

from __future__ import annotations

from typing import List

import networkx as nx

from .builder import build_digraph
from .domains import get_kind
from .models import GraphSpec, NodeVulnerability, SecurityMetrics, VulnerabilityReport
from .shortest_paths import all_attack_paths, bellman_ford

_INF = float("inf")


# --------------------------------------------------------------------------- #
# Internal helpers.
# --------------------------------------------------------------------------- #
def _severity(score: float, reachable: bool) -> str:
    if not reachable:
        return "Safe"
    if score >= 80:
        return "Critical"
    if score >= 60:
        return "High"
    if score >= 40:
        return "Medium"
    return "Low"


def _reasons(v: "NodeVulnerability", kind, metrics: SecurityMetrics) -> None:
    """Fill ``v.reasons`` with domain-aware plain-language explanations."""
    if v.on_all_paths:
        v.reasons.append(
            f"single point of failure: appears on every {kind.path_term} "
            f"({metrics.num_attack_paths} total)"
        )
    if v.in_min_cut:
        v.reasons.append(
            f"in the minimum defense set -- {kind.mitigating} it severs "
            f"every {kind.path_term}"
        )
    if v.on_shortest_path:
        v.reasons.append(
            f"on the cheapest {kind.path_term} (first to {kind.traverse_verb})"
        )
    if v.betweenness >= 0.10:
        v.reasons.append(
            f"critical chokepoint (betweenness {v.betweenness:.2f})"
        )
    if v.path_coverage >= 0.5:
        v.reasons.append(
            f"carries {v.path_coverage * 100:.0f}% of all {kind.path_term}s"
        )
    if v.reachable and v.dist_from_source is not None:
        v.reasons.append(
            f"easily reached -- only {v.dist_from_source:g} "
            f"{kind.weight_term} from {kind.source_term}"
        )


# --------------------------------------------------------------------------- #
# Public API.
# --------------------------------------------------------------------------- #
def compute_vulnerabilities(
    spec: GraphSpec, metrics: SecurityMetrics
) -> VulnerabilityReport:
    """Identify and rank the vulnerabilities in ``spec``.

    Combines reachability cost, betweenness, path coverage, minimum-cut
    membership, and single-point-of-failure status into a per-node score.
    """
    kind = get_kind(spec.kind)
    graph = build_digraph(spec)

    # Distance from the source to every node (exposure).
    edges = [(u, v, d["weight"]) for u, v, d in graph.edges(data=True)]
    dist, _, _, _ = bellman_ford(spec.vertices, edges, spec.source, verbose=False)

    # Full betweenness centrality (criticality across all shortest paths).
    betweenness = nx.betweenness_centrality(graph, weight="weight", normalized=True)

    # Membership of the cheapest attack path(s).
    shortest_nodes = set()
    for p in metrics.shortest_paths:
        shortest_nodes.update(p)

    # Path coverage + single-point-of-failure, over ALL simple s-t paths.
    attack_paths = all_attack_paths(graph, spec.source, spec.target)
    path_count = len(attack_paths)
    coverage = {n: 0 for n in spec.vertices}
    for p in attack_paths:
        for n in set(p):
            coverage[n] += 1
    on_all = {
        n: (path_count > 0 and coverage[n] == path_count and n not in (spec.source, spec.target))
        for n in spec.vertices
    }

    # Easiest-reachable cost, used to normalise "ease".
    reachable_dists = [d for d in dist.values() if d != _INF and d > 0]
    max_dist = max(reachable_dists) if reachable_dists else 1.0

    min_cut = metrics.min_vertex_cut
    hotspots: List[NodeVulnerability] = []

    for n in spec.vertices:
        if n in (spec.source, spec.target):
            continue  # endpoints are not assessed as vulnerabilities
        d = dist[n]
        reachable = d != _INF
        b = round(betweenness.get(n, 0.0), 4)
        cov = (coverage[n] / path_count) if path_count else 0.0
        cov = round(cov, 4)

        # --- score: blend exposure (ease) and criticality ----------------
        if reachable and d > 0:
            ease = max(0.0, 1.0 - (d / max_dist))      # closer => easier => higher
        else:
            ease = 0.0
        criticality = 0.5 * b + 0.5 * cov
        score = 100.0 * (0.45 * ease + 0.55 * criticality)

        on_sp = n in shortest_nodes
        in_cut = n in min_cut

        # Rule-based severity floors (guarantee intuitive bands).
        if on_all[n]:
            score = max(score, 90.0)
        elif in_cut:
            score = max(score, 70.0)
        elif on_sp:
            score = max(score, 50.0)

        score = round(min(100.0, max(0.0, score)), 1)
        sev = _severity(score, reachable)

        v = NodeVulnerability(
            node=n,
            role=spec.node_roles.get(n, ""),
            reachable=reachable,
            dist_from_source=(d if reachable else None),
            betweenness=b,
            path_coverage=cov,
            on_shortest_path=on_sp,
            on_all_paths=on_all[n],
            in_min_cut=in_cut,
            score=score,
            severity=sev,
        )
        _reasons(v, kind, metrics)
        hotspots.append(v)

    # Worst vulnerabilities first; unreachable nodes sink to the bottom.
    hotspots.sort(
        key=lambda v: (v.reachable, v.score, v.betweenness), reverse=True
    )
    has_spof = any(v.on_all_paths for v in hotspots)

    return VulnerabilityReport(
        hotspots=hotspots,
        attack_path_count=path_count,
        has_single_point_of_failure=has_spof,
    )
