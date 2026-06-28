# SPDX-FileCopyrightText: 2026 Mohamed Khaled <mohamedabdelfatah572@aucegypt.edu>
# SPDX-License-Identifier: MIT

"""Connectivity analysis -- Menger's-theorem machinery.

Provides the two sides of Menger's equality for an s-t pair:

* the **maximum number of internally vertex-disjoint s-t paths**, and
* the **minimum s-t vertex cut** (its cardinality equals the above).

Two independent routes are offered for the vertex cut:

1. NetworkX's flow-based :func:`networkx.minimum_node_cut`, and
2. an explicit **vertex-splitting transformation** (``v_in -> v_out`` with
   capacity 1) solved with max-flow min-cut -- included for transparency and
   to mirror the paper's exposition.

A brute-force :func:`all_minimum_vertex_cuts` enumerates every minimum cut so a
specific canonical answer (e.g. the paper's ``{v4, v5}``) can be validated even
when the flow solver breaks ties differently.
"""

from __future__ import annotations

from itertools import combinations
from typing import List, Set, Tuple

import networkx as nx


def max_vertex_disjoint_paths(
    graph: nx.DiGraph, source: str, target: str
) -> Tuple[int, List[List[str]]]:
    """Maximum number of internally vertex-disjoint s-t paths (Menger LHS)."""
    if not nx.has_path(graph, source, target):
        return 0, []
    paths = [list(p) for p in nx.node_disjoint_paths(graph, source, target)]
    return len(paths), paths


def min_vertex_cut(graph: nx.DiGraph, source: str, target: str) -> Set[str]:
    """Minimum-cardinality s-t vertex cut via NetworkX (Menger RHS)."""
    if not nx.has_path(graph, source, target):
        return set()
    return set(nx.minimum_node_cut(graph, source, target))


def vertex_splitting_min_cut(
    graph: nx.DiGraph, source: str, target: str, big: float = 1e9
) -> Tuple[float, Set[str]]:
    """Minimum vertex cut via an explicit vertex-splitting transformation.

    Each vertex ``v`` is split into ``v_in -> v_out``:

    * capacity 1 for internal vertices (eligible to be cut),
    * capacity ``big`` for ``s`` and ``t`` (cannot belong to a vertex cut).

    Each original edge ``(u, v)`` becomes ``u_out -> v_in`` with capacity
    ``big`` (never chosen).  The min *edge* cut in the split graph then has
    capacity equal to the min *vertex* cut, and each cut edge maps back to a
    vertex.
    """
    if not nx.has_path(graph, source, target):
        return 0.0, set()

    split = nx.DiGraph()
    for node in graph.nodes:
        capacity = big if node in (source, target) else 1
        split.add_edge(f"{node}_in", f"{node}_out", capacity=capacity)
    for u, v in graph.edges:
        split.add_edge(f"{u}_out", f"{v}_in", capacity=big)

    cut_value, (reachable, non_reachable) = nx.minimum_cut(
        split, f"{source}_in", f"{target}_out"
    )
    cut_vertices: Set[str] = set()
    for u in reachable:
        for v in split.successors(u):
            if v in non_reachable and split[u][v]["capacity"] == 1:
                cut_vertices.add(u.replace("_in", ""))
    return cut_value, cut_vertices


def min_edge_cut_size(graph: nx.DiGraph, source: str, target: str) -> int:
    """Cardinality of the minimum s-t *edge* cut (== max edge-disjoint paths)."""
    if not nx.has_path(graph, source, target):
        return 0
    try:
        return len(nx.minimum_edge_cut(graph, source, target))
    except nx.NetworkXError:
        return 0


def all_minimum_vertex_cuts(
    graph: nx.DiGraph, source: str, target: str, max_size: int = 6
) -> Tuple[int, List[Set[str]]]:
    """Exhaustively enumerate every minimum s-t vertex cut.

    Deterministic, so it can confirm a specific cut (e.g. ``{v4, v5}``) is
    genuinely minimum even when flow-based solvers return a different tie.
    The search is bounded by ``max_size`` to stay tractable on large graphs.
    """
    if not nx.has_path(graph, source, target):
        return 0, [set()]
    internal = [v for v in graph.nodes if v not in (source, target)]
    for size in range(1, min(max_size, len(internal)) + 1):
        cuts: List[Set[str]] = []
        for combo in combinations(internal, size):
            survivors = [n for n in graph.nodes if n not in combo]
            if not nx.has_path(graph.subgraph(survivors), source, target):
                cuts.append(set(combo))
        if cuts:
            return size, cuts
    return 0, []
