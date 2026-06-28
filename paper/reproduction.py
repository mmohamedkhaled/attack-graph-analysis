#!/usr/bin/env python3
# -*- coding: utf-8 -*-
"""
Attack Graph Analysis  --  Graph Theory Implementation
=======================================================

A complete, modular implementation of the empirical analysis described in the
research paper:

    "Attack Graph Analysis: A Graph Theory Research Paper"
        Mohamed Khaled, Malak Ahmed, Hoda Hussein, Ali Elkhouly  (May 2026)

A university campus network is modelled as a directed weighted acyclic graph
(DAG) in which:

    * Vertices  -> known vulnerabilities / hosts.
    * Edges     -> feasible exploit transitions.
    * Weights   -> exploit difficulty (cost).

The script performs the three core analyses of the paper:

    1. Reconstructs the exact attack graph  G = (V, E, w).
    2. Runs a *custom* Bellman-Ford implementation with an iteration-by-iteration
       trace that reproduces the paper's convergence on Iteration 2 with a
       shortest path cost d(s, t) = 11, and extracts the two *tied* shortest
       paths.
    3. Verifies Menger's Theorem by computing both the maximum number of
       internally vertex-disjoint s-t paths and the minimum vertex cut
       (via a vertex-splitting transformation), proving that
       Max Disjoint Paths == Min Vertex Cut == 2, with C* = {v4, v5}.
    4. Produces a professional, layered Matplotlib visualisation with the
       minimum vertex cut nodes highlighted in red.

Dependencies
------------
    * networkx   (graph algorithms)
    * matplotlib (visualisation)

Run with::

    python3 paper/reproduction.py
"""

from __future__ import annotations

import sys
from itertools import combinations
from typing import Dict, List, Optional, Set, Tuple

# ---------------------------------------------------------------------------
# Dependency guard -- fail loudly with a helpful message if anything is missing.
# ---------------------------------------------------------------------------
try:
    import matplotlib.pyplot as plt
    import networkx as nx
except ImportError as exc:  # pragma: no cover - environmental
    MISSING = exc.name
    print(
        f"\n[ERROR] Missing required dependency: '{MISSING}'.\n"
        "Please install the required libraries before running:\n\n"
        "    pip install networkx matplotlib\n"
    )
    sys.exit(1)


# ===========================================================================
# 1. GRAPH SPECIFICATION  (Section 3 of the paper)
# ===========================================================================

#: Ordered vertex set V = {s, v1, ..., v7, t}.
#: The source ``s`` is the public web server (Layer 0) and the sink ``t`` is the
#: records database (Layer 4).
VERTICES: List[str] = ["s", "v1", "v2", "v3", "v4", "v5", "v6", "v7", "t"]

#: Source and target labels.
SOURCE: str = "s"
TARGET: str = "t"

#: Weighted directed edges, kept in the *exact scanning order* used by the
#: paper's Bellman-Ford trace (Section 4.6).  Each tuple is (u, v, w).
EDGES: List[Tuple[str, str, int]] = [
    ("s", "v1", 2),
    ("s", "v2", 4),
    ("s", "v3", 3),
    ("v1", "v4", 3),
    ("v2", "v4", 2),
    ("v3", "v5", 5),
    ("v4", "v5", 4),
    ("v4", "v7", 3),
    ("v5", "v6", 2),
    ("v6", "t", 1),
    ("v7", "t", 3),
]

#: The minimum vertex cut identified by the paper (Section 5.3).
PAPER_MIN_VERTEX_CUT: Set[str] = {"v4", "v5"}

#: Topological layers used purely for the layered layout (left -> right).
LAYERS: Dict[int, List[str]] = {
    0: ["s"],
    1: ["v1", "v2", "v3"],
    2: ["v4", "v5"],
    3: ["v6", "v7"],
    4: ["t"],
}


def build_attack_graph() -> nx.DiGraph:
    """Construct the directed weighted attack graph G = (V, E, w).

    Returns
    -------
    networkx.DiGraph
        A DAG whose nodes are ``VERTICES`` and whose edges carry an integer
        ``weight`` attribute equal to the exploit cost.
    """
    graph = nx.DiGraph(name="University Campus Network Attack Graph")
    graph.add_nodes_from(VERTICES)
    for source, destination, weight in EDGES:
        graph.add_edge(source, destination, weight=weight)
    return graph


# ===========================================================================
# 2. CUSTOM BELLMAN-FORD  (Sections 4.3 - 4.6 of the paper)
# ===========================================================================

_INF = float("inf")


def _format_dist(dist: Dict[str, float]) -> str:
    """Return a compact, readable rendering of the distance vector."""
    parts = [f"dist[{v}] = {int(d) if d != _INF else 'inf'}" for v, d in dist.items()]
    return "[" + ", ".join(parts) + "]"


def _format_pred(pred: Dict[str, Optional[str]]) -> str:
    """Return a compact, readable rendering of the predecessor vector."""
    parts = [f"pred[{v}] = {p if p is not None else 'NIL'}" for v, p in pred.items()]
    return "[" + ", ".join(parts) + "]"


def bellman_ford(
    vertices: List[str],
    edges: List[Tuple[str, str, int]],
    source: str,
    verbose: bool = True,
) -> Tuple[Dict[str, float], Dict[str, Optional[str]], int]:
    """Run the Bellman-Ford single-source shortest-path algorithm from scratch.

    The implementation follows the pseudocode of Section 4.4 of the paper and,
    when ``verbose`` is True, prints an iteration-by-iteration trace of every
    edge relaxation together with the evolving ``dist`` and ``predecessor``
    vectors.

    Parameters
    ----------
    vertices : list of str
        The vertex set V (insertion order is preserved for tidy logging).
    edges : list of (u, v, w)
        The weighted directed edge list, in the scanning order of the paper.
    source : str
        The source vertex ``s``.
    verbose : bool, default True
        Whether to print the detailed step-by-step trace.

    Returns
    -------
    dist : dict
        Mapping vertex -> shortest-path distance from ``source``.
    pred : dict
        Mapping vertex -> predecessor on a shortest path (None if none).
    converged_at : int
        The 1-based iteration index on which the values stabilised.
    """
    # --- INITIALIZE (pseudocode lines 1-5) --------------------------------
    dist: Dict[str, float] = {v: _INF for v in vertices}
    pred: Dict[str, Optional[str]] = {v: None for v in vertices}
    dist[source] = 0

    n = len(vertices)  # |V|; outer loop runs at most |V| - 1 times.

    if verbose:
        print("=" * 78)
        print(" BELLMAN-FORD  --  Iteration-by-Iteration Trace")
        print("=" * 78)
        print(f"Graph has |V| = {n} vertices  ->  at most |V|-1 = {n - 1} iterations.")
        print("INITIALISATION:")
        print(f"  {_format_dist(dist)}")
        print(f"  {_format_pred(pred)}\n")

    converged_at = 0

    # --- RELAX (pseudocode lines 6-11) ------------------------------------
    for iteration in range(1, n):
        updated = False

        if verbose:
            print("-" * 78)
            print(f"ITERATION {iteration}")
            print("-" * 78)
            print(f"  Starting state: {_format_dist(dist)}")

        for source_node, dest_node, weight in edges:
            old = dist[dest_node]
            candidate = dist[source_node] + weight
            if candidate < old:
                # Relaxation succeeds -> record the improvement.
                pred[dest_node] = source_node
                dist[dest_node] = candidate
                updated = True
                if verbose:
                    old_repr = int(old) if old != _INF else "inf"
                    print(
                        f"  Edge ({source_node:>2},{dest_node:>2}) w={weight}: "
                        f"{int(candidate)} < {old_repr}  -> UPDATE  "
                        f"dist[{dest_node}]={int(candidate)}, "
                        f"pred[{dest_node}]={source_node}"
                    )
            else:
                # No improvement -> explain *why* (matches the paper's notes).
                if verbose:
                    old_repr = int(old) if old != _INF else "inf"
                    relation = "=" if candidate == old else ">"
                    print(
                        f"  Edge ({source_node:>2},{dest_node:>2}) w={weight}: "
                        f"{int(candidate)} {relation} {old_repr}  -> no update"
                    )

        if verbose:
            print(f"\n  After iteration {iteration}:")
            print(f"    {_format_dist(dist)}")
            print(f"    {_format_pred(pred)}\n")

        # Early termination: if a full pass changes nothing, we have converged.
        if not updated:
            converged_at = iteration
            if verbose:
                print("*" * 78)
                print(
                    f" CONVERGED on Iteration {iteration}: no distance was updated.\n"
                    f" Iterations {iteration + 1}..{n - 1} would likewise make no changes."
                )
                print("*" * 78 + "\n")
            break
    else:
        # Loop completed without early break (should not happen for a DAG).
        converged_at = n - 1

    return dist, pred, converged_at


# ===========================================================================
# 2b. EXTRACTING THE (TIED) SHORTEST PATHS
# ===========================================================================

def build_shortest_path_dag(
    dist: Dict[str, float], edges: List[Tuple[str, str, int]]
) -> nx.DiGraph:
    """Build the shortest-path sub-DAG.

    An edge (u, v) belongs to *some* shortest path exactly when
    ``dist[u] + w(u, v) == dist[v]``.  Collecting all such edges yields the
    sub-graph that contains **every** shortest path from the source, which lets
    us recover *tied* shortest paths that a single predecessor pointer cannot.
    """
    dag = nx.DiGraph()
    for u, v, w in edges:
        if dist[u] != _INF and dist[u] + w == dist[v]:
            dag.add_edge(u, v, weight=w)
    return dag


def enumerate_simple_paths(
    dag: nx.DiGraph, source: str, target: str
) -> List[List[str]]:
    """Enumerate every simple s-t path inside the shortest-path DAG."""
    if source not in dag or target not in dag:
        return []
    return list(nx.all_simple_paths(dag, source=source, target=target))


def path_cost(path: List[str], edges: List[Tuple[str, str, int]]) -> int:
    """Sum the weights along a given vertex path."""
    lookup = {(u, v): w for u, v, w in edges}
    return sum(lookup[(path[i], path[i + 1])] for i in range(len(path) - 1))


# ===========================================================================
# 3. MENGER'S THEOREM  (Section 5 of the paper)
# ===========================================================================

def max_vertex_disjoint_paths(
    graph: nx.DiGraph, source: str, target: str
) -> Tuple[int, List[List[str]]]:
    """Maximum number of internally vertex-disjoint s-t paths (Menger's LHS).

    Uses NetworkX's flow-based node-disjoint path routine (which itself applies
    a vertex-splitting transformation internally).
    """
    paths = list(nx.node_disjoint_paths(graph, source, target))
    return len(paths), paths


def minimum_vertex_cut(
    graph: nx.DiGraph, source: str, target: str
) -> Set[str]:
    """Minimum-cardinality s-t vertex cut via NetworkX (Menger's RHS)."""
    return set(nx.minimum_node_cut(graph, source, target))


def vertex_splitting_min_cut(
    graph: nx.DiGraph, source: str, target: str, big: float = 1e9
) -> Tuple[float, Set[str]]:
    """Minimum vertex cut via an explicit vertex-splitting transformation.

    Each vertex ``v`` is split into ``v_in -> v_out`` with capacity:

        * 1      for every internal vertex (it *can* be cut),
        * ``big`` for ``s`` and ``t`` (they cannot belong to a vertex cut).

    Every original edge ``(u, v)`` becomes ``u_out -> v_in`` with capacity
    ``big`` so it is never chosen by the min-cut.  The capacity of the resulting
    minimum *edge* cut is then exactly the cardinality of the minimum *vertex*
    cut, and each cut edge ``(v_in, v_out)`` maps back to the original vertex.
    """
    split_graph = nx.DiGraph()

    # Split every node.
    for node in graph.nodes:
        capacity = big if node in (source, target) else 1
        split_graph.add_edge(f"{node}_in", f"{node}_out", capacity=capacity)

    # Rewire original edges across the split boundary.
    for u, v in graph.edges:
        split_graph.add_edge(f"{u}_out", f"{v}_in", capacity=big)

    cut_value, (reachable, non_reachable) = nx.minimum_cut(
        split_graph, f"{source}_in", f"{target}_out"
    )

    # Recover the cut edges that sit *inside* a vertex (capacity == 1).
    cut_vertices: Set[str] = set()
    for u in reachable:
        for v in split_graph[u]:
            if v in non_reachable and split_graph[u][v]["capacity"] == 1:
                cut_vertices.add(u.replace("_in", ""))

    return cut_value, cut_vertices


def all_minimum_vertex_cuts(
    graph: nx.DiGraph, source: str, target: str
) -> Tuple[int, List[Set[str]]]:
    """Brute-force enumerate *every* minimum s-t vertex cut.

    This deterministic check complements the flow-based routines and lets us
    confirm that the paper's set ``{v4, v5}`` is genuinely one of the minimum
    cuts (NetworkX's flow solver may return any valid one of them).
    """
    internal = [v for v in graph.nodes if v not in (source, target)]
    for size in range(1, len(internal) + 1):
        cuts = [
            set(combo)
            for combo in combinations(internal, size)
            if not nx.has_path(
                graph.subgraph(
                    [n for n in graph.nodes if n not in combo]
                ),
                source,
                target,
            )
        ]
        if cuts:  # The smallest size with at least one cut is the minimum.
            return size, cuts
    return 0, []


# ===========================================================================
# 4. VISUALISATION  (Section 3.4 / Figure 1 of the paper)
# ===========================================================================

def layered_positions(layers: Dict[int, List[str]]) -> Dict[str, Tuple[float, float]]:
    """Hand-tuned left-to-right layout mirroring Figure 1 of the paper.

    x grows from the source (Layer 0) on the left to the target (Layer 4) on
    the right; y is set so that v1/v4/v7 sit on the upper channel and
    v3/v5/v6 on the lower channel, exactly like the paper's diagram.
    """
    # Generously spaced coordinates so labels never collide.  x grows
    # left -> right (source to target); the upper channel holds v1/v4/v7 and
    # the lower channel holds v3/v5/v6, mirroring Figure 1 of the paper.
    return {
        # Layer 0 -- source
        "s":  (0.00, 0.00),
        # Layer 1 -- first hop (wide vertical spread)
        "v1": (1.70, 1.50),
        "v2": (1.70, 0.00),
        "v3": (1.70, -1.50),
        # Layer 2 -- pivot / AD server
        "v4": (3.40, 0.80),
        "v5": (3.40, -1.00),
        # Layer 3 -- penultimate hop
        "v6": (5.10, -1.00),
        "v7": (5.10, 0.80),
        # Layer 4 -- target
        "t":  (6.80, 0.00),
    }


def visualize_attack_graph(
    graph: nx.DiGraph,
    cut_nodes: Set[str],
    shortest_paths: List[List[str]],
    output_path: str = "figure.png",
) -> None:
    """Render a high-resolution, publication-style plot of the attack graph.

    Parameters
    ----------
    graph : networkx.DiGraph
        The attack graph to draw.
    cut_nodes : set of str
        Minimum vertex cut nodes, drawn in red ("patched vulnerabilities").
    shortest_paths : list of paths
        The tied shortest paths, emphasised with thicker/coloured edges.
    output_path : str
        Where to save the resulting PNG figure.
    """
    pos = layered_positions(LAYERS)

    # --- Colour palette ---------------------------------------------------
    node_colours = []
    for node in graph.nodes:
        if node in cut_nodes:
            node_colours.append("#E63946")   # red  -> patched / mitigated
        elif node == SOURCE:
            node_colours.append("#2A9D8F")   # teal -> attacker entry point
        elif node == TARGET:
            node_colours.append("#F4A261")   # gold -> protected database
        else:
            node_colours.append("#8AB4D6")   # soft blue -> ordinary host

    # Mark the edges that lie on any shortest path so we can highlight them.
    shortest_edges: Set[Tuple[str, str]] = set()
    for path in shortest_paths:
        for i in range(len(path) - 1):
            shortest_edges.add((path[i], path[i + 1]))

    # --- Draw -------------------------------------------------------------
    fig, ax = plt.subplots(figsize=(17, 9), dpi=150)

    nx.draw_networkx_nodes(
        graph,
        pos,
        ax=ax,
        node_size=3200,
        node_color=node_colours,
        edgecolors="#1d3557",
        linewidths=2.0,
    )
    nx.draw_networkx_labels(
        graph,
        pos,
        ax=ax,
        font_size=14,
        font_weight="bold",
        font_color="white",
    )

    # The (v4, v5) edge is vertical (same x), so draw it curved to free up the
    # space its label would otherwise share with the node labels.  Everything
    # else is drawn straight.
    curved_edges = [("v4", "v5")]
    straight_edges = [(u, v) for u, v in graph.edges if (u, v) not in curved_edges]

    # Straight edges.
    nx.draw_networkx_edges(
        graph,
        pos,
        ax=ax,
        edgelist=straight_edges,
        edge_color=[
            "#264653" if (u, v) in shortest_edges else "#B0B0B0"
            for u, v in straight_edges
        ],
        width=[2.6 if (u, v) in shortest_edges else 1.5 for u, v in straight_edges],
        arrows=True,
        arrowstyle="-|>",
        arrowsize=28,
        connectionstyle="arc3,rad=0.0",
        node_size=3200,
    )
    # Curved (v4, v5) edge, bowed to the right into the empty inter-column gap.
    nx.draw_networkx_edges(
        graph,
        pos,
        ax=ax,
        edgelist=curved_edges,
        edge_color=["#B0B0B0"],
        width=[1.5],
        arrows=True,
        arrowstyle="-|>",
        arrowsize=28,
        connectionstyle="arc3,rad=0.45",
        node_size=3200,
    )

    # --- Edge weight labels ----------------------------------------------
    # Fully opaque white boxes so a label cleanly masks anything beneath it,
    # and a *per-edge* position so converging edges (into v4 and into t) do not
    # stack their labels on top of one another.
    edge_labels = {(u, v): f"{d['weight']}" for u, v, d in graph.edges(data=True)}
    label_pos = {
        ("s", "v1"): 0.5,
        ("s", "v2"): 0.35,
        ("s", "v3"): 0.5,
        ("v1", "v4"): 0.55,
        ("v2", "v4"): 0.40,
        ("v3", "v5"): 0.5,
        ("v4", "v5"): 0.5,   # handled manually below (curved edge)
        ("v4", "v7"): 0.5,
        ("v5", "v6"): 0.5,
        ("v6", "t"): 0.40,
        ("v7", "t"): 0.60,
    }
    label_bbox = dict(
        boxstyle="round,pad=0.30",
        facecolor="white",
        edgecolor="#bbbbbb",
        alpha=1.0,
    )

    for edge, text in edge_labels.items():
        if edge == ("v4", "v5"):
            # Place this label out in the empty gap the curve bows into.
            mx = (pos["v4"][0] + pos["v5"][0]) / 2 + 0.62
            my = (pos["v4"][1] + pos["v5"][1]) / 2
            ax.text(
                mx, my, text,
                fontsize=13, fontweight="bold", color="#1d3557",
                ha="center", va="center", zorder=5, bbox=label_bbox,
            )
            continue
        nx.draw_networkx_edge_labels(
            graph,
            pos,
            ax=ax,
            edge_labels={edge: text},
            label_pos=label_pos[edge],
            font_size=13,
            font_color="#1d3557",
            font_weight="bold",
            bbox=label_bbox,
        )

    # --- Legend & cosmetics ----------------------------------------------
    from matplotlib.patches import Patch

    legend_handles = [
        Patch(facecolor="#2A9D8F", edgecolor="#1d3557", label="Source 's' (web server)"),
        Patch(facecolor="#F4A261", edgecolor="#1d3557", label="Target 't' (records DB)"),
        Patch(facecolor="#E63946", edgecolor="#1d3557",
              label="Min vertex cut {v4, v5}  -- patched / mitigated"),
        Patch(facecolor="#8AB4D6", edgecolor="#1d3557", label="Other vulnerable hosts"),
    ]
    ax.legend(handles=legend_handles, loc="upper center",
              bbox_to_anchor=(0.5, 1.10), ncol=2, frameon=False, fontsize=10)

    ax.set_title(
        "University Campus Network Attack Graph  (Directed Weighted DAG)\n"
        "Shortest attack cost d(s, t) = 11   |   Min vertex cut |C*| = 2",
        fontsize=14, fontweight="bold", pad=24,
    )
    ax.axis("off")
    plt.tight_layout()
    plt.savefig(output_path, dpi=200, bbox_inches="tight")
    print(f"[Visualisation] Saved high-resolution figure -> {output_path}")
    plt.show()


# ===========================================================================
# DRIVER
# ===========================================================================

def _print_header(title: str) -> None:
    print("\n" + "#" * 78)
    print(f"# {title}")
    print("#" * 78)


def main() -> None:
    """Run the full attack-graph analysis pipeline end to end."""

    # --- 1. Build the graph ----------------------------------------------
    _print_header("1. ATTACK GRAPH CONSTRUCTION  G = (V, E, w)")
    graph = build_attack_graph()
    print(f"Vertices  V = {VERTICES}")
    print(f"|V| = {len(VERTICES)}   |E| = {graph.number_of_edges()}")
    print("Weighted directed edges E:")
    for u, v, w in EDGES:
        print(f"    w({u:>2}, {v:>2}) = {w}")
    if not nx.is_directed_acyclic_graph(graph):
        print("[WARNING] The graph is not a DAG; the paper assumes acyclicity.")

    # --- 2. Custom Bellman-Ford + trace ----------------------------------
    _print_header("2. CUSTOM BELLMAN-FORD  (from-scratch implementation)")
    dist, pred, converged_at = bellman_ford(VERTICES, EDGES, SOURCE, verbose=True)
    print(f"Shortest distance  d(s, t) = {int(dist[TARGET])}")
    print(f"Algorithm converged on Iteration {converged_at}.")

    # --- 2b. Extract the two tied shortest paths -------------------------
    _print_header("2b. SHORTEST PATHS (including the tie)")
    sp_dag = build_shortest_path_dag(dist, EDGES)
    shortest_paths = enumerate_simple_paths(sp_dag, SOURCE, TARGET)

    # Cross-check against NetworkX's own shortest-path routine.
    nx_paths = list(nx.all_shortest_paths(graph, SOURCE, TARGET, weight="weight"))
    assert sorted(map(tuple, shortest_paths)) == sorted(map(tuple, nx_paths)), (
        "Custom shortest-path extraction disagrees with NetworkX."
    )

    for idx, path in enumerate(shortest_paths, start=1):
        arrow_path = " -> ".join(path)
        print(f"  Path {idx}: {arrow_path}   (cost = {path_cost(path, EDGES)})")
    print(f"  => Baseline shortest compromise cost  d(s, t) = {int(dist[TARGET])}")

    # --- 3. Menger's Theorem verification --------------------------------
    _print_header("3. MENGER'S THEOREM  --  vertex-disjoint paths vs. min vertex cut")

    max_k, disjoint_paths = max_vertex_disjoint_paths(graph, SOURCE, TARGET)
    print(f"Max internally vertex-disjoint s-t paths  = {max_k}")
    for i, p in enumerate(disjoint_paths, start=1):
        print(f"    P{i}: {' -> '.join(p)}")

    # Flow-based confirmation of the cardinality (a valid cut, but the solver
    # may break ties differently from the paper -- see exhaustive check below).
    nxcut = minimum_vertex_cut(graph, SOURCE, TARGET)
    flow_value, split_cut = vertex_splitting_min_cut(graph, SOURCE, TARGET)
    print(f"\nMin vertex cut (NetworkX node-cut)        = {sorted(nxcut)}  "
          f"|cardinality| = {len(nxcut)}")
    print(f"Min vertex cut (vertex-splitting max-flow)= {sorted(split_cut)}  "
          f"(max-flow value = {int(flow_value)})")
    print("  [note] Flow solvers return *a* valid minimum cut; the tie is broken")
    print("         arbitrarily, so the algorithmic cut need not equal the paper's.")
    print("         The exhaustive enumeration below proves the canonical answer.")

    # Exhaustive enumeration -> the mathematically authoritative answer.
    min_size, all_cuts = all_minimum_vertex_cuts(graph, SOURCE, TARGET)
    print(f"\nExhaustive search: minimum vertex-cut size = {min_size}; "
          f"{len(all_cuts)} distinct minimum cuts exist:")
    for cut in sorted(all_cuts):
        marker = "  <- paper's C*" if set(cut) == PAPER_MIN_VERTEX_CUT else ""
        print(f"    {sorted(cut)}{marker}")

    # Explicitly prove the paper's C* = {v4, v5}: it disconnects s-t AND no
    # single vertex removal can, so its cardinality (2) is minimal.
    paper_cut_valid = PAPER_MIN_VERTEX_CUT in all_cuts
    print(f"\nThe paper's C* = {sorted(PAPER_MIN_VERTEX_CUT)} is a valid minimum "
          f"vertex cut: {paper_cut_valid}")
    single_vertex_cuts = [
        v for v in graph.nodes
        if v not in (SOURCE, TARGET)
        and not nx.has_path(
            graph.subgraph([n for n in graph.nodes if n != v]), SOURCE, TARGET
        )
    ]
    print(f"Any single vertex whose removal disconnects s-t: "
          f"{single_vertex_cuts or 'NONE -> size-1 cut is impossible'}")
    # Sanity assertion that the chosen C* really breaks reachability.
    assert not nx.has_path(
        graph.subgraph([n for n in graph.nodes if n not in PAPER_MIN_VERTEX_CUT]),
        SOURCE, TARGET,
    ), "The paper's C* does not disconnect s from t!"

    # --- 3b. Menger equality confirmation --------------------------------
    _print_header("3b. MENGER EQUALITY  --  final confirmation")
    print(f"   Max vertex-disjoint paths   == {max_k}")
    print(f"   Min vertex cut cardinality  == {min_size}   "
          f"(== max-flow value {int(flow_value)})")
    equality_holds = (max_k == min_size == int(flow_value))
    print("   " + "-" * 46)
    print(f"   Menger's Theorem holds:  {max_k} == {min_size} == "
          f"{int(flow_value)}  ->  {equality_holds}")

    # --- 4. Visualisation ------------------------------------------------
    _print_header("4. PROFESSIONAL NETWORK VISUALISATION")
    visualize_attack_graph(
        graph,
        cut_nodes=PAPER_MIN_VERTEX_CUT,
        shortest_paths=shortest_paths,
        output_path="figure.png",
    )


if __name__ == "__main__":
    main()
