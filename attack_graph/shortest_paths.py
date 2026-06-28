"""Shortest-path routines, including a from-scratch Bellman-Ford.

The Bellman-Ford implementation here is deliberately *not* a NetworkX shortcut:
it follows the textbook relaxation loop and additionally

* runs an iteration-by-iteration trace when ``verbose=True`` (useful for
  reproducing a paper's convergence table), and
* detects negative-weight cycles (so the toolkit works on arbitrary graphs,
  not just the paper's DAG).
"""

from __future__ import annotations

from typing import Dict, List, Optional, Tuple

import networkx as nx

_INF = float("inf")


def _format(values: Dict[str, float]) -> str:
    return "[" + ", ".join(
        f"{k}={int(v) if v != _INF else 'inf'}" for k, v in values.items()
    ) + "]"


def bellman_ford(
    vertices: List[str],
    edges: List[Tuple[str, str, float]],
    source: str,
    verbose: bool = False,
) -> Tuple[Dict[str, float], Dict[str, Optional[str]], int, bool]:
    """Run Bellman-Ford from ``source``.

    Parameters
    ----------
    vertices : ordered list of vertex labels.
    edges : list of ``(u, v, weight)`` in the desired scanning order.
    source : the source vertex.
    verbose : if True, print the per-iteration relaxation trace.

    Returns
    -------
    dist : dict vertex -> shortest distance (``inf`` if unreachable).
    pred : dict vertex -> predecessor on a shortest path (``None`` if none).
    converged_at : 1-based iteration on which distances stabilised.
    has_negative_cycle : True if a negative-weight cycle is reachable.
    """
    dist: Dict[str, float] = {v: _INF for v in vertices}
    pred: Dict[str, Optional[str]] = {v: None for v in vertices}
    dist[source] = 0

    n = len(vertices)
    converged_at = n - 1

    if verbose:
        print("=" * 72)
        print(" BELLMAN-FORD trace")
        print("=" * 72)
        print(f"|V|={n} -> at most {n - 1} iterations.")
        print(f"init: {_format(dist)}\n")

    # --- relaxation loop (|V|-1 passes) ----------------------------------
    for iteration in range(1, n):
        updated = False
        if verbose:
            print(f"-- Iteration {iteration} | start {_format(dist)}")
        for u, v, w in edges:
            old = dist[v]
            candidate = dist[u] + w
            if dist[u] != _INF and candidate < old:
                dist[v] = candidate
                pred[v] = u
                updated = True
                if verbose:
                    print(f"   ({u:>3},{v:>3}) w={w}: {candidate:g} < "
                          f"{old if old == _INF else int(old)} -> update")
        if verbose and updated:
            print(f"   after: {_format(dist)}\n")
        if not updated:
            converged_at = iteration
            if verbose:
                print(f"\n* Converged on iteration {iteration} (no updates).\n")
            break

    # --- negative-cycle check (one extra pass) ---------------------------
    has_negative_cycle = False
    for u, v, w in edges:
        if dist[u] != _INF and dist[u] + w < dist[v]:
            has_negative_cycle = True
            break

    return dist, pred, converged_at, has_negative_cycle


def shortest_path_dag(
    dist: Dict[str, float], edges: List[Tuple[str, str, float]]
) -> nx.DiGraph:
    """Build the sub-DAG of edges that lie on *some* shortest path.

    An edge ``(u, v)`` qualifies when ``dist[u] + w(u, v) == dist[v]``.
    Enumerating paths inside this DAG recovers every tied shortest path that a
    single predecessor pointer would miss.
    """
    dag = nx.DiGraph()
    for u, v, w in edges:
        if dist[u] != _INF and dist[u] + w == dist[v]:
            dag.add_edge(u, v, weight=w)
    return dag


def all_shortest_paths(
    dist: Dict[str, float],
    edges: List[Tuple[str, str, float]],
    source: str,
    target: str,
) -> List[List[str]]:
    """Return every shortest s-t path (handles ties)."""
    if dist.get(target, _INF) == _INF:
        return []
    dag = shortest_path_dag(dist, edges)
    if source not in dag or target not in dag:
        return []
    return [list(p) for p in nx.all_simple_paths(dag, source, target)]


def all_attack_paths(
    graph: nx.DiGraph, source: str, target: str, cap: int = 5000
) -> List[List[str]]:
    """Enumerate all simple s-t attack paths, capped to avoid combinatorial blow-up."""
    paths: List[List[str]] = []
    for path in nx.all_simple_paths(graph, source, target):
        paths.append(list(path))
        if len(paths) >= cap:
            break
    return paths


def path_cost(path: List[str], graph: nx.DiGraph) -> float:
    """Total weight along a vertex path in ``graph``."""
    return sum(graph[path[i]][path[i + 1]]["weight"] for i in range(len(path) - 1))
