"""Graph visualisation.

The layout is computed automatically so it works for **any** input graph:

* if the graph is a DAG, nodes are placed left-to-right by their
  :func:`networkx.topological_generations` (depth) layer, with each layer
  ordered by the vertical position of its predecessors to keep edges tidy;
* otherwise a spring layout is used as a fallback.

The minimum vertex-cut nodes are highlighted in red ("patched/mitigated
vulnerabilities"), shortest-path edges are emphasised, and edge labels carry
fully-opaque white boxes so they never disappear under other elements.
"""

from __future__ import annotations

from typing import Dict, Optional, Set, Tuple

import networkx as nx

# matplotlib is imported lazily so the package can be used head-less for
# analysis even when matplotlib is unavailable.


def _layered_layout(
    graph: nx.DiGraph, source: str, target: str
) -> Dict[str, Tuple[float, float]]:
    """Return ``{node: (x, y)}`` positions for a clean left-to-right flow."""
    x_gap, y_gap = 2.6, 1.8

    if nx.is_directed_acyclic_graph(graph):
        generations = list(nx.topological_generations(graph))
        pos: Dict[str, Tuple[float, float]] = {}
        for depth, layer in enumerate(generations):
            # Order each layer by the mean y of its predecessors so edges
            # stay roughly horizontal and cross as little as possible.
            def _key(node: str) -> float:
                preds = list(graph.predecessors(node))
                if not preds:
                    return 0.0
                return sum(pos[p][1] for p in preds) / len(preds)

            ordered = sorted(layer, key=_key)
            n = len(ordered)
            for i, node in enumerate(ordered):
                y = (i - (n - 1) / 2.0) * y_gap
                pos[node] = (depth * x_gap, y)
        return pos

    # Fallback: force-directed layout, with source pinned left & target right.
    pos = nx.spring_layout(graph, seed=42, scale=max(3.0, len(graph) * 0.4))
    if source in pos:
        pos[source] = (0.0, 0.0)
    if target in pos:
        pos[target] = (max(p[0] for p in pos.values()) + 1.0, 0.0)
    return pos


def visualize_report(
    report,
    output_path: Optional[str] = None,
    show: bool = True,
) -> None:
    """Render a :class:`attack_graph.models.SecurityReport` to a figure.

    Parameters
    ----------
    report : SecurityReport
        The analysis result to draw.
    output_path : str, optional
        If given, save the PNG here.
    show : bool
        Whether to call ``plt.show()`` (interactive).
    """
    try:
        import matplotlib.pyplot as plt
    except ImportError as exc:  # pragma: no cover - environmental
        raise ImportError(
            "matplotlib is required for visualisation. Install the "
            "optional 'plot' extra with 'pip install attack-graph-analysis[plot]' "
            "(or re-run with --no-plot for headless analysis)."
        ) from exc

    graph = build_digraph_from_report(report)
    spec = report.spec
    metrics = report.metrics
    pos = _layered_layout(graph, spec.source, spec.target)

    cut_nodes: Set[str] = set(metrics.min_vertex_cut)
    shortest_edges: Set[Tuple[str, str]] = set()
    for path in metrics.shortest_paths:
        for i in range(len(path) - 1):
            shortest_edges.add((path[i], path[i + 1]))

    # --- colours ----------------------------------------------------------
    node_colours = []
    for node in graph.nodes:
        if node in cut_nodes:
            node_colours.append("#E63946")   # red   -> patched / mitigated
        elif node == spec.source:
            node_colours.append("#2A9D8F")   # teal  -> entry point
        elif node == spec.target:
            node_colours.append("#F4A261")   # gold  -> protected asset
        else:
            node_colours.append("#8AB4D6")   # blue  -> ordinary host

    # Edges that share both endpoints in the same x-column (vertical) are
    # curved so their labels do not collide with the node labels.
    curved = [
        (u, v) for u, v in graph.edges
        if abs(pos[u][0] - pos[v][0]) < 0.5
    ]
    straight = [e for e in graph.edges if e not in curved]

    fig, ax = plt.subplots(figsize=(16, 9), dpi=150)

    nx.draw_networkx_nodes(
        graph, pos, ax=ax, node_size=3000, node_color=node_colours,
        edgecolors="#1d3557", linewidths=2.0,
    )
    nx.draw_networkx_labels(
        graph, pos, ax=ax, font_size=13, font_weight="bold", font_color="white",
    )

    nx.draw_networkx_edges(
        graph, pos, ax=ax, edgelist=straight,
        edge_color=["#264653" if e in shortest_edges else "#B0B0B0"
                    for e in straight],
        width=[2.6 if e in shortest_edges else 1.4 for e in straight],
        arrows=True, arrowstyle="-|>", arrowsize=26, node_size=3000,
        connectionstyle="arc3,rad=0.0",
    )
    if curved:
        nx.draw_networkx_edges(
            graph, pos, ax=ax, edgelist=curved,
            edge_color=["#B0B0B0"] * len(curved), width=[1.4] * len(curved),
            arrows=True, arrowstyle="-|>", arrowsize=26, node_size=3000,
            connectionstyle="arc3,rad=0.4",
        )

    # --- edge labels (opaque boxes) --------------------------------------
    label_bbox = dict(
        boxstyle="round,pad=0.28", facecolor="white",
        edgecolor="#bbbbbb", alpha=1.0,
    )
    for u, v, d in graph.edges(data=True):
        nx.draw_networkx_edge_labels(
            graph, pos, ax=ax, edge_labels={(u, v): f"{d['weight']}"},
            label_pos=0.5, font_size=12, font_weight="bold",
            font_color="#1d3557", bbox=label_bbox,
        )

    # --- legend & title ---------------------------------------------------
    from matplotlib.patches import Patch

    legend = [
        Patch(facecolor="#2A9D8F", edgecolor="#1d3557",
              label=f"Source '{spec.source}'"),
        Patch(facecolor="#F4A261", edgecolor="#1d3557",
              label=f"Target '{spec.target}'"),
        Patch(facecolor="#E63946", edgecolor="#1d3557",
              label=f"Min vertex cut {sorted(cut_nodes) or '{}'}"),
        Patch(facecolor="#8AB4D6", edgecolor="#1d3557", label="Other hosts"),
    ]
    ax.legend(handles=legend, loc="upper center",
              bbox_to_anchor=(0.5, 1.10), ncol=4, frameon=False, fontsize=10)

    reachable = "reachable" if metrics.is_reachable else "UNREACHABLE"
    cost = (f"{metrics.shortest_path_cost:g}" if metrics.is_reachable else "n/a")
    ax.set_title(
        f"{spec.name}\n"
        f"Target {reachable} | d(s,t) = {cost} | "
        f"min vertex cut = {metrics.min_vertex_cut_size} | "
        f"security score {report.score:g}/100 (grade {report.grade})",
        fontsize=13, fontweight="bold", pad=26,
    )
    ax.axis("off")
    plt.tight_layout()

    if output_path:
        plt.savefig(output_path, dpi=200, bbox_inches="tight")

    if show:
        plt.show()
    else:
        plt.close(fig)


def build_digraph_from_report(report) -> nx.DiGraph:
    """Rebuild the analysed graph from a report (avoids re-parsing JSON)."""
    from .builder import build_digraph  # local import to avoid cycle
    return build_digraph(report.spec)
