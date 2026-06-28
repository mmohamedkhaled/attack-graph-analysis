"""Construction of a :class:`networkx.DiGraph` from a :class:`GraphSpec`."""

from __future__ import annotations

import networkx as nx

from .models import GraphSpec


def build_digraph(spec: GraphSpec) -> nx.DiGraph:
    """Return a ``networkx.DiGraph`` carrying an integer/float ``weight`` per edge.

    The graph is built directly from the validated ``spec``; node roles (if any)
    are stored as the ``role`` node attribute so the visualiser can annotate them.
    """
    spec.validate()
    graph = nx.DiGraph(name=spec.name)
    for vertex in spec.vertices:
        graph.add_node(vertex, role=spec.node_roles.get(vertex, ""))
    for edge in spec.edges:
        graph.add_edge(edge.source, edge.target, weight=edge.weight)
    return graph
