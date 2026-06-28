# SPDX-FileCopyrightText: 2026 Mohamed Khaled <mohamedabdelfatah572@aucegypt.edu>
# SPDX-License-Identifier: MIT

"""Graph export -- write a modelled graph to standard interchange formats.

So the toolkit interoperates with the rest of the security/graph ecosystem,
a :class:`GraphSpec` (hand-written, constructed, or scanned) can be written to:

* **GraphML** (.graphml/.xml) -- the de-facto interchange format, readable by
  Gephi, yEd, Cytoscape, Neo4j-import, etc.
* **DOT** (.dot/.gv) -- the Graphviz format, renderable with ``dot -Tpng``.
* **JSON** (.json) -- the toolkit's own config format (round-trips exactly).

All node and edge attributes survive the export: node ``role`` (and the
``[observed]``/``[inferred]`` provenance tag from constructed graphs), edge
``weight``, and the originating CVSS vector where present.
"""

from __future__ import annotations

from pathlib import Path
from typing import Union

import networkx as nx

from .graph_io import save_graph
from .models import Edge, GraphSpec

# Format -> file extensions recognised by :func:`export`.
_FORMAT_EXTENSIONS = {
    "graphml": (".graphml", ".xml"),
    "dot": (".dot", ".gv"),
    "json": (".json",),
}


def _enriched_graph(spec: GraphSpec) -> nx.DiGraph:
    """Build the DiGraph with all attributes preserved for export."""
    spec.validate()
    graph = nx.DiGraph(name=spec.name)
    for vertex in spec.vertices:
        graph.add_node(vertex, role=spec.node_roles.get(vertex, ""))
    for edge in spec.edges:
        attrs = {"weight": edge.weight}
        if edge.cvss:
            attrs["cvss"] = edge.cvss
        graph.add_edge(edge.source, edge.target, **attrs)
    return graph


def _detect_format(path: Union[str, Path]) -> str:
    suffix = Path(path).suffix.lower()
    for fmt, exts in _FORMAT_EXTENSIONS.items():
        if suffix in exts:
            return fmt
    raise ValueError(
        f"Cannot determine export format from extension '{suffix}'. "
        f"Use one of: {sorted(e for exts in _FORMAT_EXTENSIONS.values() for e in exts)}."
    )


def _dot_escape(text: str) -> str:
    return text.replace("\\", "\\\\").replace('"', '\\"')


def write_graphml(spec: GraphSpec, path: Union[str, Path]) -> Path:
    """Write the graph as GraphML (readable by Gephi, yEd, Cytoscape, ...)."""
    path = Path(path)
    graph = _enriched_graph(spec)
    nx.write_graphml(graph, path)
    return path


def write_dot(spec: GraphSpec, path: Union[str, Path]) -> Path:
    """Write the graph as Graphviz DOT (render with ``dot -Tpng in.dot``).

    A self-contained emitter so no Graphviz Python binding is required.
    """
    path = Path(path)
    graph = _enriched_graph(spec)
    lines = [f'digraph "{_dot_escape(spec.name)}" {{', "  rankdir=LR;"]
    for node, data in graph.nodes(data=True):
        role = data.get("role", "")
        label = f"{node}\\n{role}" if role else node
        lines.append(f'  "{_dot_escape(node)}" [label="{_dot_escape(label)}"];')
    for u, v, data in graph.edges(data=True):
        w = data.get("weight", 1.0)
        attrs = [f'weight={w}', f'label="{w}"']
        if "cvss" in data:
            attrs.append(f'cvss="{_dot_escape(data["cvss"])}"')
        lines.append(
            f'  "{_dot_escape(u)}" -> "{_dot_escape(v)}" [{", ".join(attrs)}];'
        )
    lines.append("}")
    path.write_text("\n".join(lines) + "\n", encoding="utf-8")
    return path


def write_json(spec: GraphSpec, path: Union[str, Path]) -> Path:
    """Write the graph in the toolkit's own JSON config format (round-trips)."""
    save_graph(spec, path)
    return Path(path)


def export(spec: GraphSpec, path: Union[str, Path],
           fmt: str = None) -> Path:  # noqa: B008 (None default is intentional)
    """Export ``spec`` to ``path``, choosing the format from the extension.

    Parameters
    ----------
    spec : GraphSpec
    path : path-like
    fmt : "graphml" | "dot" | "json", optional
        Overrides the auto-detected format.

    The destination directory is created if it does not exist.
    """
    path = Path(path)
    fmt = (fmt or _detect_format(path)).lower()
    path.parent.mkdir(parents=True, exist_ok=True)

    writers = {
        "graphml": write_graphml,
        "dot": write_dot,
        "json": write_json,
    }
    if fmt not in writers:
        raise ValueError(f"Unknown format '{fmt}' (use: {sorted(writers)}).")
    return writers[fmt](spec, path)


# Re-export Edge so callers can build specs programmatically alongside export.
__all__ = ["export", "write_graphml", "write_dot", "write_json", "Edge"]
