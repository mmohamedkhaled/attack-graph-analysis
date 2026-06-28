"""JSON serialisation of :class:`GraphSpec` objects.

JSON schema
-----------
A graph config file looks like this::

    {
      "name": "University Campus Network",
      "description": "Directed weighted DAG of exploit transitions.",
      "source": "s",
      "target": "t",
      "vertices": ["s", "v1", "v2", "v3", "v4", "v5", "v6", "v7", "t"],
      "edges": [
        {"from": "s", "to": "v1", "weight": 2},
        ["s", "v1", 2],
        {"from": "v1", "to": "v4", "cvss": "AV:A/AC:L/PR:L/UI:N"}
      ],
      "node_roles": {"s": "public web server", "t": "records database"}
    }

Edges may be written in three forms:

* a full object with an explicit ``weight``: ``{"from", "to", "weight"}``;
* a compact triple ``[u, v, w]``;
* a CVSS-derived object ``{"from", "to", "cvss"}`` whose weight is computed
  at load time from the CVSS v3.1 Exploitability metrics (see
  :mod:`attack_graph.weights`).  An optional ``cve`` label is recorded for
  auditability but does not affect the weight.

Both ``weight`` and ``cvss`` may be given together -- ``weight`` wins, but
the CVSS vector is still stored on the edge for documentation.
"""

from __future__ import annotations

import json
from pathlib import Path
from typing import List, Union

from .models import Edge, GraphSpec
from .weights import derive_weight

# Type alias for the accepted JSON edge representations.
_EdgeJSON = Union[dict, list]


def _parse_edge(raw: _EdgeJSON) -> Edge:
    """Normalise a JSON edge entry into an :class:`Edge`.

    Handles the three accepted forms (explicit weight, compact triple, and
    CVSS-derived).  See the module docstring for the schema.
    """
    if isinstance(raw, dict):
        source = str(raw["from"]) if "from" in raw else None
        target = str(raw["to"]) if "to" in raw else None
        if source is None or target is None:
            raise ValueError(
                f"Edge object {raw} is missing 'from' and/or 'to'."
            )

        # Case 1: explicit weight (unchanged historical behaviour).
        if "weight" in raw:
            cvss = raw.get("cvss")
            return Edge(
                source=source,
                target=target,
                weight=float(raw["weight"]),
                cvss=str(cvss) if cvss else None,
            )

        # Case 2: CVSS-derived weight.
        if "cvss" in raw:
            derivation = derive_weight(str(raw["cvss"]))
            return Edge(
                source=source,
                target=target,
                weight=derivation.weight,
                cvss=str(raw["cvss"]),
                weight_basis=(
                    f"CVSS {raw['cvss']} -> E={derivation.exploitability:.3f}, "
                    f"difficulty={derivation.difficulty:.3f} -> weight="
                    f"{derivation.weight:.2f}"
                ),
            )

        raise ValueError(
            f"Edge object {raw} has neither 'weight' nor 'cvss'."
        )

    # Case 3: compact triple [u, v, w].
    if isinstance(raw, (list, tuple)) and len(raw) == 3:
        return Edge(source=str(raw[0]), target=str(raw[1]), weight=float(raw[2]))

    raise ValueError(
        f"Unrecognised edge entry {raw!r}; expected an object with "
        "'from'/'to'/'weight' or 'from'/'to'/'cvss', or a [u, v, w] triple."
    )


def load_graph(path: Union[str, Path]) -> GraphSpec:
    """Load a :class:`GraphSpec` from a JSON config file.

    Raises
    ------
    FileNotFoundError
        If ``path`` does not exist.
    ValueError
        If the JSON is malformed or fails schema/spec validation.
    """
    path = Path(path)
    if not path.is_file():
        raise FileNotFoundError(f"Graph config not found: {path}")
    try:
        data = json.loads(path.read_text(encoding="utf-8"))
    except json.JSONDecodeError as exc:
        raise ValueError(f"Invalid JSON in {path}: {exc}") from exc

    if not isinstance(data, dict):
        raise ValueError(f"Top-level JSON in {path} must be an object.")

    required = {"name", "vertices", "edges", "source", "target"}
    missing = required - data.keys()
    if missing:
        raise ValueError(f"{path} is missing keys: {sorted(missing)}")

    spec = GraphSpec(
        name=str(data["name"]),
        description=str(data.get("description", "")),
        source=str(data["source"]),
        target=str(data["target"]),
        vertices=[str(v) for v in data["vertices"]],
        edges=[_parse_edge(e) for e in data["edges"]],
        node_roles={str(k): str(v) for k, v in data.get("node_roles", {}).items()},
        kind=str(data.get("kind", "security")),
    )
    spec.validate()  # raise early on inconsistent specs
    return spec


def save_graph(spec: GraphSpec, path: Union[str, Path]) -> None:
    """Write a :class:`GraphSpec` back to a JSON config file."""
    path = Path(path)
    payload = {
        "name": spec.name,
        "description": spec.description,
        "kind": spec.kind,
        "source": spec.source,
        "target": spec.target,
        "vertices": spec.vertices,
        "edges": [_edge_to_dict(e) for e in spec.edges],
        "node_roles": spec.node_roles,
    }
    path.write_text(json.dumps(payload, indent=2), encoding="utf-8")


def discover_graphs(directory: Union[str, Path]) -> List[Path]:
    """Return all ``*.json`` graph configs inside ``directory`` (sorted)."""
    directory = Path(directory)
    if not directory.is_dir():
        raise FileNotFoundError(f"Not a directory: {directory}")
    return sorted(directory.glob("*.json"))


def _edge_to_dict(edge: Edge) -> dict:
    """Serialise an edge, round-tripping CVSS provenance when present."""
    out: dict = {"from": edge.source, "to": edge.target}
    if edge.cvss:
        out["cvss"] = edge.cvss
    out["weight"] = round(edge.weight, 2)
    return out
