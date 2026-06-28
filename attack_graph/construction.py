"""Graph *construction* -- building an attack graph from real access.

The rest of the toolkit *analyses* a graph you hand it. This module does the
opposite: it **constructs** the graph, and it does so honestly with respect to
**how much access you actually have** to the target system:

    * **No access**      -- pure black-box / external observation. Only the
                           externally-exposed surface is known; the interior is
                           *inferred*. Use :func:`from_external_observation`
                           or :func:`from_template`.
    * **Minimal access** -- a single foothold (one compromised host). The
                           foothold and its immediate neighbours are *observed*;
                           everything beyond is *inferred*. Use
                           :func:`from_foothold`.
    * **Partial / full** -- several or all hosts are known. Use
                           :func:`from_adjacency` or :func:`from_discovery`.

The crucial idea is **provenance**: every node and edge is tagged as
*observed* (we have direct evidence) or *inferred* (a hypothesis). A graph
built with no access is mostly inferred, and that uncertainty is preserved in
the :class:`ConstructedGraph` so the downstream analysis never silently treats
a guess as a fact. You can therefore *analyse systems you have no access to* --
the result is explicitly a best-effort hypothesis, not ground truth.

No live scanning is performed. The constructors consume data you already have
(scan output, a discovery description, a template choice) and assemble a
:class:`GraphSpec` ready for :func:`attack_graph.security.analyze`.
"""

from __future__ import annotations

import json
from dataclasses import dataclass, field
from enum import Enum
from pathlib import Path
from typing import Dict, List, Optional, Sequence, Tuple, Union

from .models import Edge, GraphSpec

# Default weight assigned to an edge whose cost was not measured (only inferred).
_INFERRED_WEIGHT = 5.0


class AccessLevel(Enum):
    """How much access to the target system was used to build the graph."""

    NONE = "none"        # black-box / external only; topology inferred
    MINIMAL = "minimal"  # single foothold; its neighbours discovered
    PARTIAL = "partial"  # several hosts accessed
    FULL = "full"        # complete topology knowledge

    @classmethod
    def parse(cls, code: str) -> "AccessLevel":
        try:
            return cls(code)
        except ValueError:
            valid = [a.value for a in cls]
            raise ValueError(
                f"Unknown access level '{code}' (valid: {valid})."
            ) from None


# --------------------------------------------------------------------------- #
# Discovery primitives -- the raw material the builders consume.
# --------------------------------------------------------------------------- #
@dataclass
class DiscoveredHost:
    """A host discovered (or hypothesised) during construction."""

    id: str
    role: str = ""
    observed: bool = True   # True = direct evidence, False = inferred


@dataclass
class DiscoveredLink:
    """A directed transition discovered (or hypothesised) during construction."""

    source: str
    target: str
    weight: float = _INFERRED_WEIGHT
    observed: bool = True
    evidence: str = ""      # how we know (or why we inferred it)


# --------------------------------------------------------------------------- #
# The accumulator + result types.
# --------------------------------------------------------------------------- #
class GraphBuilder:
    """Accumulate discovered hosts/links and assemble a :class:`GraphSpec`.

    Keeps observed and inferred elements separate so provenance survives into
    the :class:`ConstructedGraph`.
    """

    def __init__(self, name: str, source: str, target: str,
                 access: AccessLevel, kind: str = "security") -> None:
        self.name = name
        self.source = source
        self.target = target
        self.access = access
        self.kind = kind
        self._hosts: Dict[str, DiscoveredHost] = {}
        self._links: List[DiscoveredLink] = []

    def add_host(self, host: Union[DiscoveredHost, str],
                 role: str = "", observed: bool = True) -> "GraphBuilder":
        if isinstance(host, DiscoveredHost):
            self._hosts[host.id] = host
        else:
            self._hosts[host] = DiscoveredHost(host, role, observed)
        return self

    def add_link(self, source: str, target: str,
                 weight: float = _INFERRED_WEIGHT,
                 observed: bool = True, evidence: str = "") -> "GraphBuilder":
        self._links.append(
            DiscoveredLink(source, target, weight, observed, evidence)
        )
        # Ensure both endpoints exist as hosts.
        for hid in (source, target):
            if hid not in self._hosts:
                self._hosts[hid] = DiscoveredHost(hid, observed=observed)
        return self

    def build(self, description: str = "") -> "ConstructedGraph":
        # Preserve insertion order but ensure source/target are present.
        for endpoint in (self.source, self.target):
            if endpoint not in self._hosts:
                self._hosts[endpoint] = DiscoveredHost(endpoint, observed=False)

        roles = {}
        for hid, host in self._hosts.items():
            tag = "observed" if host.observed else "inferred"
            role = host.role or "unknown"
            roles[hid] = f"{role} [{tag}]"

        edges = [
            Edge(source=lnk.source, target=lnk.target, weight=lnk.weight)
            for lnk in self._links
        ]

        observed_nodes = [h.id for h in self._hosts.values() if h.observed]
        inferred_nodes = [h.id for h in self._hosts.values() if not h.observed]
        observed_edges = sum(1 for lnk in self._links if lnk.observed)
        inferred_edges = sum(1 for lnk in self._links if not lnk.observed)

        spec = GraphSpec(
            name=self.name,
            vertices=list(self._hosts.keys()),
            edges=edges,
            source=self.source,
            target=self.target,
            description=description or self._auto_description(),
            node_roles=roles,
            kind=self.kind,
        )
        spec.validate()
        return ConstructedGraph(
            spec=spec,
            access_level=self.access,
            observed_nodes=observed_nodes,
            inferred_nodes=inferred_nodes,
            observed_edges=observed_edges,
            inferred_edges=inferred_edges,
            link_evidence=[(lnk.source, lnk.target, lnk.evidence) for lnk in self._links],
        )

    def _auto_description(self) -> str:
        return (
            f"Constructed with {self.access.value} access. "
            f"Provenance recorded per node/edge (observed vs inferred)."
        )


@dataclass
class ConstructedGraph:
    """A graph built by construction, together with its provenance."""

    spec: GraphSpec
    access_level: AccessLevel
    observed_nodes: List[str]
    inferred_nodes: List[str]
    observed_edges: int
    inferred_edges: int
    link_evidence: List[Tuple[str, str, str]] = field(default_factory=list)

    @property
    def total_nodes(self) -> int:
        return len(self.observed_nodes) + len(self.inferred_nodes)

    @property
    def confidence(self) -> float:
        """Fraction of nodes that were directly observed (0..1)."""
        if self.total_nodes == 0:
            return 0.0
        return round(len(self.observed_nodes) / self.total_nodes, 2)

    def summary(self) -> str:
        return (
            f"{self.access_level.value} access: "
            f"{len(self.observed_nodes)} observed / {len(self.inferred_nodes)} "
            f"inferred nodes, {self.observed_edges} observed / "
            f"{self.inferred_edges} inferred edges "
            f"(confidence {self.confidence})."
        )

    def save(self, path: Union[str, Path]) -> None:
        """Persist the constructed graph as a normal graph JSON config."""
        from .graph_io import save_graph
        save_graph(self.spec, path)


# --------------------------------------------------------------------------- #
# Built-in topology templates (used when you have no access at all).
# --------------------------------------------------------------------------- #
def _template_3tier() -> GraphBuilder:
    b = GraphBuilder("3-Tier Web App (template)", "internet", "db", AccessLevel.NONE)
    b.add_host("internet", "external vantage", observed=True)
    for hid, role in [("web", "public web server"), ("vpn", "vpn gateway")]:
        b.add_host(hid, role, observed=True)
        b.add_link("internet", hid, 2, observed=True, evidence="externally visible")
    for hid, role in [("app", "app server"), ("auth", "auth service")]:
        b.add_host(hid, role, observed=False)
    b.add_host("db", "customer database", observed=False)
    b.add_link("web", "app", 3, observed=False, evidence="inferred interior")
    b.add_link("vpn", "auth", 4, observed=False, evidence="inferred interior")
    b.add_link("app", "auth", 2, observed=False, evidence="inferred interior")
    b.add_link("auth", "db", 3, observed=False, evidence="inferred interior")
    b.add_link("app", "db", 5, observed=False, evidence="inferred interior")
    return b


def _template_dmz() -> GraphBuilder:
    b = GraphBuilder("DMZ + Internal (template)", "internet", "db", AccessLevel.NONE)
    b.add_host("internet", "external vantage", observed=True)
    b.add_host("fw", "edge firewall", observed=True)
    b.add_link("internet", "fw", 2, observed=True, evidence="externally visible")
    for hid, role in [("dmz_web", "DMZ web server"), ("dmz_mail", "DMZ mail relay")]:
        b.add_host(hid, role, observed=False)
        b.add_link("fw", hid, 3, observed=False, evidence="inferred DMZ")
    b.add_host("ad", "Active Directory", observed=False)
    b.add_host("db", "internal database", observed=False)
    b.add_link("dmz_web", "ad", 4, observed=False, evidence="inferred")
    b.add_link("dmz_mail", "ad", 5, observed=False, evidence="inferred")
    b.add_link("ad", "db", 2, observed=False, evidence="inferred")
    return b


def _template_flatlan() -> GraphBuilder:
    b = GraphBuilder("Flat LAN (template)", "s", "t", AccessLevel.NONE)
    b.add_host("s", "entry host", observed=True)
    b.add_host("t", "critical host", observed=False)
    for i in range(1, 5):
        b.add_host(f"h{i}", f"peer host {i}", observed=False)
        b.add_link("s", f"h{i}", 2, observed=False, evidence="inferred peer")
        b.add_link(f"h{i}", "t", 3, observed=False, evidence="inferred peer")
    return b


TEMPLATES: Dict[str, callable] = {
    "3-tier-webapp": _template_3tier,
    "dmz-internal": _template_dmz,
    "flat-lan": _template_flatlan,
}


# --------------------------------------------------------------------------- #
# Public constructors.
# --------------------------------------------------------------------------- #
def from_template(name: str, kind: str = "security") -> ConstructedGraph:
    """Build a graph from a named topology template (zero access).

    Every node/edge is *inferred* -- the template is a hypothesis about a
    typical architecture, not a measurement. Useful when you have no access at
    all and need a starting point to reason about.
    """
    if name not in TEMPLATES:
        raise ValueError(
            f"Unknown template '{name}' (available: {sorted(TEMPLATES)})."
        )
    builder = TEMPLATES[name]()
    builder.kind = kind
    return builder.build(
        description=(
            f"Constructed from template '{name}' with NO access. "
            "All nodes/edges are inferred -- treat results as a hypothesis."
        )
    )


def from_external_observation(
    exposed: Sequence[Tuple[str, str, float]],
    target: str = "internal",
    target_role: str = "critical internal asset",
    kind: str = "security",
) -> ConstructedGraph:
    """Build a graph from pure external observation (zero access).

    Parameters
    ----------
    exposed : sequence of (host_id, role, weight_from_internet)
        The services visible from outside -- the only thing you actually know.
    target : str
        The hypothesised critical asset behind the exposed surface.
    target_role : str
        Human description of the target.

    Every exposed service is *observed*; the path from each service to the
    target is *inferred* (you cannot see inside). The result is an honest
    "attack surface + hypothesised interior" graph.
    """
    b = GraphBuilder("Externally-Observed Network", "internet", target,
                     AccessLevel.NONE, kind=kind)
    b.add_host("internet", "external vantage", observed=True)
    b.add_host(target, target_role, observed=False)
    for hid, role, w in exposed:
        b.add_host(hid, role, observed=True)
        b.add_link("internet", hid, float(w), observed=True,
                   evidence="externally visible service")
        b.add_link(hid, target, float(w) * 2, observed=False,
                   evidence="inferred interior path")
    return b.build(
        description=(
            "Constructed with NO access from external observation. Exposed "
            "services are observed; interior paths are inferred."
        )
    )


def from_foothold(
    foothold: str,
    target: str,
    neighbors: Dict[str, Sequence],
    roles: Optional[Dict[str, str]] = None,
    kind: str = "security",
) -> ConstructedGraph:
    """Build a graph from a single compromised host (minimal access).

    Parameters
    ----------
    foothold : str
        The one host you have access to (the entry point).
    target : str
        The asset you are trying to reach.
    neighbors : dict host -> sequence of (neighbor_id, weight[, evidence])
        What each discovered host can reach. The foothold's neighbours are
        *observed*; anything two or more hops out that you did not directly
        probe is *inferred*.
    roles : dict, optional
        Human-readable roles for the hosts.
    """
    roles = roles or {}
    b = GraphBuilder("Foothold-Discovered Network", foothold, target,
                     AccessLevel.MINIMAL, kind=kind)
    b.add_host(foothold, roles.get(foothold, "foothold"), observed=True)

    observed_hosts = {foothold}
    # First pass: the foothold's direct neighbours are observed.
    for entry in neighbors.get(foothold, []):
        nid = entry[0]
        observed_hosts.add(nid)

    for host, entries in neighbors.items():
        if host not in b._hosts:  # noqa: SLF001 (builder internal)
            b.add_host(host, roles.get(host, ""), observed=(host in observed_hosts))
        for entry in entries:
            nid = entry[0]
            weight = entry[1] if len(entry) > 1 else _INFERRED_WEIGHT
            evidence = entry[2] if len(entry) > 2 else ""
            observed = host in observed_hosts and nid in observed_hosts
            if not evidence:
                evidence = "observed from foothold" if observed else "inferred"
            if nid not in b._hosts:  # noqa: SLF001
                b.add_host(nid, roles.get(nid, ""), observed=(nid in observed_hosts))
            b.add_link(host, nid, float(weight), observed=observed, evidence=evidence)

    if target not in b._hosts:  # noqa: SLF001
        b.add_host(target, roles.get(target, "critical asset"), observed=False)

    return b.build(
        description=(
            f"Constructed with MINIMAL access from foothold '{foothold}'. "
            "Direct neighbours are observed; deeper paths are inferred."
        )
    )


def from_adjacency(
    adjacency: Dict[str, Sequence],
    source: str,
    target: str,
    roles: Optional[Dict[str, str]] = None,
    access: Union[AccessLevel, str] = AccessLevel.FULL,
    kind: str = "security",
) -> ConstructedGraph:
    """Build a graph from an adjacency description (partial/full access).

    ``adjacency`` maps each host to a sequence of ``(neighbor, weight)`` or
    plain neighbor ids. Use this when you have a complete or partial picture
    (e.g. parsed from a scan).
    """
    access = AccessLevel.parse(access) if isinstance(access, str) else access
    roles = roles or {}
    b = GraphBuilder("Adjacency-Discovered Network", source, target, access, kind=kind)
    b.add_host(source, roles.get(source, "source"), observed=True)
    for host, entries in adjacency.items():
        if host not in b._hosts:  # noqa: SLF001
            b.add_host(host, roles.get(host, ""), observed=True)
        for entry in entries:
            if isinstance(entry, (tuple, list)):
                nid, weight = entry[0], entry[1]
            else:
                nid, weight = entry, _INFERRED_WEIGHT
            if nid not in b._hosts:  # noqa: SLF001
                b.add_host(nid, roles.get(nid, ""), observed=True)
            b.add_link(host, nid, float(weight), observed=True, evidence="provided")
    if target not in b._hosts:  # noqa: SLF001
        b.add_host(target, roles.get(target, "target"), observed=True)
    return b.build(
        description=f"Constructed from adjacency with {access.value} access."
    )


def from_discovery(path_or_dict: Union[str, Path, dict]) -> ConstructedGraph:
    """Build a graph from a *discovery description* (JSON file or dict).

    The discovery format lets you spell out exactly what you observed and what
    you inferred, with an explicit access level::

        {
          "name": "Foothold on web-01",
          "access": "minimal",
          "kind": "security",
          "source": "web",
          "target": "db",
          "hosts": [
            {"id": "web", "role": "public web server", "observed": true},
            {"id": "db", "role": "database", "observed": false}
          ],
          "links": [
            {"from": "web", "to": "app", "weight": 2, "observed": true,
             "evidence": "port scan"},
            {"from": "app", "to": "db", "weight": 3, "observed": false,
             "evidence": "inferred"}
          ]
        }
    """
    if isinstance(path_or_dict, dict):
        data = path_or_dict
    else:
        path = Path(path_or_dict)
        data = json.loads(path.read_text(encoding="utf-8"))

    access = AccessLevel.parse(str(data.get("access", "full")))
    b = GraphBuilder(
        name=str(data.get("name", "Discovered Network")),
        source=str(data["source"]),
        target=str(data["target"]),
        access=access,
        kind=str(data.get("kind", "security")),
    )
    for host in data.get("hosts", []):
        b.add_host(DiscoveredHost(
            id=str(host["id"]),
            role=str(host.get("role", "")),
            observed=bool(host.get("observed", True)),
        ))
    for link in data.get("links", []):
        b.add_link(
            str(link["from"]), str(link["to"]),
            weight=float(link.get("weight", _INFERRED_WEIGHT)),
            observed=bool(link.get("observed", True)),
            evidence=str(link.get("evidence", "")),
        )
    return b.build(
        description=str(data.get(
            "description",
            f"Constructed from discovery file with {access.value} access.",
        ))
    )
