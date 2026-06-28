"""Pluggable network *domains* -- the heart of the toolkit's generality.

The package is a **security-analysis toolkit for arbitrary weighted directed
networks**. The graph engine (Bellman-Ford, Menger, composite scoring) is
completely domain-agnostic: it only needs vertices, weighted edges, and two
endpoints. What changes between applications is the *vocabulary* used to
explain the results -- a transport network has "junctions" and "routes", a
supply chain has "facilities" and "lanes", an IT attack graph has
"vulnerabilities" and "exploits".

A :class:`NetworkKind` bundles that vocabulary. Registering a new domain is
just adding an entry to :data:`NETWORK_KINDS` -- no algorithm code changes.
The same engine then analyses cyber networks, road systems, supply chains,
and social graphs with identical, security-focused conclusions expressed in
each domain's own terms.

The unifying idea: no matter the network, we ask the same security questions
-- *what is the cheapest way for a threat to travel from an entry point to a
critical asset, and what is the smallest set of nodes whose removal defends
it?*
"""

from __future__ import annotations

from dataclasses import dataclass
from typing import Dict


@dataclass(frozen=True)
class NetworkKind:
    """Vocabulary and framing for one category of modelled network.

    Every field is a short human phrase used to phrase findings so they read
    naturally for the domain. The underlying analysis is identical for all
    kinds; only the words change.
    """

    code: str             # short id used in JSON ("security", "transport", ...)
    name: str             # display name ("IT / Cyber Attack Network")
    vertex_term: str      # what a node represents ("host / vulnerability")
    source_term: str      # what the source represents ("threat entry point")
    target_term: str      # what the target represents ("critical asset")
    weight_term: str      # what an edge weight represents ("exploit cost")
    traverse_verb: str    # moving along an edge ("compromise", "reach")
    mitigate_verb: str    # defending a node ("patch", "close", "isolate")
    mitigating: str       # present participle of mitigate ("patching")
    path_term: str        # an s-t path ("attack path", "route")
    threat_term: str      # who travels the path ("attacker", "threat", "flow")


#: Registry of built-in domains. Add a row here to support a new network type.
NETWORK_KINDS: Dict[str, NetworkKind] = {
    "security": NetworkKind(
        code="security",
        name="IT / Cyber Attack Network",
        vertex_term="host / vulnerability",
        source_term="attacker entry point",
        target_term="protected asset",
        weight_term="exploit cost",
        traverse_verb="compromise",
        mitigate_verb="patch",
        mitigating="patching",
        path_term="attack path",
        threat_term="attacker",
    ),
    "transport": NetworkKind(
        code="transport",
        name="Transportation / Routing Network",
        vertex_term="junction / intersection",
        source_term="origin",
        target_term="destination",
        weight_term="travel distance / time",
        traverse_verb="traverse",
        mitigate_verb="close",
        mitigating="closing",
        path_term="route",
        threat_term="flow",
    ),
    "supply-chain": NetworkKind(
        code="supply-chain",
        name="Supply Chain / Logistics Network",
        vertex_term="facility / node",
        source_term="supplier origin",
        target_term="critical destination",
        weight_term="shipment cost / lead-time",
        traverse_verb="supply",
        mitigate_verb="disrupt",
        mitigating="disrupting",
        path_term="supply route",
        threat_term="flow",
    ),
    "social": NetworkKind(
        code="social",
        name="Social / Influence Network",
        vertex_term="person / actor",
        source_term="source individual",
        target_term="key person",
        weight_term="influence resistance",
        traverse_verb="influence",
        mitigate_verb="isolate",
        mitigating="isolating",
        path_term="influence chain",
        threat_term="influence",
    ),
}


def get_kind(code: str) -> NetworkKind:
    """Return the :class:`NetworkKind` for ``code`` (defaults to security).

    An unknown code falls back to the cyber-security vocabulary rather than
    raising, so user-authored configs never hard-crash the engine.
    """
    return NETWORK_KINDS.get(code, NETWORK_KINDS["security"])
