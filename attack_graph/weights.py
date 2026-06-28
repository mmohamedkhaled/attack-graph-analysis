# SPDX-FileCopyrightText: 2026 Mohamed Khaled <mohamedabdelfatah572@aucegypt.edu>
# SPDX-License-Identifier: MIT

"""CVSS-based edge-weight derivation.

This module answers the central modelling question of the project:

    *What number should an attack-graph edge carry, and how do we know -- in
    real life -- that one edge's weight is higher than another's?*

The answer adopted here is: **the weight of an edge is the effort an attacker
must expend to traverse it, and that effort is derived from the exploit's CVSS
v3.1 Exploitability metrics** (Attack Vector, Attack Complexity, Privileges
Required, User Interaction).  Each weight is therefore not a guessed integer
but a *traceable, auditable* value: it can be reproduced from a public CVE
record and explained factor by factor.

Why CVSS?
---------
CVSS (Common Vulnerability Scoring System, v3.1) is the industry-standard
language for describing how a vulnerability is exploited.  Its *Exploitability*
sub-score captures exactly the things that make an exploit expensive for an
attacker:

    * reaching the target physically is harder than over the network,
    * high-complexity exploits are harder than trivial ones,
    * needing prior privileges is harder than needing none,
    * having to trick a user (phishing/click) is harder than not.

Attack-graph edge weights should rise with each of those factors.  CVSS gives
us calibrated numeric values for all of them, so we reuse its formula rather
than inventing a private rubric.

The derivation (three steps)
----------------------------
1. **CVSS Exploitability** -- the official v3.1 formula:

       E = 8.22 * AV * AC * PR * UI

   where ``AV, AC, PR, UI`` are the metric values from the CVSS specification
   (see :data:`CVSS3_METRICS`).  ``E`` is large when the exploit is *easy*
   (network-reachable, low complexity, no privileges, no user interaction) and
   small when it is *hard*.

2. **Normalise to [0, 1]** against the full theoretical range of ``E``:

       norm = (E - E_min) / (E_max - E_min)

   so ``norm = 1`` is the easiest possible exploit and ``norm = 0`` the hardest.

3. **Invert and scale to a weight** (cost).  The attacker minimises total path
   cost, so an *easy* exploit must be *cheap*:

       difficulty = 1 - norm
       weight     = W_min + (W_max - W_min) * difficulty

   By default ``W_min = 1`` and ``W_max = 10`` (overridable), so weights land
   on a clean 1..10 scale comparable to the paper's 1..5 integers but with a
   far wider, better-calibrated spread.

Worked intuition (sanity checks)
--------------------------------
    * AV:N/AC:L/PR:N/UI:N  (trivial remote RCE)            -> weight 1.00
    * AV:N/AC:L/PR:N/UI:R  (phishing, needs a click)       -> weight 3.52
    * AV:A/AC:L/PR:L/UI:N  (adjacent net, low priv)        -> weight 5.35
    * AV:L/AC:H/PR:H/UI:N  (local exploit needing admin)   -> weight 9.20
    * AV:P/AC:H/PR:H/UI:R  (physical + user interaction)   -> weight 10.0

These match common-sense security reasoning, which is the whole point: the
numbers are no longer arbitrary, they are *defensible*.

References
----------
* CVSS v3.1 Specification Document:
  https://www.first.org/cvss/v3.1/specification-document
* CVSS v3.1 Examples: https://www.first.org/cvss/examples
"""

from __future__ import annotations

from dataclasses import dataclass
from typing import Dict

# --------------------------------------------------------------------------- #
# CVSS v3.1 metric values (Exploitability metrics only).
#
# These are the exact numeric coefficients published in the CVSS v3.1
# specification.  We deliberately restrict ourselves to the four
# Exploitability metrics because an attack-graph edge models *the act of
# exploiting a transition* -- impact (C/I/A) belongs to the vertex (the
# compromised asset), not to the edge.
# --------------------------------------------------------------------------- #
CVSS3_METRICS: Dict[str, Dict[str, float]] = {
    # Attack Vector -- how remote the attacker can be.
    "AV": {"N": 0.85, "A": 0.62, "L": 0.55, "P": 0.20},
    # Attack Complexity -- conditions beyond the attacker's control.
    "AC": {"L": 0.77, "H": 0.44},
    # Privileges Required -- prior access the attacker must already hold.
    # (Scope-Unchanged values; Scope-Changed differs only for PR and is rare
    # for an exploit-transition edge, so we use the standard table.)
    "PR": {"N": 0.85, "L": 0.62, "H": 0.27},
    # User Interaction -- whether a second human must cooperate.
    "UI": {"N": 0.85, "R": 0.62},
}

#: Human-readable names for each metric (for the audit breakdown).
CVSS3_METRIC_NAMES: Dict[str, str] = {
    "AV": "Attack Vector",
    "AC": "Attack Complexity",
    "PR": "Privileges Required",
    "UI": "User Interaction",
}

#: Human-readable values for each metric choice.
CVSS3_VALUE_NAMES: Dict[str, Dict[str, str]] = {
    "AV": {"N": "Network", "A": "Adjacent", "L": "Local", "P": "Physical"},
    "AC": {"L": "Low", "H": "High"},
    "PR": {"N": "None", "L": "Low", "H": "High"},
    "UI": {"N": "None", "R": "Required"},
}

# The constant multiplier in the CVSS Exploitability formula.
_CVSS_EXPLOITABILITY_CONSTANT = 8.22

# Theoretical bounds of the Exploitability sub-score, used for normalisation.
#   E_max = easiest exploit  (AV:N/AC:L/PR:N/UI:N)
#   E_min = hardest exploit  (AV:P/AC:H/PR:H/UI:R)
_EXPLOITABILITY_MAX = (
    _CVSS_EXPLOITABILITY_CONSTANT
    * CVSS3_METRICS["AV"]["N"] * CVSS3_METRICS["AC"]["L"]
    * CVSS3_METRICS["PR"]["N"] * CVSS3_METRICS["UI"]["N"]
)  # ~ 3.887
_EXPLOITABILITY_MIN = (
    _CVSS_EXPLOITABILITY_CONSTANT
    * CVSS3_METRICS["AV"]["P"] * CVSS3_METRICS["AC"]["H"]
    * CVSS3_METRICS["PR"]["H"] * CVSS3_METRICS["UI"]["R"]
)  # ~ 0.121


# --------------------------------------------------------------------------- #
# CVSS vector parsing.
# --------------------------------------------------------------------------- #
def parse_cvss_vector(vector: str) -> Dict[str, str]:
    """Parse a CVSS v3.1 vector string into a ``{metric: value}`` dict.

    Accepts both the full official form ``"CVSS:3.1/AV:N/AC:L/PR:N/UI:N"``
    and the compact form ``"AV:N/AC:L/PR:N/UI:N"``.  Only the Exploitability
    metrics (AV, AC, PR, UI) are retained; any other metrics (Scope, Impact,
    Temporal, ...) are ignored because they do not affect the edge weight.

    Raises
    ------
    ValueError
        If the vector is malformed or a required Exploitability metric is
        missing or has an unknown value.
    """
    if not isinstance(vector, str) or not vector.strip():
        raise ValueError("CVSS vector must be a non-empty string.")

    tokens = [t for t in vector.strip().split("/") if t]
    # Drop an optional leading "CVSS:3.1" / "CVSS:3.0" prefix.
    if tokens and tokens[0].upper().startswith("CVSS:"):
        tokens = tokens[1:]

    parsed: Dict[str, str] = {}
    for token in tokens:
        if ":" not in token:
            raise ValueError(
                f"Invalid CVSS token '{token}' in vector '{vector}' "
                "(expected 'METRIC:VALUE')."
            )
        metric, value = token.split(":", 1)
        metric, value = metric.strip().upper(), value.strip().upper()
        if metric not in CVSS3_METRICS:
            continue  # ignore non-Exploitability metrics (e.g. S, C, I, A)
        if value not in CVSS3_METRICS[metric]:
            raise ValueError(
                f"Unknown value '{value}' for CVSS metric '{metric}' "
                f"(valid: {sorted(CVSS3_METRICS[metric])})."
            )
        parsed[metric] = value

    missing = set(CVSS3_METRICS) - parsed.keys()
    if missing:
        raise ValueError(
            f"CVSS vector '{vector}' is missing required Exploitability "
            f"metric(s): {sorted(missing)}."
        )
    return parsed


# --------------------------------------------------------------------------- #
# Exploitability + weight derivation.
# --------------------------------------------------------------------------- #
def cvss_exploitability(metrics: Dict[str, str]) -> float:
    """Return the CVSS v3.1 Exploitability sub-score ``E``.

    ``E`` is large when the exploit is *easy* and small when it is *hard*.
    """
    return _CVSS_EXPLOITABILITY_CONSTANT * (
        CVSS3_METRICS["AV"][metrics["AV"]]
        * CVSS3_METRICS["AC"][metrics["AC"]]
        * CVSS3_METRICS["PR"][metrics["PR"]]
        * CVSS3_METRICS["UI"][metrics["UI"]]
    )


@dataclass(frozen=True)
class WeightDerivation:
    """Full audit trail of how an edge weight was computed from CVSS.

    Stored on the edge so that *every number in the graph can be explained*
    -- a reviewer can see exactly which CVSS metric pushed a weight up or
    down.  This is what makes the weighting defensible for a research paper.
    """

    cvss_vector: str              # original vector, e.g. "AV:N/AC:L/PR:N/UI:N"
    exploitability: float         # raw CVSS Exploitability sub-score E
    normalized: float             # E mapped to [0,1], 1=easiest
    difficulty: float             # 1 - normalized, [0,1], 1=hardest
    weight: float                 # final edge weight (cost)
    breakdown: Dict[str, str]     # metric -> "value (name)" for human reading

    def explain(self) -> str:
        """Return a one-line, human-readable justification of the weight."""
        parts = ", ".join(
            f"{m}={CVSS3_VALUE_NAMES[m][v]}({v})"
            for m, v in self.breakdown.items()
        )
        return (
            f"weight={self.weight:.2f}  "
            f"[exploitability E={self.exploitability:.3f}, "
            f"difficulty={self.difficulty:.3f}]  "
            f"({parts})"
        )


def derive_weight(
    cvss_vector: str,
    w_min: float = 1.0,
    w_max: float = 10.0,
) -> WeightDerivation:
    """Derive an attack-graph edge weight from a CVSS v3.1 vector.

    Parameters
    ----------
    cvss_vector : str
        The CVSS vector, e.g. ``"AV:N/AC:L/PR:N/UI:N"`` (a ``CVSS:3.1/...``
        prefix is accepted and stripped).
    w_min, w_max : float
        The weight assigned to the easiest / hardest possible exploit.
        Defaults give a clean 1..10 scale.

    Returns
    -------
    WeightDerivation
        The computed weight together with a full, explainable audit trail.

    Raises
    ------
    ValueError
        If the vector is malformed (see :func:`parse_cvss_vector`).
    """
    metrics = parse_cvss_vector(cvss_vector)
    exploitability = cvss_exploitability(metrics)

    span = _EXPLOITABILITY_MAX - _EXPLOITABILITY_MIN
    # Clamp guards against tiny floating-point excursions at the endpoints.
    normalized = max(
        0.0,
        min(1.0, (exploitability - _EXPLOITABILITY_MIN) / span),
    )
    difficulty = 1.0 - normalized
    weight = w_min + (w_max - w_min) * difficulty

    return WeightDerivation(
        cvss_vector=cvss_vector,
        exploitability=exploitability,
        normalized=normalized,
        difficulty=difficulty,
        weight=weight,
        breakdown=metrics,
    )


def derive_edge_weight(cvss_vector: str) -> float:
    """Convenience: return *just* the derived weight (rounded to 2 dp).

    This is the hook the JSON loader uses when an edge specifies a CVSS
    vector but no explicit ``weight``.
    """
    return round(derive_weight(cvss_vector).weight, 2)
