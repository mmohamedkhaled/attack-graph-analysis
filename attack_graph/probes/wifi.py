"""WiFi probe -- passive scanning that constructs an attack graph.

Discovers nearby access points by listening to their beacon frames (a passive,
legal operation -- your phone does the same thing to list networks), then
builds an attack graph where each AP is a potential entry point weighted by how
*attackable* it is:

    * a **weak encryption** (Open / WEP / WPA1) makes an AP cheap to breach,
    * a **strong signal** (close range) makes an attack cheaper, and
    * a **strong encryption** (WPA2 / WPA3) makes it expensive.

The resulting weight is computed by :func:`wifi_weight` -- a transparent
formula analogous to the CVSS exploitability model but calibrated for the
WiFi physical layer.

What this probe is NOT
----------------------
It performs **no active attack**: no deauthentication, no handshake capture,
no packet injection, no key cracking, no association with networks. It only
reads what APs already broadcast. Running it still requires authorization to
scan the airspace you are in.
"""

from __future__ import annotations

import re
import shutil
import subprocess
from dataclasses import dataclass
from typing import List, Optional

from ..construction import (
    _INFERRED_WEIGHT,
    AccessLevel,
    ConstructedGraph,
    GraphBuilder,
)

# --------------------------------------------------------------------------- #
# WiFi security-posture coefficients (higher = harder to attack = higher weight).
#
# These mirror the philosophy of the CVSS exploitability table: a calibrated
# number per "how hard is this to exploit". Weak crypto -> small coefficient.
# --------------------------------------------------------------------------- #
WIFI_SECURITY = {
    "open": 0.10,   # no encryption -- trivial to join
    "wep": 0.30,    # broken in minutes
    "wpa1": 0.55,   # deprecated, several known weaknesses
    "wpa2": 0.80,   # strong (given a strong passphrase)
    "wpa3": 1.00,   # strongest mainstream option
}

#: Maps the security tokens nmcli/iwlist report to our coefficient keys.
_SECURITY_TOKEN_MAP = {
    "wpa3": "wpa3",
    "wpa2": "wpa2",
    "wpa1": "wpa1",
    "wpa": "wpa1",
    "wep": "wep",
    "802.1x": "wpa2",   # enterprise -- treat as strong
}


@dataclass
class AccessPoint:
    """One access point observed during a scan."""

    bssid: str
    ssid: str
    channel: Optional[int]
    signal: int           # normalised 0..100 (100 = strongest)
    security: str         # raw token string, e.g. "WPA1 WPA2"

    @property
    def security_key(self) -> str:
        """Strongest encryption the AP advertises, mapped to a coefficient key."""
        if not self.security.strip() or self.security.lower() in ("open", "--"):
            return "open"
        tokens = re.findall(r"[A-Za-z0-9.\-]+", self.security)
        found = [_SECURITY_TOKEN_MAP.get(t.lower()) for t in tokens]
        # Pick the strongest present.
        order = ["wpa3", "wpa2", "802.1x", "wpa1", "wep"]
        for sec in order:
            if sec in found:
                return "wpa3" if sec == "wpa3" else (
                    "wpa2" if sec in ("wpa2", "802.1x") else
                    "wpa1" if sec == "wpa1" else "wep"
                )
        return "wpa2"  # unknown-but-present security: assume strong


# --------------------------------------------------------------------------- #
# Weight model.
# --------------------------------------------------------------------------- #
def wifi_weight(signal: int, security: str) -> float:
    """Derive an edge weight (attack cost) for breaching an AP.

    ``signal`` is 0..100 (stronger = closer = cheaper to attack);
    ``security`` is the raw token string. The result lies on the same 1..10
    scale used everywhere else in the toolkit::

        weight = 1 + 9 * security_strength * (1 - 0.5 * ease)

    so a close, open AP is nearly free (~1.5) while a far, WPA3 AP is
    maximally expensive (~10).
    """
    signal = max(0, min(100, int(signal)))
    ap = AccessPoint(bssid="", ssid="", channel=None, signal=signal, security=security)
    strength = WIFI_SECURITY[ap.security_key]   # higher = harder
    ease = signal / 100.0                        # higher = easier
    weight = 1.0 + 9.0 * strength * (1.0 - 0.5 * ease)
    return round(weight, 2)


# --------------------------------------------------------------------------- #
# Scanning backends (passive).
# --------------------------------------------------------------------------- #
def _parse_nmcli_terse(line: str) -> Optional[AccessPoint]:
    """Parse one line of ``nmcli -t -f ... dev wifi list`` output.

    Fields are colon-separated; literal colons inside a value are escaped as
    ``\\:`` by nmcli, which we undo before splitting.
    """
    unescaped = line.replace("\\:", "\x00")
    parts = unescaped.split(":")
    if len(parts) < 6:
        return None
    bssid = parts[0].replace("\x00", ":")
    ssid = parts[1].replace("\x00", ":")
    chan = parts[3]
    signal = parts[4]
    security = ":".join(parts[5:]).replace("\x00", ":").strip()
    if security in ("", "--"):
        security = "open"
    try:
        chan_i = int(chan) if chan else None
    except ValueError:
        chan_i = None
    try:
        sig_i = int(signal)
    except ValueError:
        sig_i = 0
    if not bssid or bssid == "--":
        return None
    return AccessPoint(
        bssid=bssid, ssid=(ssid or "<hidden>"), channel=chan_i,
        signal=sig_i, security=security.strip() or "open",
    )


def _run_nmcli(iface: Optional[str], rescan: bool) -> str:
    args = ["nmcli"]
    if iface:
        args += ["--fields", "all"]
    args += ["-t", "-f", "BSSID,SSID,FREQ,CHAN,SIGNAL,SECURITY", "dev", "wifi", "list"]
    if iface:
        args += ["ifname", iface]
    if rescan:
        # A rescan is a standard, low-impact operation your OS performs anyway.
        subprocess.run(["nmcli", "dev", "wifi", "rescan"],
                       check=False, capture_output=True)
    return subprocess.run(args, check=True, capture_output=True,
                          text=True).stdout


def _run_iwlist(iface: str) -> str:
    return subprocess.run(["iwlist", iface, "scan"],
                          check=True, capture_output=True, text=True).stdout


def _parse_iwlist(raw: str) -> List[AccessPoint]:
    aps: List[AccessPoint] = []
    cur: Optional[AccessPoint] = None
    for line in raw.splitlines():
        s = line.strip()
        if s.startswith("Cell") and "Address:" in s:
            if cur:
                aps.append(cur)
            bssid = s.split("Address:")[-1].strip()
            cur = AccessPoint(bssid=bssid, ssid="", channel=None,
                              signal=0, security="open")
        elif cur is not None:
            if "ESSID:" in s:
                m = re.search(r'ESSID:"([^"]*)"', s)
                if m:
                    cur.ssid = m.group(1) or "<hidden>"
            elif "Quality=" in s or "Signal level=" in s:
                m = re.search(r"Signal level=(-?\d+)\s*dBm", s)
                if m:
                    dbm = int(m.group(1))
                    cur.signal = max(0, min(100, 2 * (dbm + 100)))  # dBm -> 0..100
            elif "Channel:" in s:
                m = re.search(r"Channel:(\d+)", s)
                if m:
                    cur.channel = int(m.group(1))
            elif "Encryption key:" in s:
                if "off" in s:
                    cur.security = "open"
                elif cur.security == "open":
                    cur.security = "WPA2"  # encrypted; exact suite unknown
    if cur:
        aps.append(cur)
    return aps


def scan_wifi(iface: Optional[str] = None, *, authorized: bool = False,
              rescan: bool = False, backend: str = "auto") -> List[AccessPoint]:
    """Passively scan for nearby access points.

    Parameters
    ----------
    iface : str, optional
        Wireless interface (e.g. ``"wlan0"``). If ``None``, nmcli scans all.
    authorized : bool
        **Must be True.** A hard gate: scanning is only performed when the
        caller explicitly asserts authorisation to scan the airspace.
    rescan : bool
        Trigger a fresh nmcli rescan first (off by default -> maximally
        passive, reads the most recent cached results).
    backend : str
        ``"auto"`` (nmcli then iwlist), ``"nmcli"``, or ``"iwlist"``.

    Raises
    ------
    PermissionError
        If ``authorized`` is not True.
    EnvironmentError
        If no scanning backend is available.
    """
    if not authorized:
        raise PermissionError(
            "scan_wifi() requires authorized=True. Only scan networks you own "
            "or are authorised to assess."
        )

    if backend in ("auto", "nmcli") and shutil.which("nmcli"):
        try:
            raw = _run_nmcli(iface, rescan)
            aps = [ap for line in raw.splitlines()
                   if (ap := _parse_nmcli_terse(line))]
            if aps:
                return aps
        except (subprocess.CalledProcessError, FileNotFoundError):
            pass

    if backend in ("auto", "iwlist") and iface and shutil.which("iwlist"):
        raw = _run_iwlist(iface)
        return _parse_iwlist(raw)

    raise EnvironmentError(
        "No WiFi scanning backend available (install NetworkManager's nmcli "
        "or wireless-tools' iwlist)."
    )


# --------------------------------------------------------------------------- #
# Construction from a scan.
# --------------------------------------------------------------------------- #
def from_wifi_scan(
    aps: List[AccessPoint],
    *,
    target: str = "foothold",
    target_role: str = "foothold on a breached LAN",
    scanner: str = "scanner",
    iface_name: Optional[str] = None,
    dedupe_by_ssid: bool = True,
) -> ConstructedGraph:
    """Build an attack graph from a list of observed access points.

    Topology: ``scanner -> AP -> foothold`` for each AP. The ``scanner -> AP``
    edge is *observed* and weighted by :func:`wifi_weight` (signal + security).
    The ``AP -> foothold`` edge is *inferred* (the interior of the LAN behind
    the AP is unknown). The cheapest path therefore reveals the easiest
    network to breach; the hotspot detector flags the weakest APs.
    """
    builder = GraphBuilder(
        name="WiFi Attack Surface",
        source=scanner,
        target=target,
        access=AccessLevel.MINIMAL,
        kind="security",
    )
    builder.add_host(
        scanner,
        role=f"attacker ({iface_name or 'wifi interface'})",
        observed=True,
    )
    builder.add_host(target, role=target_role, observed=False)

    seen_ssids = set()
    for ap in aps:
        if dedupe_by_ssid and ap.ssid in seen_ssids:
            continue
        seen_ssids.add(ap.ssid)
        node = ap.ssid if ap.ssid != "<hidden>" else ap.bssid
        role = (f"AP {ap.ssid} [{ap.security or 'open'}, sig {ap.signal}, "
                f"ch {ap.channel}]")
        builder.add_host(node, role=role, observed=True)
        w = wifi_weight(ap.signal, ap.security)
        builder.add_link(
            scanner, node, weight=w, observed=True,
            evidence=f"observed beacon; signal={ap.signal}, security={ap.security or 'open'}",
        )
        # Inferred interior: once on the AP, reach the LAN.
        builder.add_link(
            node, target, weight=_INFERRED_WEIGHT, observed=False,
            evidence="inferred LAN interior",
        )
    return builder.build(
        description=(
            f"Constructed from a live WiFi scan of {len(seen_ssids)} AP(s). "
            "Scanner->AP edges are observed (signal+security weight); "
            "AP->foothold edges are inferred (unknown LAN interior)."
        )
    )


def scan_and_construct(
    iface: Optional[str] = None, *, authorized: bool = False,
    rescan: bool = False, target: str = "foothold",
) -> ConstructedGraph:
    """Convenience: run a passive scan and build the attack graph."""
    aps = scan_wifi(iface, authorized=authorized, rescan=rescan)
    return from_wifi_scan(aps, target=target, iface_name=iface)


def merge_scans(scan_results: List[List[AccessPoint]]) -> List[AccessPoint]:
    """Merge several scans (e.g. taken at different locations) into one.

    WiFi is a *local* radio medium: a single scan only hears APs within radio
    range (~30-100m). Scanning from several positions and merging the results
    is the legitimate way to grow the *observed* part of the graph -- a
    passive form of wardriving. APs seen more than once are deduplicated by
    BSSID, keeping the strongest signal observed.
    """
    merged = {}
    for aps in scan_results:
        for ap in aps:
            key = ap.bssid or ap.ssid
            if key not in merged or ap.signal > merged[key].signal:
                merged[key] = ap
    return list(merged.values())


def from_wifi_scans(
    scan_results: List[List[AccessPoint]], *, target: str = "foothold",
    iface_name: Optional[str] = None,
) -> ConstructedGraph:
    """Build a graph from several merged scans (multiple locations)."""
    aps = merge_scans(scan_results)
    cg = from_wifi_scan(aps, target=target, iface_name=iface_name)
    cg.spec.name = "WiFi Attack Surface (merged scans)"
    return cg
