# SPDX-FileCopyrightText: 2026 Mohamed Khaled <mohamedabdelfatah572@aucegypt.edu>
# SPDX-License-Identifier: MIT

"""Live network probes -- discovery backends that feed graph construction.

A *probe* observes a real system and yields structured discovery data that the
:mod:`attack_graph.construction` framework turns into a graph. Probes cover the
two real-data layers of an attack graph:

* **WiFi** (:mod:`attack_graph.probes.wifi`) -- the wireless *perimeter*
  (which networks exist and how weak their crypto is).
* **nmap** (:mod:`attack_graph.probes.nmap`) -- the network *interior*
  (hosts, ports, services), parsed from ``nmap -oX`` output.

Safety
------
Probes are **observation-only at the perimeter** (WiFi listens to beacons) and
**active-but-gated in the interior** (nmap sends packets). Live scanning always
requires ``authorized=True`` / the CLI ``--i-am-authorized`` flag. Parsing an
existing nmap ``-oX`` file is fully offline and is the recommended path. Only
scan networks you own or are authorised to assess.
"""

from .nmap import (
    SERVICE_ATTACKABILITY,
    NmapHost,
    Port,
    from_nmap,
    host_weight,
    parse_nmap_xml,
    scan_nmap,
)
from .wifi import (
    WIFI_SECURITY,
    AccessPoint,
    from_wifi_scan,
    from_wifi_scans,
    merge_scans,
    scan_and_construct,
    scan_wifi,
    wifi_weight,
)

__all__ = [
    # WiFi (perimeter)
    "AccessPoint",
    "WIFI_SECURITY",
    "scan_wifi",
    "wifi_weight",
    "from_wifi_scan",
    "scan_and_construct",
    "merge_scans",
    "from_wifi_scans",
    # nmap (interior)
    "Port",
    "NmapHost",
    "SERVICE_ATTACKABILITY",
    "parse_nmap_xml",
    "host_weight",
    "from_nmap",
    "scan_nmap",
]
