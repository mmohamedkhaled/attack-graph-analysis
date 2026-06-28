# SPDX-FileCopyrightText: 2026 Mohamed Khaled <mohamedabdelfatah572@aucegypt.edu>
# SPDX-License-Identifier: MIT

"""nmap probe -- the *interior* layer of an attack graph.

While the WiFi probe sees the **wireless perimeter** (which networks exist and
how weak their crypto is), nmap sees the **network interior**: the actual
hosts, their open ports, and the services they run. This module parses nmap's
XML output (``nmap -oX``) into structured host/port records and builds an
attack graph weighted by each host's **service-based attackability**.

The weighting follows the same philosophy as the CVSS and WiFi models: a
calibrated coefficient per service, combined by the *weakest-link* rule (a host
is only as hard to breach as its easiest-to-exploit exposed service). A box
running ``telnet``/``ftp`` is therefore nearly free; a box exposing only
``ssh`` is expensive.

Safety
------
Parsing an existing XML file (``-oX``) is completely offline and safe -- every
pentester already saves scans this way. Live scanning
(:func:`scan_nmap`) sends packets and requires ``authorized=True``, exactly
like the WiFi probe. Only scan networks you own or are authorised to assess.
"""

from __future__ import annotations

import shutil
import subprocess
import xml.etree.ElementTree as ET
from dataclasses import dataclass, field
from pathlib import Path
from typing import List, Optional, Union

from ..construction import (
    _INFERRED_WEIGHT,
    AccessLevel,
    ConstructedGraph,
    GraphBuilder,
)

#: Attackability coefficient per common service (higher = easier to exploit).
#: Calibrated from historical exposure and default-credential / vuln history;
#: same spirit as the CVSS and WiFi coefficient tables.
SERVICE_ATTACKABILITY = {
    # legacy / cleartext -- trivial
    "telnet": 0.95, "ftp": 0.85, "rsh": 0.95, "rlogin": 0.95, "rexec": 0.95,
    # remote-display / management -- often misconfigured
    "vnc": 0.80, "xdmcp": 0.80, "x11": 0.85,
    # databases exposed to the network -- high value, frequent default creds
    "mysql": 0.78, "postgresql": 0.75, "ms-sql": 0.78, "oracle": 0.75,
    "redis": 0.82, "mongodb": 0.82, "cassandra": 0.75, "elasticsearch": 0.80,
    # file/print + directory -- high-value lateral and info-leak targets
    "microsoft-ds": 0.72, "smb": 0.72, "netbios-ssn": 0.72, "microsoft-rdp": 0.68,
    "rdp": 0.68, "ldap": 0.65, "snmp": 0.72, "nfs": 0.70, "ipp": 0.65,
    # mail / web -- moderate
    "smtp": 0.50, "pop3": 0.52, "imap": 0.52, "http": 0.55, "http-alt": 0.55,
    "http-proxy": 0.60, "socks": 0.60,
    # generally stronger
    "https": 0.40, "httpssl": 0.40, "imaps": 0.40, "pop3s": 0.40, "smtps": 0.40,
    "ssh": 0.30, "domain": 0.45, "dns": 0.45, "ntp": 0.45,
}

#: Fallback for services not in the table (rare/unknown -> assume moderate).
DEFAULT_ATTACKABILITY = 0.50


@dataclass
class Port:
    """A single port/service observed on a host."""

    port: int
    protocol: str = "tcp"   # tcp / udp
    service: str = ""       # ssh, http, microsoft-ds, ...
    product: str = ""
    version: str = ""
    state: str = "open"

    def label(self) -> str:
        s = self.service or str(self.port)
        if self.product:
            s += f" {self.product}"
            if self.version:
                s += f"/{self.version}"
        return f"{self.port}/{self.protocol} {s}".strip()


@dataclass
class NmapHost:
    """A host discovered by nmap."""

    ip: str
    hostname: str = ""
    mac: str = ""
    os: str = ""
    status: str = "up"      # up / down
    ports: List[Port] = field(default_factory=list)

    @property
    def name(self) -> str:
        """Best identifier for use as a graph node (hostname preferred)."""
        return self.hostname or self.ip

    def services_summary(self) -> str:
        return ", ".join(p.service or str(p.port) for p in self.ports) or "none"


# --------------------------------------------------------------------------- #
# Parsing.
# --------------------------------------------------------------------------- #
def _looks_like_path(s: str) -> bool:
    return ("\n" not in s) and (
        s.lstrip().startswith("<") is False and Path(s).exists()
    )


def parse_nmap_xml(source: Union[str, Path]) -> List[NmapHost]:
    """Parse nmap XML (a file path or a raw XML string) into hosts.

    Only ``up`` hosts with at least one ``open`` port are returned as attack
    surface; everything else is noise for graph construction.
    """
    if isinstance(source, Path) or (isinstance(source, str) and Path(source).exists()):
        tree = ET.parse(Path(source))
        root = tree.getroot()
    else:
        root = ET.fromstring(source)

    hosts: List[NmapHost] = []
    for h in root.iter("host"):
        status_el = h.find("status")
        status = status_el.get("state", "up") if status_el is not None else "up"

        ip = ""
        mac = ""
        for addr in h.findall("address"):
            atype = addr.get("addrtype", "")
            if atype in ("ipv4", "ipv6") and not ip:
                ip = addr.get("addr", "")
            elif atype == "mac" and not mac:
                mac = addr.get("addr", "")
        if not ip:
            continue

        hostname = ""
        hn_el = h.find("hostnames/hostname")
        if hn_el is not None:
            hostname = hn_el.get("name", "")

        os_name = ""
        osmatch = h.find("os/osmatch")
        if osmatch is not None:
            os_name = osmatch.get("name", "")

        ports: List[Port] = []
        ports_el = h.find("ports")
        if ports_el is not None:
            for p in ports_el.findall("port"):
                state_el = p.find("state")
                state = state_el.get("state", "open") if state_el is not None else "open"
                if state != "open":
                    continue
                svc_el = p.find("service")
                service = product = version = ""
                if svc_el is not None:
                    service = svc_el.get("name", "") or ""
                    product = svc_el.get("product", "") or ""
                    version = svc_el.get("version", "") or ""
                ports.append(Port(
                    port=int(p.get("portid", "0")),
                    protocol=p.get("protocol", "tcp"),
                    service=service,
                    product=product,
                    version=version,
                    state=state,
                ))

        hosts.append(NmapHost(
            ip=ip, hostname=hostname, mac=mac, os=os_name,
            status=status, ports=ports,
        ))
    return hosts


# --------------------------------------------------------------------------- #
# Weighting.
# --------------------------------------------------------------------------- #
def service_attackability(service_name: str) -> float:
    """Coefficient for a service (higher = easier to exploit)."""
    return SERVICE_ATTACKABILITY.get(
        (service_name or "").lower(), DEFAULT_ATTACKABILITY
    )


def host_weight(host: NmapHost) -> float:
    """Derive an edge weight (attack cost) for compromising a host.

    Weakest-link rule: the host is only as hard as its easiest exposed service,
    so we take the *maximum* service attackability and invert it into a cost on
    the toolkit's 1..10 scale. A box with nothing open is unreachable (returns
    10, the hardest).
    """
    if not host.ports:
        return 10.0
    attackability = max(service_attackability(p.service) for p in host.ports)
    # breadth bonus: more open ports = more exploitation options (capped)
    breadth = min(0.10, 0.02 * (len(host.ports) - 1))
    attackability = min(1.0, attackability + breadth)
    weight = 1.0 + 9.0 * (1.0 - attackability)
    return round(weight, 2)


# --------------------------------------------------------------------------- #
# Construction.
# --------------------------------------------------------------------------- #
def from_nmap(
    hosts: List[NmapHost],
    *,
    target: str = "foothold",
    target_role: str = "foothold / initial compromise",
    scanner: str = "scanner",
) -> ConstructedGraph:
    """Build an attack graph from parsed nmap hosts (the interior layer).

    Topology: ``scanner -> host -> foothold`` for each host with open ports.
    The ``scanner -> host`` edge is *observed* and weighted by
    :func:`host_weight` (service attackability); ``host -> foothold`` is
    *inferred* (gaining code execution is not directly measured by nmap). The
    cheapest path therefore names the easiest host to compromise first, and the
    hotspot detector ranks the most attractive first targets.
    """
    builder = GraphBuilder(
        name="Nmap Attack Surface",
        source=scanner,
        target=target,
        access=AccessLevel.MINIMAL,
        kind="security",
    )
    builder.add_host(scanner, role="nmap scanner", observed=True)
    builder.add_host(target, role=target_role, observed=False)

    # De-duplicate by node name (a hostname shared by several IPs).
    seen = set()
    observed_hosts = 0
    for host in hosts:
        if host.status != "up" or not host.ports:
            continue
        node = host.name
        if node in seen:
            continue
        seen.add(node)
        observed_hosts += 1
        role = (
            f"{host.ip} [{host.os or 'unknown OS'}] "
            f"services: {host.services_summary()}"
        )
        builder.add_host(node, role=role, observed=True)
        w = host_weight(host)
        builder.add_link(
            scanner, node, weight=w, observed=True,
            evidence=f"nmap open ports: {[p.label() for p in host.ports]}",
        )
        builder.add_link(
            node, target, weight=_INFERRED_WEIGHT, observed=False,
            evidence="inferred compromise",
        )

    return builder.build(
        description=(
            f"Constructed from nmap scan of {observed_hosts} up host(s) with "
            "open ports. scanner->host edges are observed (service-attackability "
            "weight); host->foothold edges are inferred (actual exploitation "
            "not measured by nmap)."
        )
    )


# --------------------------------------------------------------------------- #
# Live scanning (active -- authorization-gated).
# --------------------------------------------------------------------------- #
def scan_nmap(
    target_spec: str,
    *,
    authorized: bool = False,
    extra_args: Optional[List[str]] = None,
) -> List[NmapHost]:
    """Run nmap live against ``target_spec`` and parse the result.

    Sends packets (active scan) -- therefore requires ``authorized=True``.
    Parsing an existing ``-oX`` file via :func:`parse_nmap_xml` is the
    recommended, fully-offline path.
    """
    if not authorized:
        raise PermissionError(
            "scan_nmap() requires authorized=True. nmap sends packets; only "
            "scan networks you own or are authorised to assess."
        )
    if not shutil.which("nmap"):
        raise EnvironmentError("nmap is not installed or not on PATH.")
    cmd = ["nmap", "-oX", "-"] + (extra_args or []) + [target_spec]
    xml = subprocess.run(cmd, check=True, capture_output=True, text=True).stdout
    return parse_nmap_xml(xml)
