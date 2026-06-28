# Attack Graph Analysis

[![CI](https://github.com/mmohamedkhaled/attack-graph-analysis/actions/workflows/ci.yml/badge.svg)](https://github.com/mmohamedkhaled/attack-graph-analysis/actions/workflows/ci.yml)
[![PyPI](https://img.shields.io/pypi/v/attack-graph-analysis.svg)](https://pypi.org/project/attack-graph-analysis/)
[![Python 3.10+](https://img.shields.io/badge/python-3.10+-blue.svg)](https://www.python.org/)
[![License: MIT](https://img.shields.io/badge/License-MIT-yellow.svg)](LICENSE)

A modular Python **security-analysis toolkit for arbitrary weighted directed
networks**. It models *any* network -- an IT attack graph, a road system, a
supply chain, a social/influence graph -- as a directed weighted graph and
reasons about its security/robustness using graph theory:

* **CVSS-derived edge weights** -- each weight is computed from a CVSS v3.1
  Exploitability vector, so every number is traceable to a public security
  standard rather than guessed,
* a **from-scratch Bellman-Ford** implementation to find the cheapest attack
  path(s) `d(s, t)`,
* **Menger's Theorem** machinery (vertex-disjoint paths + minimum vertex cut,
  solved three independent ways) to find the smallest set of vulnerabilities to
  patch, and
* a transparent **composite security score (0-100) with a letter grade (A-F)**.

The same engine analyses **cyber, transport, supply-chain, and social**
networks -- only the vocabulary of the findings changes (see
[Modeling different networks](#modeling-different-networks)). Graphs are
defined as plain **JSON config files**, so you can model any topology without
touching code.

> The research paper and its self-contained reproduction live in
> [`paper/`](paper/) (`paper.pdf`, `paper/reproduction.py`, `paper/figure.png`).
> The `attack_graph/` package generalises those algorithms to arbitrary graphs,
> domains, and live data.

> **Data & privacy.** This repository contains **no real network data**. Every
> graph, scan sample, and hostname in `graphs/` and `discovery/` is **synthetic**
> and anonymised (e.g. placeholder `XX:XX` MACs). Live scan output is never
> committed -- `.gitignore` blocks `*.pcap`, `wifi_scan*.txt`, `nmcli_*.txt`,
> and the generated `plots/`. Only scan networks you own or are authorised to
> assess, and never push real discovery data to a public repo.

---

## Table of contents

1. [Project layout](#project-layout)
2. [Install](#install)
3. [Usage](#usage)
4. [Background: graph theory in one page](#background-graph-theory-in-one-page)
5. [Modeling different networks](#modeling-different-networks)
6. [Where are the vulnerabilities? (hotspot detection)](#where-are-the-vulnerabilities-hotspot-detection)
7. [Constructing graphs (minimal or no access)](#constructing-graphs-minimal-or-no-access)
8. [Graph export](#graph-export)
9. [JSON graph format](#json-graph-format)
10. [How edge weights are derived (the CVSS model)](#how-edge-weights-are-derived-the-cvss-model)
11. [Security scoring model](#security-scoring-model)
12. [Algorithms](#algorithms)
13. [Sample comparison](#sample-comparison)
14. [Limitations & future work](#limitations--future-work)

---

## Project layout

```
attack-graph-analysis/
├── analyze.py                   # thin shim -> attack_graph.cli (in-repo use)
├── pyproject.toml               # packaging + registers the `aga` command
├── requirements.txt             # runtime deps (networkx; matplotlib optional)
├── requirements-dev.txt         # adds ruff (lint / CI)
├── CHANGELOG.md                 # release history (Keep a Changelog)
├── aga.1                        # man page (roff)
├── aga.desktop                  # XDG application entry
├── .gitignore                   # ignores caches, plots/, live scan data
├── .github/workflows/ci.yml     # CI: ruff + smoke tests on every push/PR
├── completions/                 # shell completions for the `aga` command
│   ├── aga.bash                 #   bash
│   ├── _aga                     #   zsh
│   └── aga.fish                 #   fish
├── debian/                      # Debian/Kali packaging (control, rules, ...)
├── attack_graph/                # the reusable toolkit (the package)
│   ├── data/                    #   bundled preset graphs (shipped as package data)
│   ├── models.py                #   dataclasses: GraphSpec, SecurityMetrics, SecurityReport
│   ├── graph_io.py              #   JSON load / save / discovery (+ CVSS edge support)
│   ├── builder.py               #   build a networkx DiGraph from a spec
│   ├── construction.py          #   build graphs from real access (templates/foothold/external)
│   ├── domains.py               #   pluggable network domains (security/transport/supply-chain/social)
│   ├── weights.py               #   CVSS v3.1 -> edge-weight derivation (auditable)
│   ├── shortest_paths.py        #   custom Bellman-Ford + shortest-path extraction
│   ├── connectivity.py          #   Menger: disjoint paths, vertex/edge cuts, vertex-splitting
│   ├── vulnerabilities.py       #   hotspot detection -- *where* the weak points are
│   ├── security.py              #   metrics + composite score + grade + domain-aware findings
│   ├── export.py                #   write graphs to GraphML / DOT / JSON
│   ├── visualization.py         #   auto-layered Matplotlib plot
│   ├── cli.py                   #   the `aga` command-line interface
│   └── probes/                  #   live discovery backends
│       ├── wifi.py              #     passive WiFi scan -> attack graph (perimeter)
│       └── nmap.py              #     nmap XML parse -> attack graph (interior)
├── paper/                       # the research paper + its standalone reproduction
│   ├── paper.pdf                #   the paper (team work)
│   ├── reproduction.py          #   self-contained reproduction of the paper's analysis
│   └── figure.png               #   the paper's attack-graph figure
├── graphs/                      # ready-made network configs (any domain)
│   ├── campus_paper.json        #   cyber: the paper's campus network  (grade C)
│   ├── campus_cvss.json         #   cyber: same topology, CVSS-derived weights  (grade B)
│   ├── deep_defense.json        #   cyber: single long expensive chain  (grade A)
│   ├── isolated_target.json     #   cyber: target unreachable           (grade A)
│   ├── single_chokepoint.json   #   cyber: one path, one chokepoint     (grade B)
│   ├── highly_redundant.json    #   cyber: many disjoint routes         (grade F)
│   ├── transport_road.json      #   transport: city road mesh           (grade B)
│   ├── supply_chain.json        #   supply-chain: global sourcing graph (grade B)
│   └── social_influence.json    #   social: organisational influence graph (grade B)
├── discovery/                   # raw access descriptions -> constructed graphs
│   ├── external_only.json       #   no access: only the external attack surface is known
│   ├── foothold_web.json        #   minimal access: a single foothold + its neighbours
│   ├── wifi_sample_scan.txt     #   sample nmcli WiFi scan (for offline demos)
│   └── nmap_sample.xml          #   sample nmap XML output (for offline demos)
└── plots/                       # generated PNGs (created on demand)
```

---

## Install

`aga` is published on PyPI as the **`attack-graph-analysis`** distribution
(the `aga` command is what ends up on your PATH). Use [pipx](https://pypa.io)
to install it as an isolated tool:

```bash
# Base install -- headless CLI (networkx only). Puts the `aga` command on PATH.
pipx install attack-graph-analysis

# With GUI support (adds matplotlib for graph rendering):
pipx install attack-graph-analysis[plot]

# Upgrade
pipx upgrade attack-graph-analysis
```

> The distribution name is `attack-graph-analysis` (the short name `aga` was
> already taken on PyPI by an unrelated project). The command you run is `aga`.

Requires Python 3.10+. After install, `aga` works from anywhere; in a source
checkout `python3 analyze.py` is an equivalent shim.

### From source (development)

```bash
# Editable install with all dev/test extras (networkx, matplotlib, argcomplete,
# ruff, pytest):
pip install -e ".[dev]"
```

---

## Usage

After `pipx install attack-graph-analysis`, use `aga` from anywhere. (In a
source checkout, `python3 analyze.py <args>` is an equivalent shim.)

```bash
# Analyse the default preset (the paper's campus network)
aga

# Analyse the CVSS-weighted version of the same topology
aga graphs/campus_cvss.json

# Compare every graph in a directory side-by-side
aga --dir graphs/

# List available presets
aga --list

# Explain, step by step, how a CVSS vector becomes an edge weight
aga --explain-cvss "AV:N/AC:L/PR:N/UI:R"

# Construct a graph from a template when you have NO access, then analyse it
aga --construct 3-tier-webapp
aga --list-templates

# Construct from a discovery description (minimal / no access), then analyse
aga --discover discovery/foothold_web.json
aga --discover discovery/external_only.json

# Construct a WiFi attack graph from a captured scan (offline, for demos)
aga --wifi-from-file discovery/wifi_sample_scan.txt

# Construct an attack graph from an nmap XML scan (the network INTERIOR)
aga --nmap discovery/nmap_sample.xml

# Run a LIVE passive WiFi scan, build the graph, and analyse it
aga --scan-wifi wlp0s20f3 --i-am-authorized

# Analyse and also export the graph to a standard format (extension picks it)
aga graphs/campus_paper.json --export out.graphml
aga --scan-wifi --i-am-authorized --export wifi.dot

# Analyse without rendering plots (head-less / CI)
aga graphs/campus_paper.json --no-plot
```

### As a library

```python
from attack_graph import load_graph, analyze

spec = load_graph("graphs/campus_paper.json")
report = analyze(spec)

print(report.score, report.grade)        # e.g. 68.63 C
print(report.metrics.min_vertex_cut)     # e.g. {'v6', 'v7'} -- one valid min
                                        # cut; {v4, v5} is another (see below)
for finding in report.findings:
    print("-", finding)
```

---

## Background: graph theory in one page

This is the vocabulary the rest of the document uses. Skip it if you are
already comfortable with directed graphs, shortest paths, and cuts.

**Directed weighted graph.** A graph `G = (V, E, w)` has a vertex set `V`
(the hosts/vulnerabilities), a directed edge set `E` (feasible exploit
transitions `u -> v`), and a weight function `w: E -> R+` (the cost of each
transition). A **DAG** is a directed graph with no cycles; the paper's campus
network is one.

**Shortest path `d(s, t)`.** The minimum total weight of any path from the
source `s` (attacker entry) to the target `t` (protected asset). In an attack
graph this is the *cheapest realistic attack*. We compute it with a
hand-written **Bellman-Ford**, which relaxes every edge `|V|-1` times and can
report an iteration-by-iteration trace; it also detects negative cycles
(negative-cost attack loops), which would otherwise let the cost diverge.

**Tied shortest paths.** A single predecessor pointer recovers only *one*
shortest path. To find *all* of them we build the **shortest-path sub-DAG**
(the edges `(u,v)` where `dist[u] + w(u,v) == dist[v]`) and enumerate its
`s-t` paths. Ties matter for security: more equally-cheap routes means a more
exposed target.

**Vertex cut.** A set `C` of vertices whose removal disconnects `s` from `t`.
A **minimum vertex cut** `C*` is one of smallest cardinality -- the smallest
set of vulnerabilities that, once patched, breaks *every* attack path. (Note:
several different minimum cuts can exist; e.g. the campus network has five of
size 2. The paper highlights `{v4, v5}`, the toolkit returns `{v6, v7}` -- both
are equally minimal.)

**Menger's Theorem** (vertex form). For any `s` and `t`:

```
max # internally vertex-disjoint s-t paths  ==  min |s-t vertex cut|
```

Two paths are *internally vertex-disjoint* if they share only `s` and `t`. So
the *most* independent attack routes equals the *fewest* vertices you must
patch -- the same number, reached from two directions. We verify the equality
three independent ways (networkx flow, vertex-splitting max-flow, exhaustive
enumeration).

**Why weights matter.** Every conclusion above depends on the edge weights:
`d(s, t)` is a weighted shortest path, and even the *number* of shortest paths
depends on which edges tie. If the weights are arbitrary, so are the
conclusions. That is why the [CVSS model](#how-edge-weights-are-derived-the-cvss-model)
grounds them in real exploitability metrics.

---

## Modeling different networks

The toolkit is a **single security engine that works on any weighted directed
network**. The algorithms (Bellman-Ford, Menger, composite scoring) are
completely domain-agnostic; what changes between applications is only the
*vocabulary* used to explain the results. A `NetworkKind`
([`attack_graph/domains.py`](attack_graph/domains.py)) supplies that
vocabulary, so findings read naturally for each domain:

| `kind` | Network | Vertex | Source | Target | Weight | Mitigation |
|---|---|---|---|---|---|---|
| `security` (default) | IT / cyber attack graph | host / vulnerability | attacker entry | protected asset | exploit cost | patch |
| `transport` | road / routing network | junction | origin | destination | travel distance | close |
| `supply-chain` | logistics network | facility | supplier origin | critical customer | shipment cost | disrupt |
| `social` | influence / comms network | person | source individual | key person | influence resistance | isolate |

No matter the domain, the engine asks the **same security questions**:

* *What is the cheapest way for a threat to travel from an entry point to the
  critical asset?* -- shortest path `d(s, t)`.
* *What is the smallest set of nodes whose removal defends it?* -- minimum
  vertex cut (Menger).
* *How defensible is the network overall?* -- composite score (0-100) + grade.

### Authoring a network in any domain

Add a `"kind"` field to the JSON config (omitting it defaults to `security`):

```json
{
  "name": "City Road Network",
  "kind": "transport",
  "source": "depot",
  "target": "hospital",
  "vertices": ["depot", "j1", "j2", "j3", "j4", "j5", "j6", "hospital"],
  "edges": [
    {"from": "depot", "to": "j1", "weight": 5},
    {"from": "j1", "to": "j3", "weight": 4}
  ],
  "node_roles": {"depot": "origin (logistics depot)", "hospital": "critical facility"}
}
```

The same command analyses every domain:

```bash
python3 analyze.py graphs/transport_road.json
python3 analyze.py graphs/supply_chain.json
python3 analyze.py graphs/social_influence.json
python3 analyze.py --dir graphs/        # compare all domains side-by-side
```

### Example: the same finding, two vocabularies

The minimum-cut finding adapts its wording to the domain while the underlying
math is identical:

> **security** -- *"Minimum vertex cut |C*| = 2: **patching** `{v4, v5}`
> severs every **attack path**."*
>
> **supply-chain** -- *"Minimum vertex cut |C*| = 2: **disrupting** `{f1, f2}`
> severs every **supply route**."*

### Adding your own domain

Register a new `NetworkKind` in `attack_graph/domains.py` -- no algorithm code
changes. The engine, scorer, CLI, and visualiser then work on your domain
automatically.

```python
from attack_graph.domains import NETWORK_KINDS, NetworkKind

NETWORK_KINDS["water"] = NetworkKind(
    code="water",
    name="Water Distribution Network",
    vertex_term="valve / junction",
    source_term="treatment plant",
    target_term="critical consumer",
    weight_term="flow resistance",
    traverse_verb="flow",
    mitigate_verb="shut",
    mitigating="shutting",
    path_term="flow path",
    threat_term="contaminant",
)
```

---

## Where are the vulnerabilities? (hotspot detection)

The score answers *"how secure is the network?"* and Menger answers *"what
is the smallest set of nodes to defend?"*. Neither answers the question an
analyst actually asks first: ***"where, exactly, are the weak points -- and
why does each one matter?"***

[`attack_graph/vulnerabilities.py`](attack_graph/vulnerabilities.py) answers
that. For **every node** it blends two complementary views into a 0-100
*vulnerability score* with a severity label:

* **Exposure** (attacker's view) -- how cheaply the node is reached from the
  entry point, and whether it lies on the cheapest path. A cheap node is the
  *first to fall*.
* **Criticality** (defender's view) -- betweenness centrality, the fraction of
  all paths that pass through the node, membership of the minimum vertex cut,
  and whether it is a **single point of failure** (on *every* path). A
  critical node, once lost, is catastrophic.

A node that is **both cheap to reach and highly critical** is the worst
vulnerability.

### What the detector looks for

| Signal | Meaning | Severity floor |
|---|---|---|
| **SPOF** -- on every path | unavoidable single point of failure | Critical |
| **MIN-CUT** -- in the minimum vertex cut | removing/patching it breaks all paths | High |
| **ON-CHEAPEST-ROUTE** -- on a shortest path | first node compromised in the cheapest attack | Medium |
| high betweenness | critical chokepoint | boosts score |
| low cost from source | easily reached | boosts score |

### Example: a road network

```
 VULNERABILITY HOTSPOTS  (where the weak points are)
   High      j5   (score 70.0) [MIN-CUT, ON-CHEAPEST-ROUTE]  east junction
              - in the minimum defense set -- closing it severs every route
              - on the cheapest route (first to traverse)
              - carries 75% of all routes
              - easily reached -- only 14 travel distance from origin
   High      j6   (score 70.0) [MIN-CUT]                     bypass junction
              - in the minimum defense set -- closing it severs every route
   Medium    j3   (score 50.0) [ON-CHEAPEST-ROUTE]           central junction
              - on the cheapest route (first to traverse)
```

The same output, in the domain's vocabulary, is produced for cyber, supply
chain, and social networks. If any node sits on **every** path, the report
flags a ***SINGLE POINT OF FAILURE***.

### Programmatic use

```python
from attack_graph import load_graph, analyze

report = analyze(load_graph("graphs/transport_road.json"))
for v in report.vulnerabilities.top(3):
    print(f"{v.severity:<9} {v.node:<6} score={v.score}  {v.role}")
    for r in v.reasons:
        print("          -", r)
```

Each `NodeVulnerability` exposes the raw signals too (`dist_from_source`,
`betweenness`, `path_coverage`, `on_shortest_path`, `on_all_paths`,
`in_min_cut`) so you can build custom dashboards on top.

---

## Constructing graphs (minimal or no access)

Everything above assumes you already *have* a graph. Often you do not -- you
have **partial knowledge of a live system** and must build the graph yourself.
[`attack_graph/construction.py`](attack_graph/construction.py) does this, and
it is honest about **how much access you actually have**:

| Access level | What you know | Constructor |
|---|---|---|
| `none` | black-box: only the externally-exposed surface; interior inferred | `from_external_observation`, `from_template` |
| `minimal` | a single foothold + its immediate neighbours; deeper hops inferred | `from_foothold` |
| `partial` / `full` | several or all hosts known | `from_adjacency`, `from_discovery` |

The key idea is **provenance**: every node and edge is tagged *observed* (you
have direct evidence) or *inferred* (a hypothesis). A graph built with no
access is mostly inferred, and that uncertainty is preserved on the
:class:`ConstructedGraph` -- so you can **analyse a system you have no access
to**, with the result explicitly a best-effort guess rather than ground truth.

> No live scanning is performed. The constructors consume data you already
> have (a discovery description, a template choice, an adjacency list) and
> assemble a `GraphSpec` ready for `analyze()`. Run them only on systems you
> own or are authorised to assess.

### No access at all: external observation

You can only see what is exposed to the internet. The interior is a hypothesis:

```python
from attack_graph import from_external_observation, analyze

cg = from_external_observation(
    exposed=[("web-edge", "public web app", 2), ("vpn-edge", "VPN gateway", 4)],
    target="internal-data",
)
print(cg.summary())        # none access: 3 observed / 1 inferred ... (confidence 0.75)
report = analyze(cg.spec)  # analyses the hypothesised topology
```

### Minimal access: a single foothold

You have compromised one host and discovered its neighbours; deeper links are
inferred:

```python
from attack_graph import from_foothold, analyze

cg = from_foothold(
    foothold="web", target="db",
    neighbors={
        "web":  [("app", 2, "port scan"), ("auth", 3, "port scan")],
        "app":  [("db", 4)],
        "auth": [("db", 3)],
    },
)
report = analyze(cg.spec)
```

### No access: start from a template

When you know nothing, begin from a representative topology and refine it:

```bash
python3 analyze.py --list-templates        # 3-tier-webapp, dmz-internal, flat-lan
python3 analyze.py --construct 3-tier-webapp
```

### Discovery files (any access level)

Spell out exactly what you observed vs inferred in a JSON file -- this is the
most explicit and auditable way to build a graph from real access:

```json
{
  "access": "minimal",
  "kind": "security",
  "source": "web-01", "target": "db-01",
  "hosts": [
    {"id": "web-01", "role": "foothold",         "observed": true},
    {"id": "db-01",  "role": "database (target)","observed": false}
  ],
  "links": [
    {"from": "web-01", "to": "app-01", "weight": 2, "observed": true,  "evidence": "port scan"},
    {"from": "app-01", "to": "db-01",  "weight": 4, "observed": false, "evidence": "inferred"}
  ]
}
```

```bash
python3 analyze.py --discover discovery/foothold_web.json    # minimal access
python3 analyze.py --discover discovery/external_only.json   # no access
```

### Reading the provenance

Every constructed graph reports its confidence and tags each node
`[observed]` or `[inferred]`. When the hotspot detector then flags
`internal-app` as a Critical single point of failure in a no-access scan, its
role reads `internal application tier [inferred]` -- so you know that
conclusion rests on a hypothesis, not a measurement. That distinction is the
whole point: **the toolkit never hides how much it actually knows**.

### Live WiFi scanning

The WiFi probe ([`attack_graph/probes/wifi.py`](attack_graph/probes/wifi.py))
listens to the beacon frames nearby access points broadcast (a **passive**
operation -- your phone does the same to list networks) and builds an attack
graph where each AP is an entry point weighted by how attackable it is:

| Signal | Security | Effect on weight |
|---|---|---|
| stronger (closer) | -- | cheaper to attack |
| -- | Open / WEP / WPA1 | cheap (weak crypto) |
| -- | WPA2 / WPA3 | expensive (strong crypto) |

```
weight = 1 + 9 * security_strength * (1 - 0.5 * signal_ease)
```

so a close open network is ~1.5 and a far WPA3 network is ~10. The cheapest
path then names the *easiest network to breach*; the hotspot detector ranks the
weakest APs.

```bash
# Offline (parse a captured nmcli scan -- for demos/tests):
python3 analyze.py --wifi-from-file discovery/wifi_sample_scan.txt

# Live (passive scan of your own / authorised airspace):
python3 analyze.py --scan-wifi wlp0s20f3 --i-am-authorized
python3 analyze.py --scan-wifi --i-am-authorized --wifi-rescan   # fresh rescan
```

> **Safety.** The probe is observation-only: it does **not** deauthenticate,
> capture handshakes, inject packets, crack keys, or associate with any
> network. It requires an explicit `--i-am-authorized` flag, and you should
> only scan airspace you own or are authorised to assess.

```python
from attack_graph import scan_wifi, from_wifi_scan, analyze, wifi_weight

print(wifi_weight(signal=54, security="WEP"))   # 2.97 -- weak + moderate signal
aps = scan_wifi("wlp0s20f3", authorized=True)   # passive scan
report = analyze(from_wifi_scan(aps).spec)      # build + analyse
```

#### Merging scans (why only ~17, and how to see more)

A single scan hears only the APs within radio range (~30-100m) -- that is why
you see ~17, not "everything". Each AP is also a hard boundary: behind it lies
a private LAN you cannot observe without breaching it (which is why those
`AP -> foothold` edges are `[inferred]`). The legitimate way to grow the
*observed* part is **wardriving** -- scan from several locations and merge:

```python
from attack_graph import scan_wifi, from_wifi_scans, analyze

loc1 = scan_wifi("wlp0s20f3", authorized=True)
# ...move to another location...
loc2 = scan_wifi("wlp0s20f3", authorized=True)
report = analyze(from_wifi_scans([loc1, loc2]).spec)  # dedupes by BSSID, keeps strongest
```

The interior of each network stays opaque -- that boundary is fundamental, not
a tool limitation.

### nmap ingest (the *interior* layer)

The WiFi probe sees the perimeter; nmap sees the **interior** -- the actual
hosts, open ports, and services. [`attack_graph/probes/nmap.py`](attack_graph/probes/nmap.py)
parses nmap's XML output (`nmap -oX`) and builds a weighted graph where each
host's weight comes from its exposed services:

* **Weakest-link rule** -- a host is only as hard to breach as its easiest
  exposed service, so the weight takes the *most attackable* service and inverts
  it onto the 1..10 scale.
* `telnet`/`ftp` -> ~1.3 (cheap); `mysql`/`smb`/`rdp` -> ~2.8 (high-value
  targets); `ssh` -> ~7.3 (expensive); nothing open -> unreachable.

The cheapest path then names the **easiest host to compromise first**, and the
hotspot detector ranks the most attractive first targets.

```bash
# Offline (parse an existing nmap XML scan -- recommended, fully safe):
python3 analyze.py --nmap discovery/nmap_sample.xml

# Live (sends packets -- requires authorisation; scan only what you own):
python3 analyze.py --nmap-live 10.0.0.0/24 --i-am-authorized
```

> **The two layers together.** For a WiFi-protected network you cannot nmap the
> interior until you have passed the wireless perimeter, so the layers chain:
> *WiFi scan (outside) -> breach -> nmap (interior)*. The WiFi graph is real on
> the outside / inferred inside; adding nmap turns the inferred interior into
> observed hosts and edges.

```python
from attack_graph import parse_nmap_xml, from_nmap, analyze

hosts = parse_nmap_xml("scan.xml")              # nmap -oX scan.xml
report = analyze(from_nmap(hosts).spec)         # build + analyse
```

nmap does **not** measure host-to-host lateral reachability, so the nmap graph
is a star (scanner -> hosts) ranking first-compromise targets -- honest about
what a single scan can tell you. Real lateral edges would come from scans run
from *inside* after a foothold (merge them with the construction API).

---

## Graph export

Any graph -- hand-written, constructed, or scanned -- can be written to a
standard interchange format so it works with the rest of the ecosystem
(Gephi, yEd, Cytoscape, Graphviz, Neo4j import, ...). The format is chosen
from the file extension, and all attributes survive (node `role` + provenance
tag, edge `weight`, CVSS vector):

| Extension | Format | Use |
|---|---|---|
| `.graphml` / `.xml` | GraphML | Gephi, yEd, Cytoscape, Neo4j |
| `.dot` / `.gv` | Graphviz DOT | `dot -Tpng in.dot -o out.png` |
| `.json` | toolkit config | round-trips exactly |

```bash
python3 analyze.py graphs/campus_paper.json --export out.graphml
python3 analyze.py --scan-wifi --i-am-authorized --export wifi.dot
```

```python
from attack_graph import load_graph, export
export(load_graph("graphs/campus_paper.json"), "out.dot")     # auto-detects DOT
export(load_graph("graphs/campus_paper.json"), "out.graphml") # -> GraphML
```

---

## JSON graph format

```json
{
  "name": "Campus Network (paper)",
  "description": "...",
  "source": "s",
  "target": "t",
  "vertices": ["s", "v1", "v2", "v3", "v4", "v5", "v6", "v7", "t"],
  "edges": [
    {"from": "s",  "to": "v1", "weight": 2},
    ["s", "v1", 2],
    {"from": "v1", "to": "v4", "cvss": "AV:A/AC:L/PR:L/UI:N", "cve": "SMB relay"}
  ],
  "node_roles": {"s": "public web server", "t": "records database"}
}
```

An edge may be written in **three** forms:

1. **Explicit weight** -- `{"from","to","weight"}`. Use this when you already
   have a cost in mind (the paper's hand-picked integers use this form).
2. **Compact triple** -- `[u, v, w]`.
3. **CVSS-derived** -- `{"from","to","cvss"}`. The weight is computed
   automatically at load time from the CVSS v3.1 Exploitability vector (see
   [How edge weights are derived](#how-edge-weights-are-derived-the-cvss-model)
   below). An optional `cve` label is recorded for documentation but does not
   affect the number.

You may also supply both `weight` *and* `cvss` -- `weight` wins, and the CVSS
vector is kept on the edge purely for traceability.

* `vertices` -- the vertex set `V`.
* `edges` -- any mix of the three forms above. Weights must be **positive**.
* `source` / `target` -- the attacker entry point and the protected asset.
* `node_roles` (optional) -- human-readable host roles, surfaced in findings.

---

## How edge weights are derived (the CVSS model)

> **This section answers the project's central modelling question:** *what
> number should an attack-graph edge carry, and how do we know -- in real life
> -- that one edge's weight is higher than another's?*

### The modelling principle

An attack-graph **vertex** is a compromised asset (a host or a privilege); an
**edge** is the *act of exploiting a transition* from one to the next. The
edge **weight** is therefore the **effort/cost the attacker must expend** to
make that transition. Bellman-Ford then finds the minimum-total-cost path,
i.e. the cheapest realistic attack.

That is the *principle*. The hard part is the *number*: why should one edge be
`2` and another `5`? Picking integers by gut feel is not defensible. Instead,
we derive every weight from a **public, calibrated standard -- the CVSS v3.1
Exploitability metrics** -- so that each weight is reproducible from a CVE
record and explainable factor by factor.

### Why CVSS Exploitability, specifically

CVSS (Common Vulnerability Scoring System, v3.1) is the industry-standard
language for describing how a vulnerability is exploited. Its *Exploitability*
sub-score captures exactly the four things that make a real exploit expensive
for an attacker, with calibrated numeric coefficients:

| Metric | Code | Question answered | Values (coefficient) |
|---|---|---|---|
| Attack Vector | `AV` | How remote can the attacker be? | Network `.85`, Adjacent `.62`, Local `.55`, Physical `.20` |
| Attack Complexity | `AC` | Conditions beyond the attacker's control? | Low `.77`, High `.44` |
| Privileges Required | `PR` | Prior access the attacker must already hold? | None `.85`, Low `.62`, High `.27` |
| User Interaction | `UI` | Must a second human cooperate? | None `.85`, Required `.62` |

Edge weights should *rise* with every one of those factors. CVSS already
calibrated the coefficients, so we reuse its formula instead of inventing a
private rubric. (Impact metrics C/I/A describe *what is harmed* and belong to
the vertex -- the compromised asset -- not to the edge.)

### The derivation, in four steps

**Step 1 -- CVSS Exploitability sub-score** (the official v3.1 formula):

```
E = 8.22 * AV * AC * PR * UI
```

`E` is large when the exploit is *easy* (network-reachable, low complexity,
no privileges, no user interaction) and small when it is *hard*. The
theoretical range is `E in [0.121, 3.887]`.

**Step 2 -- Normalise to `[0, 1]`:**

```
norm = (E - E_min) / (E_max - E_min)      # 1 = easiest, 0 = hardest
```

**Step 3 -- Invert into a difficulty** (the attacker *minimises* path cost, so
an easy exploit must be a *cheap* edge):

```
difficulty = 1 - norm                       # 0 = easy, 1 = hard
```

**Step 4 -- Map onto the weight scale** (default `1..10`, overridable in
`attack_graph/weights.py`):

```
weight = W_min + (W_max - W_min) * difficulty
```

### Why this is well-calibrated: sanity checks

The whole point is that the numbers now match common-sense security reasoning.
Each row below is reproducible with `python3 analyze.py --explain-cvss "..."`:

| Scenario | CVSS vector | Exploitability `E` | **Weight** |
|---|---|---|---|
| Trivial remote RCE | `AV:N/AC:L/PR:N/UI:N` | 3.887 | **1.00** |
| Phishing (needs a click) | `AV:N/AC:L/PR:N/UI:R` | 2.835 | **3.51** |
| Adjacent-net exploit, low priv | `AV:A/AC:L/PR:L/UI:N` | 2.068 | **5.35** |
| Race condition (high complexity) | `AV:N/AC:H/PR:N/UI:N` | 2.221 | **4.98** |
| Network service needing admin | `AV:N/AC:L/PR:H/UI:N` | 1.235 | **7.34** |
| Local privesc to domain admin | `AV:L/AC:H/PR:H/UI:N` | 0.457 | **9.20** |
| Physical + user interaction | `AV:P/AC:H/PR:H/UI:R` | 0.121 | **10.0** |

Notice how the weight moves the way a security engineer would expect: needing
prior privileges, local or physical access, or a cooperating user all push the
cost up -- and now we can say *exactly by how much and why*.

### Worked example on the campus network

`graphs/campus_paper.json` uses the paper's hand-picked integers (`1`-`5`).
`graphs/campus_cvss.json` keeps the **identical topology** but re-annotates
each edge with a realistic CVSS vector, so the weights are derived rather than
guessed:

| Edge | Exploit modelled | CVSS vector | Derived w | Paper w |
|---|---|---|---|---|
| `s->v1` | remote RCE on public web app | `AV:N/AC:L/PR:N/UI:N` | 1.00 | 2 |
| `s->v2` | race condition in mail relay | `AV:N/AC:H/PR:N/UI:N` | 4.98 | 4 |
| `s->v3` | stored-XSS pivoted via file server | `AV:N/AC:L/PR:N/UI:R` | 3.51 | 3 |
| `v1->v4` | SMB relay onto pivot host | `AV:A/AC:L/PR:L/UI:N` | 5.35 | 3 |
| `v3->v5` | local privesc to domain admin | `AV:L/AC:H/PR:H/UI:N` | 9.20 | 5 |
| `v4->v5` | Kerberoasting across subnet | `AV:A/AC:H/PR:H/UI:N` | 9.06 | 4 |
| `v5->v6` | app-server admin abuse | `AV:N/AC:L/PR:H/UI:N` | 7.34 | 2 |
| `v7->t`  | local dump of backup image | `AV:L/AC:L/PR:H/UI:N` | 8.38 | 3 |

Because the derived weights spread realistically (`1`-`9.2`) instead of
compressing into `1`-`5`, the cheapest attack becomes considerably more
expensive:

```
                       d(s,t)   Grade
Campus (paper, int)       11      C
Campus (CVSS-derived)   20.07     B
```

This is exactly the kind of defensible, reproducible result the CVSS model
enables: the topology is unchanged, but the numbers are now traceable to
public security metrics.

### Authoring a CVSS-derived edge

Use the `cvss` key (and an optional `cve` label for documentation):

```json
{"from": "v1", "to": "v4", "cvss": "AV:A/AC:L/PR:L/UI:N", "cve": "SMB relay"}
```

On load, the weight is computed and stored on the edge together with a
human-readable `weight_basis` string (`"CVSS AV:A/AC:L/PR:L/UI:N -> E=2.068,
difficulty=0.483 -> weight=5.35"`). The analysis report prints the full
audit trail for every CVSS-derived edge under an **EDGE WEIGHTS** block.

### Programmatic use

```python
from attack_graph import derive_weight

d = derive_weight("AV:L/AC:H/PR:H/UI:N")
print(d.weight)        # 9.2
print(d.explain())     # weight=9.20  [exploitability E=0.457, difficulty=0.911]
                       # (AV=Local(L), AC=High(H), PR=High(H), UI=None(N))
```

### References

* CVSS v3.1 Specification Document -- <https://www.first.org/cvss/v3.1/specification-document>
* CVSS v3.1 Examples -- <https://www.first.org/cvss/examples>

---

## Security scoring model

The composite score blends four dimensions (each normalised so
**higher = more secure**):

| Component (weight)        | Metric                              | Direction          |
|---------------------------|-------------------------------------|--------------------|
| Attack cost (35%)         | shortest-path cost `d(s, t)`        | higher = more secure |
| Path diversity (25%)      | number of tied shortest paths       | fewer = more secure  |
| Mitigation effort (25%)   | minimum vertex cut `|C*|`           | lower = more secure  |
| Exposure (15%)            | number of distinct attack paths     | fewer = more secure  |

Grades: **A >= 85**, **B >= 70**, **C >= 55**, **D >= 40**, **F < 40**.

If the target is **unreachable** from the source, the network is perfectly
secure (score 100, grade A).

Weights and penalties are configurable in `attack_graph/security.py`
(`ScoringConfig`).

---

## Algorithms

* **Bellman-Ford** (`shortest_paths.bellman_ford`) -- implemented from scratch,
  with an optional iteration-by-iteration trace and negative-cycle detection.
* **Tied shortest paths** -- recovered by building the shortest-path sub-DAG
  (edges where `dist[u] + w == dist[v]`) and enumerating its s-t paths.
* **Minimum vertex cut** -- computed three ways for cross-validation:
  1. `networkx.minimum_node_cut` (flow-based),
  2. an explicit **vertex-splitting transformation** (`v_in -> v_out`, cap 1)
     solved with max-flow min-cut,
  3. exhaustive enumeration (`all_minimum_vertex_cuts`) to confirm a specific
     canonical cut.
* **Menger's equality** is verified as
  `max vertex-disjoint paths == min vertex cut cardinality`.

---

## Sample comparison

```
Graph                      Kind           Reach   d(s,t)  #sh  #atk  |C*|   Score  Grade
--------------------------------------------------------------------------------------
Campus Network (CVSS)      security        yes    20.07    1     5     2    77.8     B
Campus Network (paper)     security        yes        11    2     5     2   68.63     C
Deep Defense               security        yes        20    1     1     1    92.5     A
Isolated Target           security         NO          -    0     0     0   100.0     A
Single Chokepoint         security        yes         9    1     1     1   83.75     B
Highly Redundant          security        yes         3    5     5     3   19.05     F
City Road Network         transport       yes        17    1     4     2    79.6     B
Global Supply Chain       supply-chain    yes        13    2     5     2   71.55     B
Organisational Influence  social          yes        10    1     4     2   73.77     B
```

The bottom three rows are *not* attack graphs -- they are a road mesh, a
logistics network, and an influence graph -- yet the same engine scores them
all. The two *Campus Network* rows share a topology; only the weighting
differs (CVSS-derived vs. the paper's hand-picked integers). Scores are
reproducible with `python3 analyze.py --dir graphs/ --no-plot`.

---

## Limitations & future work

The model is deliberately transparent and reproducible, but it makes
simplifications worth stating plainly (especially for a research context):

**Weighting model.**
* Edges are weighted from the CVSS v3.1 **Exploitability** metrics only
  (AV/AC/PR/UI). Impact (Confidentiality/Integrity/Availability) is modelled
  on the *vertex* (the compromised asset), not on the edge, because the edge
  represents the *act* of exploiting a transition.
* The `1..10` output scale is a linear map of normalised difficulty; it is
  well-calibrated for ranking but the absolute numbers are a modelling choice,
  not a measurement. Tunable via `w_min`/`w_max` in `attack_graph/weights.py`.
* CVSS scores a *single vulnerability*; an edge may bundle several. We assume
  the stated vector dominates the transition's difficulty.

**Graph model.**
* Weights are **static** and **independent** -- the cost of exploiting one
  edge does not change after a prior compromise, and there is no notion of
  attacker skill accumulation or detection probability over time.
* A **single attacker model** is assumed (one source, one target, full
  knowledge of the graph). There is no defender moving in parallel, no
  probabilistic uncertainty, and no time-to-compromise.

**Scoring model.**
* The composite score is a transparent, fixed-weight blend (see
  `ScoringConfig`); it is a defensible summary, not an empirical calibration.
  The grade thresholds (A>=85, ...) are conventional, not data-driven.

**Possible extensions.**
* **Bayesian / probabilistic attack graphs** -- edge weights as
  `-log(P(success))` so path cost becomes a log-likelihood and the cheapest
  path is the most *likely* attack.
* **CVSS v4.0** -- the newer standard adds Supplemental and Environmental
  metrics; the metric table in `weights.py` is the natural extension point.
* **Dynamic re-weighting** -- let an edge's weight depend on previously
  visited vertices (e.g. once domain admin is held, lateral moves cheapen).
* **Empirical calibration** -- fit the `ScoringConfig` penalties against a
  dataset of real breaches so the letter grade predicts incident outcomes.
