"""Entity graph built from structured evidence fields (never ``raw``).

Node keys are ``<type>:<normalised value>``; process, directory and file nodes
are scoped to their host (``process:srv-db-01|bhz.exe``). Each edge aggregates
every evidence record that shows the same relationship and cites all of them.

    account  --started-->        process        (process_start)
    host     --runs-->           process
    process  --child_of-->       process        (parent image on the same host)
    process  --has_hash-->       hash
    file     --executed_as-->    process        (image path)
    process  --wrote_in-->       dir            (file activity, per directory)
    process  --created-->        file           (executables / scripts created)
    host     --connected_to-->   ip | host      (flow / connect; attrs: port)
    process  --connected_to-->   ip | host      (EDR connect)
    host     --resolved-->       domain ; domain --resolves_to--> ip
    host     --requested-->      domain         (proxy; attrs: outcome)
    ip       --http_request_to-> host           (web access; attrs: status)
    account  --logged_on_to-->   host           (attrs: outcome, logon type)
    host|ip  --remote_auth-->    host           (network logons; attrs: outcome)
    host     --autostarts-->     file           (service / Run key)
    alert    --about-->          host | process
    email    --delivered_to-->   account

An address that the evidence-derived address book resolves to exactly one host
is represented by that host. Size is bounded (nodes/edges); truncation is
reported, never silent. ``find_path`` treats edges as undirected: a path shows
that entities are CONNECTED through evidence, not that one caused the other -
use the timeline for sequence.
"""

from __future__ import annotations

import json
from collections import defaultdict, deque
from typing import Any

from cyberrescue.core.audit import canonical_json
from cyberrescue.detection.context import Ev, EvidenceView
from cyberrescue.detection.matchers import (
    basename,
    dirname,
    normalize_domain,
    normalize_ip,
    normalize_sha256,
    url_host,
)
from cyberrescue.detection.model import digest
from cyberrescue.investigation.model import EntityGraph, GraphEdge, GraphNode, untrusted

MAX_NODES = 2000
MAX_EDGES = 5000
_CREATED_EXT = (".exe", ".dll", ".ps1", ".bat", ".cmd", ".vbs", ".js", ".scr", ".msi")


def host_key(h: str | None) -> str | None:
    return f"host:{h}" if h else None


def account_key(a: str | None) -> str | None:
    return f"account:{a.lower()}" if a else None


def process_key(host: str | None, image: str | None) -> str | None:
    name = basename(image or "").lower()
    return f"process:{host}|{name}" if host and name else None


def ip_key(v: object) -> str | None:
    ip = normalize_ip(v)
    return f"ip:{ip}" if ip else None


def domain_key(v: object) -> str | None:
    d = normalize_domain(v)
    return f"domain:{d}" if d else None


def hash_key(v: object) -> str | None:
    h = normalize_sha256(v)
    return f"hash:{h}" if h else None


def file_key(host: str | None, path: str | None) -> str | None:
    return f"file:{host}|{path.lower()}" if host and path else None


def addr_key(view: EvidenceView, v: object) -> str | None:
    """An address as an entity: its host when the evidence-derived address book
    resolves it unambiguously, otherwise the ip itself."""
    host = view.addresses.resolve(v)
    return host_key(host) if host else ip_key(v)


def source_host(view: EvidenceView, e: Ev) -> str | None:
    ws = e.s("source.domain")
    if ws and view.assets.is_asset(ws):
        return ws
    return view.addresses.resolve(e.s("source.ip"))


def edges_of(view: EvidenceView, e: Ev) -> list[tuple[str, str, str, dict[str, Any], str]]:
    """(src_key, rel, dst_key, attrs, label-of-dst) for one evidence record."""
    out: list[tuple[str | None, str, str | None, dict[str, Any], str | None]] = []
    host, user, t = e.host, e.user, e.event_type
    if t == "process_start":
        exe = e.s("process.executable") or e.s("process.name")
        proc = process_key(host, exe)
        out += [(account_key(user), "started", proc, {}, exe),
                (host_key(host), "runs", proc, {}, exe),
                (proc, "child_of", process_key(host, e.s("process.parent.name")), {},
                 e.s("process.parent.name")),
                (proc, "has_hash", hash_key(e.s("process.hash.sha256")), {},
                 e.s("process.hash.sha256")),
                (file_key(host, e.s("process.executable")), "executed_as", proc, {}, exe)]
    elif e.kind == "file":
        path = e.s("file.path")
        proc = process_key(host, e.s("process.name"))
        d = dirname(path or "")
        out.append((proc, "wrote_in", f"dir:{host}|{d}" if host and d else None,
                    {"action": t}, d))
        if path and path.lower().endswith(_CREATED_EXT) and t != "file_rename":
            out.append((proc, "created", file_key(host, path), {}, path))
    elif t in ("flow", "network_connect"):
        dst = e.s("destination.ip")
        attrs = {"port": e.i("destination.port")}
        out.append((host_key(host), "connected_to", addr_key(view, dst), attrs, dst))
        if t == "network_connect":
            out.append((process_key(host, e.s("process.name")), "connected_to",
                        addr_key(view, dst), attrs, dst))
    elif t == "dns_query":
        q = e.s("dns.question.name")
        out.append((host_key(host), "resolved", domain_key(q), {}, q))
        out += [(domain_key(q), "resolves_to", ip_key(a), {}, a) for a in e.strings("dns.answers")]
    elif t == "http_request":
        h = url_host(e.s("url.original"))
        out.append((host_key(host), "requested", domain_key(h),
                    {"outcome": e.s("event.action")}, h))
    elif t == "http_access":
        out.append((addr_key(view, e.s("source.ip")), "http_request_to", host_key(host),
                    {"status": e.i("http.response.status_code")}, host))
    elif e.kind == "auth" and t in ("4624", "4625"):
        attrs = {"outcome": e.s("event.outcome"), "logon_type": e.s("winlog.logon.type")}
        out.append((account_key(user), "logged_on_to", host_key(host), attrs, host))
        if e.s("winlog.logon.type") == "3":
            src = source_host(view, e)
            out.append((host_key(src) if src else ip_key(e.s("source.ip")), "remote_auth",
                        host_key(host) if src != host else None,
                        {"outcome": e.s("event.outcome"), "account": (user or "").lower()},
                        host))
    elif t == "7045":
        target = e.s("service.executable")
        out.append((host_key(host), "autostarts", file_key(host, target),
                    {"mechanism": "service"}, target))
    elif t == "registry_set":
        for target in e.strings("registry.data.strings"):
            out.append((host_key(host), "autostarts", file_key(host, target),
                        {"mechanism": "run_key"}, target))
    elif e.kind == "alert":
        rule = e.s("rule.name")
        alert = f"alert:{host}|{(rule or '?').lower()}" if host else None
        out.append((alert, "about", host_key(host), {}, host))
        if e.s("process.name"):
            out.append((alert, "about", process_key(host, e.s("process.name")), {},
                        e.s("process.name")))
    elif t == "message_delivered":
        sender = (e.s("email.from.address") or "").lower()
        out.append((f"email:{sender}" if sender else None, "delivered_to", account_key(user),
                    {}, user))
    return [(s, r, d, a, lab) for s, r, d, a, lab in out if s and d and s != d]


def _label(key: str, given: str | None) -> str:
    return given or key.split(":", 1)[1]


def build_graph(view: EvidenceView, *, max_nodes: int = MAX_NODES,
                max_edges: int = MAX_EDGES) -> EntityGraph:
    labels: dict[str, str] = {}
    edges: dict[tuple, list[str]] = defaultdict(list)
    truncated = False
    for e in view.events:
        for src, rel, dst, attrs, dst_label in edges_of(view, e):
            key = (src, rel, dst, canonical_json(attrs))
            new_nodes = [n for n in (src, dst) if n not in labels]
            if key not in edges and (len(edges) >= max_edges
                                     or len(labels) + len(new_nodes) > max_nodes):
                truncated = True
                continue
            labels.setdefault(src, _label(src, None))
            if dst not in labels or labels[dst] == _label(dst, None):
                labels[dst] = _label(dst, dst_label)
            edges[key].append(e.id)
    nodes = tuple(GraphNode(key=k, type=k.split(":", 1)[0], label=untrusted(v))
                  for k, v in sorted(labels.items()))
    out_edges = sorted((GraphEdge(id="E-" + digest(src, rel, dst, attrs_json)[:16], src=src,
                                  rel=rel, dst=dst, evidence_ids=view.ordered(ids),
                                  attrs=json.loads(attrs_json))
                        for (src, rel, dst, attrs_json), ids in edges.items()),
                       key=lambda g: g.id)
    return EntityGraph(nodes=nodes, edges=tuple(out_edges), truncated=truncated,
                       limits={"max_nodes": max_nodes, "max_edges": max_edges})


def find_path(graph: EntityGraph, src: str, dst: str, *,
              max_hops: int = 4) -> list[GraphEdge] | None:
    """Shortest path (edges treated as undirected), deterministic tie-breaks."""
    adj: dict[str, list[tuple[str, GraphEdge]]] = defaultdict(list)
    for edge in graph.edges:
        adj[edge.src].append((edge.dst, edge))
        adj[edge.dst].append((edge.src, edge))
    if src not in adj or dst not in adj:
        return None
    prev: dict[str, tuple[str, GraphEdge] | None] = {src: None}
    queue = deque([(src, 0)])
    while queue:
        node, depth = queue.popleft()
        if node == dst:
            path = []
            while prev[node] is not None:
                parent, edge = prev[node]
                path.append(edge)
                node = parent
            return path[::-1]
        if depth == max_hops:
            continue
        for nxt, edge in sorted(adj[node], key=lambda x: (x[1].id, x[0])):
            if nxt not in prev:
                prev[nxt] = (node, edge)
                queue.append((nxt, depth + 1))
    return None
