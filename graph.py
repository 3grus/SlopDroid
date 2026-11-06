#!/usr/bin/env python3
"""
graph.py -- visualize the process-transition graph from an analyze.py JSON report.

Scope: DOMAINS ONLY. Nodes are the source domain plus every domain reachable via
process transition (the `reached_domains` set), each annotated with its resolved
entrypoint binary. Each reached domain is itself a re-auditable source -- re-run
`analyze.py reach -s <that domain>` to expand the next ring.

Usage:
  python3 graph.py <out.json> [--format dot|html|both] [-o PREFIX]

Outputs (default PREFIX = input filename without .json):
  PREFIX.dot    Graphviz DOT; render with:  dot -Tsvg PREFIX.dot -o PREFIX.svg
  PREFIX.html   self-contained interactive graph (no external deps; opens offline)

Note on topology: the JSON report folds the reachable-domain set, so the exact
A->B->C transition chain is not fully reconstructable from it; edges are drawn
from the source to each reached domain ("can cause to run"). Intermediate hops
recorded in a finding's `via_domains` are shown on hover in the HTML view.
"""
from __future__ import annotations

import argparse
import html
import json
import os
import sys


def load_report(path: str) -> dict:
    with open(path) as f:
        return json.load(f)


def collect(report: dict) -> tuple:
    """Return (source, nodes) where nodes maps domain -> {binaries, via}."""
    source = report.get("source_domain", "<unknown>")
    reached = report.get("reached_domains", []) or []
    bins = report.get("reached_domain_binaries", {}) or {}

    # Harvest any intermediate via_domains mentioned in findings, for hover context.
    via_for: dict = {d: set() for d in reached}
    for items in (report.get("by_class", {}) or {}).values():
        for it in items:
            for v in it.get("via_domains", []) or []:
                if v in via_for and v != source:
                    via_for[v].add(it.get("type", ""))

    nodes = {}
    for d in reached:
        if d == source:          # a domain reaching itself is not a pivot edge
            continue
        nodes[d] = {
            "binaries": bins.get(d) or [],
            "via_types": sorted(x for x in via_for.get(d, set()) if x),
        }
    return source, nodes


# ---- DOT ---------------------------------------------------------------------------------
def emit_dot(source: str, nodes: dict) -> str:
    def q(s: str) -> str:
        return '"' + s.replace('"', '\\"') + '"'

    lines = [
        "digraph reach {",
        "  rankdir=LR;",
        "  node [shape=box, style=\"rounded,filled\", fontname=\"monospace\", fontsize=10];",
        "  edge [color=\"#888888\", arrowsize=0.7];",
        "",
        "  %s [fillcolor=\"#ffd7b5\", penwidth=2, label=%s];"
        % (q(source), q(source + "\\n(source)")),
        "",
    ]
    for d, meta in sorted(nodes.items()):
        binline = meta["binaries"][0] if meta["binaries"] else "<entrypoint not resolved>"
        label = d + "\\n" + binline
        fill = "#dbeafe" if meta["binaries"] else "#eeeeee"
        lines.append("  %s [fillcolor=%s, label=%s];" % (q(d), q(fill), q(label)))
    lines.append("")
    for d in sorted(nodes):
        lines.append("  %s -> %s;" % (q(source), q(d)))
    lines.append("}")
    return "\n".join(lines) + "\n"


# ---- HTML (self-contained, dependency-free force layout) ---------------------------------
HTML_TEMPLATE = r"""<!doctype html>
<html lang="en">
<head>
<meta charset="utf-8">
<meta name="viewport" content="width=device-width, initial-scale=1">
<title>__TITLE__</title>
<style>
  :root {
    --bg: #f7f7f8; --fg: #1a1a1a; --panel: #ffffff; --line: #d0d0d5;
    --source: #f59e0b; --domain: #3b82f6; --domain-dim: #9ca3af; --edge: #b8b8c0;
  }
  :root:not([data-theme="light"]) { }
  @media (prefers-color-scheme: dark) {
    :root:not([data-theme="light"]) {
      --bg: #16161a; --fg: #ececf0; --panel: #22222a; --line: #3a3a44;
      --source: #fbbf24; --domain: #60a5fa; --domain-dim: #6b7280; --edge: #4a4a56;
    }
  }
  :root[data-theme="dark"] {
    --bg: #16161a; --fg: #ececf0; --panel: #22222a; --line: #3a3a44;
    --source: #fbbf24; --domain: #60a5fa; --domain-dim: #6b7280; --edge: #4a4a56;
  }
  * { box-sizing: border-box; }
  html, body { margin: 0; height: 100%; background: var(--bg); color: var(--fg);
    font-family: -apple-system, system-ui, sans-serif; }
  #wrap { display: flex; flex-direction: column; height: 100vh; }
  header { padding: 10px 16px; border-bottom: 1px solid var(--line); }
  header h1 { margin: 0; font-size: 15px; font-weight: 600; }
  header .sub { font-size: 12px; color: var(--domain-dim); margin-top: 2px;
    font-family: monospace; }
  #stage { flex: 1; position: relative; overflow: hidden; touch-action: none; }
  svg { width: 100%; height: 100%; display: block; cursor: grab; }
  svg.dragging { cursor: grabbing; }
  .edge { stroke: var(--edge); stroke-width: 1.2; }
  .node circle { stroke: var(--panel); stroke-width: 2; cursor: pointer; }
  .node.source circle { fill: var(--source); }
  .node.domain circle { fill: var(--domain); }
  .node.dim circle { fill: var(--domain-dim); }
  .node text { font-family: monospace; font-size: 11px; fill: var(--fg);
    pointer-events: none; user-select: none; }
  #panel { position: absolute; top: 10px; right: 10px; width: min(340px, 72vw);
    background: var(--panel); border: 1px solid var(--line); border-radius: 8px;
    padding: 12px 14px; font-size: 12px; box-shadow: 0 4px 16px rgba(0,0,0,.18);
    display: none; }
  #panel.show { display: block; }
  #panel h2 { margin: 0 0 6px; font-size: 13px; font-family: monospace;
    word-break: break-all; }
  #panel .k { color: var(--domain-dim); margin-top: 8px; font-size: 11px;
    text-transform: uppercase; letter-spacing: .04em; }
  #panel code { display: block; background: var(--bg); border: 1px solid var(--line);
    border-radius: 5px; padding: 6px 8px; margin-top: 4px; font-size: 11px;
    word-break: break-all; white-space: pre-wrap; }
  #panel .close { float: right; cursor: pointer; color: var(--domain-dim);
    font-size: 16px; line-height: 1; }
  #panel ul { margin: 4px 0 0; padding-left: 16px; }
  #hint { position: absolute; left: 10px; bottom: 10px; font-size: 11px;
    color: var(--domain-dim); background: var(--panel); border: 1px solid var(--line);
    border-radius: 6px; padding: 5px 9px; }
</style>
</head>
<body>
<div id="wrap">
  <header>
    <h1>Process-transition graph — source: <span style="font-family:monospace">__SOURCE__</span></h1>
    <div class="sub">__COUNT__ reachable domains · drag to pan · scroll to zoom · click a node to drill</div>
  </header>
  <div id="stage">
    <svg id="svg"><g id="view"></g></svg>
    <div id="panel">
      <span class="close" onclick="hidePanel()">×</span>
      <h2 id="p-name"></h2>
      <div id="p-body"></div>
    </div>
    <div id="hint">Each reached domain is a new source — drill, then re-run analyze.py against it.</div>
  </div>
</div>
<script id="data" type="application/json">__DATA__</script>
<script>
"use strict";
var DATA = JSON.parse(document.getElementById("data").textContent);
var SRC = DATA.source;
var svg = document.getElementById("svg");
var view = document.getElementById("view");
var W = svg.clientWidth || 800, H = svg.clientHeight || 600;

// Build node + edge model.
var nodes = [{ id: SRC, kind: "source", binaries: [], via_types: [] }];
var byId = { };
byId[SRC] = nodes[0];
Object.keys(DATA.nodes).sort().forEach(function (d) {
  var m = DATA.nodes[d];
  var n = { id: d, kind: m.binaries.length ? "domain" : "dim",
            binaries: m.binaries, via_types: m.via_types || [] };
  nodes.push(n); byId[d] = n;
});
var edges = nodes.filter(function (n) { return n.id !== SRC; })
                 .map(function (n) { return { s: byId[SRC], t: n }; });

// Initial layout: source center, others on a ring.
nodes.forEach(function (n, i) {
  if (n.id === SRC) { n.x = W / 2; n.y = H / 2; }
  else {
    var k = i - 1, total = nodes.length - 1;
    var ang = (k / Math.max(1, total)) * Math.PI * 2;
    var r = Math.min(W, H) * 0.34;
    n.x = W / 2 + Math.cos(ang) * r;
    n.y = H / 2 + Math.sin(ang) * r;
  }
  n.vx = 0; n.vy = 0;
});

// Simple force simulation.
function tick() {
  var i, j, a, b, dx, dy, d2, d, f;
  for (i = 0; i < nodes.length; i++) {
    a = nodes[i];
    for (j = i + 1; j < nodes.length; j++) {
      b = nodes[j];
      dx = a.x - b.x; dy = a.y - b.y; d2 = dx*dx + dy*dy || 0.01;
      d = Math.sqrt(d2); f = 9000 / d2;
      var ux = dx/d, uy = dy/d;
      a.vx += ux*f; a.vy += uy*f; b.vx -= ux*f; b.vy -= uy*f;
    }
  }
  edges.forEach(function (e) {
    dx = e.t.x - e.s.x; dy = e.t.y - e.s.y; d = Math.sqrt(dx*dx+dy*dy) || 0.01;
    f = (d - 170) * 0.02; var ux = dx/d, uy = dy/d;
    e.s.vx += ux*f; e.s.vy += uy*f; e.t.vx -= ux*f; e.t.vy -= uy*f;
  });
  nodes.forEach(function (n) {
    if (n.fixed) { n.vx = 0; n.vy = 0; return; }
    n.vx += (W/2 - n.x) * 0.0012; n.vy += (H/2 - n.y) * 0.0012;
    n.vx *= 0.82; n.vy *= 0.82;
    n.x += n.vx; n.y += n.vy;
  });
}

var gEdges = document.createElementNS("http://www.w3.org/2000/svg", "g");
var gNodes = document.createElementNS("http://www.w3.org/2000/svg", "g");
view.appendChild(gEdges); view.appendChild(gNodes);
var edgeEls = edges.map(function (e) {
  var l = document.createElementNS("http://www.w3.org/2000/svg", "line");
  l.setAttribute("class", "edge"); gEdges.appendChild(l); return l;
});
var nodeEls = nodes.map(function (n) {
  var g = document.createElementNS("http://www.w3.org/2000/svg", "g");
  g.setAttribute("class", "node " + n.kind);
  var c = document.createElementNS("http://www.w3.org/2000/svg", "circle");
  c.setAttribute("r", n.id === SRC ? 10 : 7);
  var t = document.createElementNS("http://www.w3.org/2000/svg", "text");
  t.setAttribute("x", 11); t.setAttribute("y", 4); t.textContent = n.id;
  g.appendChild(c); g.appendChild(t); gNodes.appendChild(g);
  g.addEventListener("mousedown", function (ev) { startDragNode(ev, n); });
  g.addEventListener("click", function (ev) { ev.stopPropagation(); showPanel(n); });
  return g;
});

function render() {
  edges.forEach(function (e, i) {
    edgeEls[i].setAttribute("x1", e.s.x); edgeEls[i].setAttribute("y1", e.s.y);
    edgeEls[i].setAttribute("x2", e.t.x); edgeEls[i].setAttribute("y2", e.t.y);
  });
  nodes.forEach(function (n, i) {
    nodeEls[i].setAttribute("transform", "translate(" + n.x + "," + n.y + ")");
  });
}
var frames = 0;
function loop() { if (frames++ < 600) { tick(); render(); requestAnimationFrame(loop); } }
loop();

// Pan + zoom.
var tx = 0, ty = 0, scale = 1;
function applyView() { view.setAttribute("transform", "translate("+tx+","+ty+") scale("+scale+")"); }
svg.addEventListener("wheel", function (e) {
  e.preventDefault();
  var r = svg.getBoundingClientRect(), mx = e.clientX - r.left, my = e.clientY - r.top;
  var ns = Math.min(4, Math.max(0.2, scale * (e.deltaY < 0 ? 1.1 : 0.9)));
  tx = mx - (mx - tx) * (ns/scale); ty = my - (my - ty) * (ns/scale); scale = ns;
  applyView();
}, { passive: false });

var dragNode = null, panning = false, px, py;
function startDragNode(e, n) { e.stopPropagation(); dragNode = n; n.fixed = true;
  frames = Math.min(frames, 400); loop(); }
svg.addEventListener("mousedown", function (e) { panning = true; px = e.clientX; py = e.clientY;
  svg.classList.add("dragging"); });
window.addEventListener("mousemove", function (e) {
  var r = svg.getBoundingClientRect();
  if (dragNode) {
    dragNode.x = (e.clientX - r.left - tx) / scale;
    dragNode.y = (e.clientY - r.top - ty) / scale; render();
  } else if (panning) {
    tx += e.clientX - px; ty += e.clientY - py; px = e.clientX; py = e.clientY; applyView();
  }
});
window.addEventListener("mouseup", function () {
  if (dragNode) dragNode.fixed = false;
  dragNode = null; panning = false; svg.classList.remove("dragging");
});

// Detail panel.
var panel = document.getElementById("panel");
function esc(s) { var d = document.createElement("div"); d.textContent = s; return d.innerHTML; }
function showPanel(n) {
  document.getElementById("p-name").textContent = n.id;
  var h = "";
  if (n.id === SRC) {
    h += '<div class="k">source domain</div>';
    h += '<div>Starting point of this report.</div>';
  } else {
    h += '<div class="k">entrypoint binary</div>';
    h += n.binaries.length
      ? "<ul>" + n.binaries.map(function (b) { return "<li>" + esc(b) + "</li>"; }).join("") + "</ul>"
      : "<div>&lt;not resolved&gt;</div>";
    if (n.via_types.length) {
      h += '<div class="k">sample types reached via this domain</div>';
      h += "<ul>" + n.via_types.slice(0, 12).map(function (t) { return "<li>" + esc(t) + "</li>"; }).join("")
         + (n.via_types.length > 12 ? "<li>…</li>" : "") + "</ul>";
    }
    h += '<div class="k">drill into this domain</div>';
    h += "<code>python3 analyze.py reach -r &lt;root&gt; -s " + esc(n.id) + " --json " + esc(n.id) + ".json</code>";
  }
  document.getElementById("p-body").innerHTML = h;
  panel.classList.add("show");
}
function hidePanel() { panel.classList.remove("show"); }
svg.addEventListener("click", hidePanel);
window.addEventListener("resize", function () {
  W = svg.clientWidth; H = svg.clientHeight;
});
</script>
</body>
</html>
"""


def emit_html(source: str, nodes: dict) -> str:
    data = {"source": source, "nodes": nodes}
    payload = json.dumps(data).replace("</", "<\\/")
    return (HTML_TEMPLATE
            .replace("__TITLE__", html.escape("reach: " + source))
            .replace("__SOURCE__", html.escape(source))
            .replace("__COUNT__", str(len(nodes)))
            .replace("__DATA__", payload))


def main():
    ap = argparse.ArgumentParser(
        description=__doc__, formatter_class=argparse.RawDescriptionHelpFormatter)
    ap.add_argument("json", help="JSON report from `analyze.py reach --json`")
    ap.add_argument("--format", choices=["dot", "html", "both"], default="both")
    ap.add_argument("-o", "--out", help="output prefix (default: input name without .json)")
    args = ap.parse_args()

    report = load_report(args.json)
    source, nodes = collect(report)
    if not nodes:
        print("warn: report lists no reached_domains; nothing to graph "
              "(did you run with the 'transition' layer?)", file=sys.stderr)

    prefix = args.out or (args.json[:-5] if args.json.endswith(".json") else args.json)

    if args.format in ("dot", "both"):
        p = prefix + ".dot"
        with open(p, "w") as f:
            f.write(emit_dot(source, nodes))
        print("[*] wrote", p, "  ->  render:  dot -Tsvg %s -o %s.svg" % (p, prefix))
    if args.format in ("html", "both"):
        p = prefix + ".html"
        with open(p, "w") as f:
            f.write(emit_html(source, nodes))
        print("[*] wrote", p, "  (open in a browser; works offline)")


if __name__ == "__main__":
    main()
