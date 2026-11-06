"""
ownership.py -- "who runs/handles this?" helpers.

Two mappings that turn labels into programs:
  1. domain -> entrypoint binary : from `type_transition D exectype:process ND` crossed with
     file_contexts(exectype).  Tells you the binary that executes in a given process domain.
  2. init service{} -> exec path : parses init *.rc so a binder service / named socket can be
     traced to the daemon that `service`-defines and launches it.
"""
from __future__ import annotations

import collections
import os
import re
from typing import Optional

from .backing_map import Contexts, Tree, FileLabelIndex
from .policy_adapter import Policy


def domain_entrypoints(policy: Policy, ctx: Contexts, tree: Tree,
                       index: Optional[FileLabelIndex] = None) -> dict:
    """
    domain -> sorted list of on-device binary paths that transition INTO it.
    (i.e. the executables that run as that domain)

    Uses the shared FileLabelIndex (one tree pass) so a binary resolves to the paths carrying
    its *actual* most-specific label -- same result as before in the common case, more correct
    when a generic rule would otherwise also match. Pass a prebuilt index to avoid rebuilding.
    """
    index = index or FileLabelIndex(ctx, tree)

    # exec_type -> set(domains that this exec type transitions into)
    exectype_to_domains = collections.defaultdict(set)
    for src, exectype, newdom in policy.process_type_transitions():
        exectype_to_domains[exectype].add(newdom)

    out = collections.defaultdict(set)
    for exectype, domains in exectype_to_domains.items():
        paths = index.paths_for(exectype)
        if not paths:
            continue
        for d in domains:
            out[d].update(paths)
    return {d: sorted(p) for d, p in out.items()}


_SERVICE_RE = re.compile(r"^\s*service\s+(\S+)\s+(\S+)")


def init_services(tree: Tree) -> dict:
    """
    service-name -> exec path, parsed from every init *.rc found in the tree.
    Also captures `socket <name>` lines so a named socket can be traced to its service.
    Returns {'services': {name: exec}, 'sockets': {sockname: service_name}}.
    """
    services: dict[str, str] = {}
    sockets: dict[str, str] = {}
    for n in tree.nodes:
        if not n.real_path.endswith(".rc"):
            continue
        try:
            with open(n.real_path, "r", errors="replace") as f:
                lines = f.readlines()
        except OSError:
            continue
        cur = None
        for line in lines:
            m = _SERVICE_RE.match(line)
            if m:
                cur = m.group(1)
                services[cur] = m.group(2)
                continue
            s = re.match(r"^\s*socket\s+(\S+)", line)
            if s and cur:
                sockets[s.group(1)] = cur
            if line.strip() and not line.startswith((" ", "\t")) and not line.lstrip().startswith("service"):
                cur = None
    return {"services": services, "sockets": sockets}
