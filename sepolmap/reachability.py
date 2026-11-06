"""
reachability.py -- Step 1: the exhaustive reachable-type set from a source process domain.

The result is intentionally LAYERED, with per-type provenance, so you can dial noise:

  L0 direct      : targets of allow/allowxperm rules sourced directly at the domain(s)
  L1 transitions : domains reachable via process:transition (entrypoint exec + type_transition),
                   unioned with each reached domain's L0 direct targets
  L2 infoflow    : transitive outbound information-flow closure (shared fd/socket/pipe/binder/
                   files written-then-read, etc.) -- the maximal, noisiest "IPC closure"

Output is organized BY OBJECT CLASS, which is what Step 2 needs for backing-file resolution.
"""
from __future__ import annotations

import collections
import dataclasses
from typing import Optional

from .policy_adapter import Policy, AllowRule


LAYER_DIRECT = "direct"
LAYER_TRANSITION = "transition"
LAYER_INFOFLOW = "infoflow"


@dataclasses.dataclass
class TypeAccess:
    """One reachable (target type, object class) with how/why it was reached."""
    type: str
    tclass: str
    perms: set = dataclasses.field(default_factory=set)
    layers: set = dataclasses.field(default_factory=set)   # which L0/L1/L2 produced it
    via_domains: set = dataclasses.field(default_factory=set)  # intermediary domains for L1/L2
    sample_sesearch: Optional[str] = None

    def merge_rule(self, r: AllowRule, layer: str, via: Optional[str]):
        self.perms |= set(r.perms)
        self.layers.add(layer)
        if via:
            self.via_domains.add(via)
        if self.sample_sesearch is None:
            self.sample_sesearch = r.sesearch()


@dataclasses.dataclass
class ReachResult:
    source_domain: str
    reached_domains: set                       # domains folded in via L1 transitions
    # (tclass, type) -> TypeAccess
    access: dict = dataclasses.field(default_factory=dict)
    transition_edges: list = dataclasses.field(default_factory=list)

    def _key(self, tclass, typ):
        return (tclass, typ)

    def add(self, r: AllowRule, layer: str, via: Optional[str] = None):
        k = self._key(r.tclass, r.target)
        ta = self.access.get(k)
        if ta is None:
            ta = TypeAccess(type=r.target, tclass=r.tclass)
            self.access[k] = ta
        ta.merge_rule(r, layer, via)

    def add_infoflow(self, target: str, tclass: str, layer: str, via: Optional[str]):
        k = self._key(tclass, target)
        ta = self.access.get(k)
        if ta is None:
            ta = TypeAccess(type=target, tclass=tclass)
            self.access[k] = ta
        ta.layers.add(layer)
        if via:
            ta.via_domains.add(via)

    def by_class(self) -> dict:
        out = collections.defaultdict(list)
        for (tclass, _typ), ta in self.access.items():
            out[tclass].append(ta)
        for v in out.values():
            v.sort(key=lambda t: t.type)
        return dict(sorted(out.items()))

    def type_set(self) -> set:
        return {ta.type for ta in self.access.values()}


def compute_reach(policy: Policy, source_domain: str,
                 layers=(LAYER_DIRECT, LAYER_TRANSITION, LAYER_INFOFLOW),
                 infoflow_min_weight: int = 1,
                 infoflow_exclude=None) -> ReachResult:
    if not policy.is_type(source_domain):
        raise ValueError("%r is not a type in this policy. Check the domain name "
                         "(e.g. untrusted_app, isolated_app, hal_camera_default)."
                         % source_domain)

    res = ReachResult(source_domain=source_domain, reached_domains=set())

    # ---- L0: direct access from the source domain -------------------------------------
    if LAYER_DIRECT in layers:
        for r in policy.allow_rules_from(source_domain):
            res.add(r, LAYER_DIRECT)

    # ---- L1: fold in domains reachable by process transition ---------------------------
    if LAYER_TRANSITION in layers:
        frontier = [source_domain]
        seen = {source_domain}
        while frontier:
            cur = frontier.pop()
            for edge in policy.transitions_from(cur):
                res.transition_edges.append(edge)
                if edge.target not in seen:
                    seen.add(edge.target)
                    res.reached_domains.add(edge.target)
                    frontier.append(edge.target)
        # union each reached domain's direct targets, tagged with the via-domain
        for d in res.reached_domains:
            for r in policy.allow_rules_from(d):
                res.add(r, LAYER_TRANSITION, via=d)

    # ---- L2: transitive outbound information-flow closure ------------------------------
    if LAYER_INFOFLOW in layers:
        # We don't get a clean object-class per infoflow target from the flow graph, so we
        # recover classes by intersecting with the target type's actual allow rules reachable
        # from the (expanded) domain set. Practically: for each infoflow target type, we mark
        # it reachable; Step 2 resolves classes from the context files. We still try to attach
        # classes we already know about from L0/L1.
        known_classes = collections.defaultdict(set)
        for (tclass, typ) in res.access.keys():
            known_classes[typ].add(tclass)
        for target_type, _rules in policy.infoflow_targets(
                source_domain, min_weight=infoflow_min_weight, exclude=infoflow_exclude):
            classes = known_classes.get(target_type) or {"<infoflow>"}
            for c in classes:
                res.add_infoflow(target_type, c, LAYER_INFOFLOW, via=source_domain)

    return res
