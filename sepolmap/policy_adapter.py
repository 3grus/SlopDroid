"""
policy_adapter.py -- the ONLY module that touches setools.

Everything version-sensitive about the setools 4.x API lives here. If an upgrade breaks
something, this is the single file to fix. `analyze.py selftest` exercises each entry point
below against a real policy so you can confirm the binding before a large run.

Why the setools *library* and not sesearch/seinfo:
  - DomainTransitionAnalysis / InfoFlowAnalysis (the transitive graph engines) are API-only.
  - The policy is parsed once and queried in memory; sesearch reparses on every invocation.
  - Results are typed objects, not text to re-parse.
We still emit an equivalent `sesearch` string per finding (see sesearch_for_rule) so any edge
can be verified by hand with the CLI.
"""
from __future__ import annotations

import dataclasses
from typing import Iterable, Iterator, Optional

try:
    import setools
    from setools import (
        SELinuxPolicy,
        TERuleQuery,
        DomainTransitionAnalysis,
        InfoFlowAnalysis,
        PermissionMap,
    )
    _IMPORT_ERROR: Optional[Exception] = None
except Exception as e:  # pragma: no cover - environment dependent
    setools = None  # type: ignore
    _IMPORT_ERROR = e


def require_setools() -> None:
    if setools is None:
        raise RuntimeError(
            "The 'setools' package is not importable: %r\n"
            "Install it: `pip install setools` (needs libsepol/libselinux dev headers, or\n"
            "install the distro package, e.g. Debian/Ubuntu `apt install setools`,\n"
            "Fedora `dnf install setools`). sesearch/seinfo are the CLI front-ends to the\n"
            "same library." % (_IMPORT_ERROR,)
        )


# --------------------------------------------------------------------------------------
# Lightweight, setools-independent value objects. The rest of the codebase only ever sees
# these, never raw setools objects -- that keeps version drift contained to this module.
# --------------------------------------------------------------------------------------
@dataclasses.dataclass(frozen=True)
class AllowRule:
    source: str
    target: str
    tclass: str
    perms: frozenset
    cond: Optional[str] = None          # conditional/boolean expression, if any
    xperm: Optional[str] = None         # ioctl xperm range text, if an allowxperm

    def sesearch(self) -> str:
        return sesearch_for_rule(self)


@dataclasses.dataclass(frozen=True)
class DomainEdge:
    source: str
    target: str                         # target DOMAIN reached by a process transition
    entrypoints: tuple                  # tuple[(exec_type, (perm_rules...))]


class Policy:
    """Thin wrapper around a loaded setools SELinuxPolicy."""

    def __init__(self, path: str):
        require_setools()
        self.path = path
        self._p = SELinuxPolicy(path)
        self._permmap = None

    # -- introspection --------------------------------------------------------
    @property
    def version(self) -> str:
        return "setools %s / policy %s" % (
            getattr(setools, "__version__", "?"),
            getattr(self._p, "version", "?"),
        )

    def types(self) -> list:
        return sorted(str(t) for t in self._p.types())

    def classes(self) -> list:
        return sorted(str(c) for c in self._p.classes())

    def is_type(self, name: str) -> bool:
        try:
            self._p.lookup_type(name)
            return True
        except Exception:
            return False

    # -- step 1a: direct allow/allowxperm rules sourced at `domain` -----------
    def allow_rules_from(self, domain: str) -> Iterator[AllowRule]:
        """
        All allow + allowxperm rules whose (expanded) source is `domain`.
        source_indirect=True makes a concrete type also match rules written against the
        attributes it holds -- essential for an exhaustive result on Android policy, which
        is written almost entirely against attributes.
        """
        for ruletype in ("allow", "allowxperm"):
            try:
                q = TERuleQuery(
                    self._p,
                    source=domain,
                    source_indirect=True,
                    ruletype=[ruletype],
                )
            except TypeError:
                # Older/newer signature: fall back to minimal args + manual filter.
                q = TERuleQuery(self._p)
                q.source = domain
                q.source_indirect = True
                q.ruletype = [ruletype]
            for r in q.results():
                yield _to_allow(r)

    # -- step 1b: process-transition graph edges out of `domain` --------------
    def transitions_from(self, domain: str) -> Iterator[DomainEdge]:
        # setools < 4.6 has transitions(); later versions replaced it with results() + a mode.
        if hasattr(DomainTransitionAnalysis, "transitions"):
            steps = DomainTransitionAnalysis(self._p, reverse=False).transitions(domain)
        else:
            steps = DomainTransitionAnalysis(
                self._p, source=domain, depth_limit=1,
                mode=DomainTransitionAnalysis.Mode.TransitionsOut).results()
        for step in steps:
            eps = []
            for ep in getattr(step, "entrypoints", []) or []:
                eps.append((str(ep.name), tuple(str(x) for x in getattr(ep, "entrypoint", []))))
            yield DomainEdge(source=str(step.source), target=str(step.target),
                             entrypoints=tuple(eps))

    # -- step 1c: transitive information-flow closure out of `source` ---------
    def infoflow_targets(self, source: str, min_weight: int = 1,
                         exclude: Optional[Iterable[str]] = None) -> Iterator[tuple]:
        """
        Yields (target_type, [rule_texts]) for every type reachable by OUTBOUND information
        flow from `source`, transitively. Uses the bundled permission map (read/write
        weighting). This is the noisy, maximal "IPC closure" layer; callers tag provenance
        so it can be filtered. min_weight raises the bar (1 = include low-bandwidth flows).
        """
        if self._permmap is None:
            self._permmap = PermissionMap()
        # setools < 4.6 has infoflows(); later versions replaced it with results() + a mode.
        legacy = hasattr(InfoFlowAnalysis, "infoflows")
        kwargs = {} if legacy else {"source": source, "depth_limit": 1,
                                    "mode": InfoFlowAnalysis.Mode.FlowsOut}
        ifa = InfoFlowAnalysis(self._p, self._permmap, min_weight=min_weight, **kwargs)
        if exclude:
            try:
                ifa.exclude = list(exclude)
            except Exception:
                pass
        # infoflows() performs a transitive BFS and yields steps; the union of targets is
        # the outbound closure. API has varied: handle both "yields steps" and "yields paths".
        for item in (ifa.infoflows(source, out=True) if legacy else ifa.results()):
            tgt = getattr(item, "target", None)
            if tgt is not None:
                rules = [str(r) for r in getattr(item, "rules", [])]
                yield (str(tgt), rules)
            else:  # a path-like object: walk its steps
                for st in item:
                    t = getattr(st, "target", None)
                    if t is not None:
                        yield (str(t), [str(r) for r in getattr(st, "rules", [])])

    # -- domain -> entrypoint exec type(s), from type_transition ... :process --
    def process_type_transitions(self) -> Iterator[tuple]:
        """Yields (source_domain, exec_type, new_domain) for every process type_transition."""
        try:
            q = TERuleQuery(self._p, ruletype=["type_transition"], tclass=["process"])
        except TypeError:
            q = TERuleQuery(self._p)
            q.ruletype = ["type_transition"]
            q.tclass = ["process"]
        for r in q.results():
            # type_transition src exectype:process newdomain
            yield (str(r.source), str(r.target), str(r.default))


def _to_allow(r) -> AllowRule:
    perms = frozenset(str(p) for p in getattr(r, "perms", []) or [])
    cond = None
    try:
        if getattr(r, "conditional", None) is not None:
            cond = str(r.conditional)
    except Exception:
        pass
    xperm = None
    try:
        if getattr(r, "xperm_type", None):
            xperm = "%s %s" % (r.xperm_type, getattr(r, "perms", ""))
    except Exception:
        pass
    return AllowRule(
        source=str(r.source),
        target=str(r.target),
        tclass=str(r.tclass),
        perms=perms,
        cond=cond,
        xperm=xperm,
    )


def sesearch_for_rule(r: AllowRule) -> str:
    """Reconstruct a sesearch invocation that isolates this rule, for manual verification."""
    flag = "-AX" if r.xperm else "-A"
    return "sesearch %s -s %s -t %s -c %s <sepolicy>" % (flag, r.source, r.target, r.tclass)
