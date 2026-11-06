"""
backing_map.py -- Step 2: map reachable (type, class) pairs to their backing artifacts in
the unpacked image.

Data sources (all plain text, parsed with stdlib):
  file_contexts / *_file_contexts  : path-regex  -> label        (files, dirs, dev nodes, sockets)
  genfs_contexts                   : fs + prefix -> label        (proc/sysfs/... kernel-backed)
  service_contexts                 : binder name -> label        (binder services)
  property_contexts                : prop prefix -> label        (system properties)
  seapp_contexts                   : app seinfo  -> domain/type   (app sandboxes)
  init *.rc                        : service{}   -> exec path     (who hosts a service/socket)
  type_transition ...:process      : domain      -> exec type    (which binary runs in a domain)

For each reachable type we answer: what concrete thing(s) in the tree carry that label, and
(where determinable) which program owns/handles it.
"""
from __future__ import annotations

import collections
import dataclasses
import heapq
import os
import re
import stat
from typing import Iterable, Optional

# object-class -> which backing resolver applies
FILE_CLASSES = {
    "file", "dir", "lnk_file", "chr_file", "blk_file", "sock_file", "fifo_file", "filesystem",
}
# file_contexts type-specifier char -> stat predicate
_SPEC_PRED = {
    "--": stat.S_ISREG,
    "-d": stat.S_ISDIR,
    "-l": stat.S_ISLNK,
    "-c": stat.S_ISCHR,
    "-b": stat.S_ISBLK,
    "-s": stat.S_ISSOCK,
    "-p": stat.S_ISFIFO,
}


@dataclasses.dataclass
class FcEntry:
    pattern: str
    regex: "re.Pattern"
    spec: Optional[str]     # '--','-d','-c',... or None (any)
    setype: str
    stem: str = ""          # leading literal run (before first regex metachar); specificity


_META = set(".^$*+?{}[]()|\\")


def _stem(pattern: str) -> str:
    """Leading literal prefix of a file_contexts pattern, up to the first regex metachar.
    Used as the primary most-specific-match-wins key (libselabel sorts by stem length)."""
    out = []
    for ch in pattern:
        if ch in _META:
            break
        out.append(ch)
    return "".join(out)


def _stem_first_segment(stem: str) -> Optional[str]:
    """First path segment of a stem, but only when it is a *complete* literal segment -- i.e.
    the stem has another '/' after it, proving the segment ended literally (not mid-metachar).
    Returns None when that can't be guaranteed (empty/relative stem, or a stem like '/system'
    whose pattern might continue as '/system_ext...'), so such entries stay in the always-test
    set. A node under '/seg/...' can then skip every entry anchored to a different segment."""
    parts = stem.split("/")
    # "/a/b" -> ['', 'a', 'b'] ; "/a" -> ['', 'a'] ; "" -> [''] ; "/" -> ['', '']
    if len(parts) >= 3 and parts[1]:
        return parts[1]
    return None


def _label_type(context: str) -> Optional[str]:
    # user:role:type:level  -> type
    parts = context.split(":")
    return parts[2] if len(parts) >= 3 else None


def _fc_regex(pattern: str) -> "re.Pattern":
    # file_contexts uses PCRE-ish regex, full-path full-match. Python re covers the dialect
    # used in practice (., *, +, ?, [...], (...), |, escapes). Anchor both ends.
    try:
        return re.compile(pattern + r"\Z")
    except re.error:
        # Last resort: treat as literal.
        return re.compile(re.escape(pattern) + r"\Z")


class Contexts:
    """Parsed context files with reverse (type -> entries) indexes."""

    def __init__(self):
        self.fc: list[FcEntry] = []
        self.fc_by_type: dict[str, list[FcEntry]] = collections.defaultdict(list)
        self.genfs: list[tuple] = []                     # (fs, path, setype)
        self.genfs_by_type: dict[str, list[tuple]] = collections.defaultdict(list)
        self.services: dict[str, list[str]] = collections.defaultdict(list)   # setype -> [name]
        self.props: dict[str, list[str]] = collections.defaultdict(list)      # setype -> [prefix]
        self.seapp: list[dict] = []

    # ---- parsers ----------------------------------------------------------------------
    def load_file_contexts(self, path: str):
        with open(path, "r", errors="replace") as f:
            for line in f:
                line = line.strip()
                if not line or line.startswith("#"):
                    continue
                toks = line.split()
                if len(toks) < 2:
                    continue
                pat = toks[0]
                spec = None
                idx = 1
                if toks[1] in _SPEC_PRED or toks[1] == "--":
                    spec = toks[1]
                    idx = 2
                if idx >= len(toks):
                    continue
                context = toks[idx]
                st = _label_type(context)
                if not st:
                    continue
                e = FcEntry(pattern=pat, regex=_fc_regex(pat), spec=spec, setype=st,
                            stem=_stem(pat))
                self.fc.append(e)
                self.fc_by_type[st].append(e)

    def load_genfs_contexts(self, path: str):
        with open(path, "r", errors="replace") as f:
            for line in f:
                line = line.strip()
                if not line or line.startswith("#"):
                    continue
                toks = line.split()
                # genfscon <fs> <path> <context>   (older: without 'genfscon' keyword)
                if toks[0] == "genfscon":
                    toks = toks[1:]
                if len(toks) < 3:
                    continue
                fs, p, context = toks[0], toks[1], toks[2]
                st = _label_type(context)
                if not st:
                    continue
                self.genfs.append((fs, p, st))
                self.genfs_by_type[st].append((fs, p, st))

    def load_service_contexts(self, path: str):
        with open(path, "r", errors="replace") as f:
            for line in f:
                line = line.strip()
                if not line or line.startswith("#"):
                    continue
                toks = line.split()
                if len(toks) < 2:
                    continue
                name, context = toks[0], toks[1]
                st = _label_type(context)
                if st:
                    self.services[st].append(name)

    def load_property_contexts(self, path: str):
        with open(path, "r", errors="replace") as f:
            for line in f:
                line = line.strip()
                if not line or line.startswith("#"):
                    continue
                toks = line.split()
                if len(toks) < 2:
                    continue
                prefix, context = toks[0], toks[1]
                st = _label_type(context)
                if st:
                    self.props[st].append(prefix)

    def load_seapp_contexts(self, path: str):
        with open(path, "r", errors="replace") as f:
            for line in f:
                line = line.strip()
                if not line or line.startswith("#"):
                    continue
                kv = dict(tok.split("=", 1) for tok in line.split() if "=" in tok)
                if kv:
                    self.seapp.append(kv)


# ------------------------------------------------------------------------------------------
# Unpacked-tree filesystem index
# ------------------------------------------------------------------------------------------
# Default mapping of top-level subdir in the unpacked tree -> on-device absolute mountpoint.
# Android file_contexts paths are on-device absolute paths; the tree root rarely is "/".
DEFAULT_PARTITION_MAP = {
    "system": "/system",
    "system_ext": "/system_ext",
    "vendor": "/vendor",
    "product": "/product",
    "odm": "/odm",
    "oem": "/oem",
    "vendor_dlkm": "/vendor_dlkm",
    "system_dlkm": "/system_dlkm",
    "data": "/data",
}


@dataclasses.dataclass
class FsNode:
    device_path: str
    real_path: str
    mode: int


class Tree:
    """Walks the unpacked tree and yields on-device paths for regex matching."""

    def __init__(self, root: str, partition_map: Optional[dict] = None,
                 system_as_root: bool = False):
        self.root = os.path.abspath(root)
        self.partition_map = dict(partition_map or DEFAULT_PARTITION_MAP)
        self.system_as_root = system_as_root
        self.nodes: list[FsNode] = []

    def _device_path(self, real: str) -> Optional[str]:
        rel = os.path.relpath(real, self.root)
        if rel == ".":
            return "/"
        rel = "/" + rel.replace(os.sep, "/")
        top = rel.split("/", 2)[1] if "/" in rel[1:] else rel[1:]
        if top in self.partition_map:
            mp = self.partition_map[top]
            remainder = rel[len("/" + top):]
            return (mp + remainder) or "/"
        # system-as-root layout: the tree root *is* the system partition mounted at /
        if self.system_as_root:
            return rel
        # Unknown top-level dir: expose as-is (e.g. the root already looks on-device).
        return rel

    def walk(self):
        for dirpath, dirnames, filenames in os.walk(self.root, followlinks=False):
            entries = [dirpath] + [os.path.join(dirpath, n) for n in filenames]
            # include symlinked dirs as nodes too
            for n in dirnames:
                entries.append(os.path.join(dirpath, n))
            for real in entries:
                try:
                    stres = os.lstat(real)
                except OSError:
                    continue
                dp = self._device_path(real)
                if dp is None:
                    continue
                self.nodes.append(FsNode(device_path=dp, real_path=real, mode=stres.st_mode))
        # de-dup (dirpath appears once; dirnames add children we also re-see next iter)
        seen = set()
        uniq = []
        for n in self.nodes:
            if n.real_path in seen:
                continue
            seen.add(n.real_path)
            uniq.append(n)
        self.nodes = uniq
        return self


# ------------------------------------------------------------------------------------------
# Resolvers: reachable (type,class) -> backing artifacts
# ------------------------------------------------------------------------------------------
@dataclasses.dataclass
class Backing:
    setype: str
    tclass: str
    kind: str                    # 'file' | 'genfs' | 'service' | 'property' | 'unresolved'
    artifacts: list              # list of str (paths / names / fs:path)
    note: str = ""


def _spec_ok(spec: Optional[str], mode: int) -> bool:
    if spec is None:
        return True
    pred = _SPEC_PRED.get(spec)
    return pred(mode) if pred else True


class FileLabelIndex:
    """Assign each tree node its single file_contexts label, then bucket device paths by that
    label. Built in ONE pass over the tree (shared by every file-class resolution and by
    ownership.domain_entrypoints), replacing the old per-type re-walk of the whole tree.

    Precedence: libselabel is most-specific-match-wins. We approximate its ordering by a
    specificity key of (stem length, pattern length, has-file-type-spec); entries are sorted
    most-specific-first, and the first one that matches a node wins. This both fixes the old
    "any entry for this type matches" over-reporting (a path shadowed by a more specific line
    of a *different* type was wrongly attributed) and gives the early-exit that keeps the
    single pass cheap. It is an approximation, not exact PCRE2/libselabel specificity --
    see the `_fc_regex` note.
    """

    def __init__(self, ctx: "Contexts", tree: "Tree"):
        self.by_type: dict[str, list[str]] = collections.defaultdict(list)
        self.labeled_types = set(ctx.fc_by_type)
        # most-specific first; ties broken by later declaration (libselabel-ish)
        ordered = sorted(
            enumerate(ctx.fc),
            key=lambda ie: (len(ie[1].stem), len(ie[1].pattern), 1 if ie[1].spec else 0, ie[0]),
            reverse=True,
        )
        ordered = [e for _i, e in ordered]
        # Prune by first path segment: an entry whose stem is "/seg/..." (a *complete* literal
        # first segment) can only match paths under "/seg", so a node need only test that
        # segment's entries plus the "ambiguous" ones (empty/partial stem, e.g. catch-alls).
        # Work in `ordered` index space so every candidate list stays specificity-ordered.
        by_seg: dict[str, list] = collections.defaultdict(list)
        ambiguous: list = []
        for i, e in enumerate(ordered):
            seg = _stem_first_segment(e.stem)
            (by_seg[seg] if seg is not None else ambiguous).append(i)
        cand_cache: dict[str, list] = {}

        def candidates(seg: str) -> list:
            c = cand_cache.get(seg)
            if c is None:
                merged = heapq.merge(by_seg.get(seg, ()), ambiguous)  # both ascending index
                c = [ordered[i] for i in merged]
                cand_cache[seg] = c
            return c

        for n in tree.nodes:
            dp, mode = n.device_path, n.mode
            seg = dp.split("/", 2)[1] if len(dp) > 1 and "/" in dp[1:] else dp[1:]
            for e in candidates(seg):
                if e.spec is not None and not _spec_ok(e.spec, mode):
                    continue
                if e.regex.match(dp):
                    self.by_type[e.setype].append(dp)
                    break
        for k, v in list(self.by_type.items()):
            self.by_type[k] = sorted(set(v))

    def paths_for(self, setype: str, cap: Optional[int] = None) -> list:
        p = self.by_type.get(setype, [])
        return list(p[:cap]) if cap else list(p)


def resolve_files(index: FileLabelIndex, setype: str, tclass: str,
                 cap: int = 2000) -> Backing:
    if setype not in index.labeled_types:
        return Backing(setype, tclass, "unresolved", [],
                       note="no file_contexts entry labels this type")
    hits = index.paths_for(setype, cap)
    note = "" if hits else "labeled by file_contexts but no matching path found in tree"
    return Backing(setype, tclass, "file", hits, note=note)


def resolve_genfs(ctx: Contexts, setype: str, tclass: str) -> Backing:
    arts = ["%s:%s" % (fs, p) for (fs, p, st) in ctx.genfs_by_type.get(setype, [])]
    return Backing(setype, tclass, "genfs", arts,
                   note="kernel-backed (proc/sysfs/etc.); owner is a kernel driver/subsystem")


def resolve_service(ctx: Contexts, setype: str, tclass: str) -> Backing:
    names = ctx.services.get(setype, [])
    return Backing(setype, tclass, "service", list(names),
                   note="binder service name(s); cross-ref init .rc / VINTF for host binary")


def resolve_property(ctx: Contexts, setype: str, tclass: str) -> Backing:
    prefixes = ctx.props.get(setype, [])
    return Backing(setype, tclass, "property", list(prefixes),
                   note="system-property prefix(es)")
