"""Locate APKs in an unpacked firmware tree, or anywhere under a directory (recursive).

Neither Stage-2 taint engine needs a directory hierarchy -- each APK is analyzed on its own --
so recursive discovery of loose APKs is safe; we only record where each APK came from so the
report can tell a priv-app from a third-party app.
"""
from __future__ import annotations

import dataclasses
import os
from typing import List, Optional

# Image subdirs that hold installed APKs, and whether that location is "privileged".
_APP_DIRS = [
    ("system/app", False), ("system/priv-app", True),
    ("system_ext/app", False), ("system_ext/priv-app", True),
    ("product/app", False), ("product/priv-app", True),
    ("vendor/app", False), ("vendor/priv-app", True),
    ("odm/app", False), ("odm/priv-app", True),
    ("system/product/app", False), ("system/product/priv-app", True),
]
# Partition roots that mark an APK as part of the platform image (not third-party /data).
_SYSTEM_ROOTS = ("system", "system_ext", "product", "vendor", "odm", "oem")


@dataclasses.dataclass
class ApkRef:
    path: str
    is_priv: bool
    is_system: bool
    origin: str          # which partition/dir it came from, for the report


def _is_priv(rel: str) -> bool:
    parts = rel.replace("\\", "/").split("/")
    return "priv-app" in parts


def _is_system(rel: str) -> bool:
    head = rel.replace("\\", "/").split("/", 1)[0]
    return head in _SYSTEM_ROOTS


def from_tree(root: str) -> List[ApkRef]:
    """APKs under the known app dirs of an unpacked image."""
    out: List[ApkRef] = []
    seen = set()
    for sub, priv in _APP_DIRS:
        base = os.path.join(root, sub)
        if not os.path.isdir(base):
            continue
        for dirpath, _d, files in os.walk(base):
            for fn in files:
                if fn.lower().endswith(".apk"):
                    full = os.path.realpath(os.path.join(dirpath, fn))
                    if full in seen:
                        continue
                    seen.add(full)
                    rel = os.path.relpath(full, root)
                    out.append(ApkRef(full, priv or _is_priv(rel), _is_system(rel), sub))
    return out


def from_dir(root: str, apk_dir: str) -> List[ApkRef]:
    """Every *.apk under apk_dir (recursive). is_priv/is_system inferred from the path when
    apk_dir sits inside the unpacked tree; otherwise flagged unknown (treated non-priv)."""
    out: List[ApkRef] = []
    seen = set()
    for dirpath, _d, files in os.walk(apk_dir):
        for fn in files:
            if not fn.lower().endswith(".apk"):
                continue
            full = os.path.realpath(os.path.join(dirpath, fn))
            if full in seen:
                continue
            seen.add(full)
            try:
                rel = os.path.relpath(full, root)
                inside = not rel.startswith("..")
            except ValueError:
                inside = False
            if inside:
                out.append(ApkRef(full, _is_priv(rel), _is_system(rel),
                                  os.path.dirname(rel)))
            else:
                out.append(ApkRef(full, False, False, "apk-dir"))
    return out


def discover(root: str, apk_dir: Optional[str]) -> List[ApkRef]:
    refs = from_dir(root, apk_dir) if apk_dir else from_tree(root)
    return sorted(refs, key=lambda r: r.path)
