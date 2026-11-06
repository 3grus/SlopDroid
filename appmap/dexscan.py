"""androguard glue: fast manifest read, signature->seinfo resolution, and (optional, slow)
DEX string cross-referencing for the file channel.

Kept deliberately thin -- all component/exported logic lives in manifest.py (pure, tested).
The two expensive operations (full DEX Analysis, cert parsing) are opt-in per call so the
cheap manifest pass can run over a whole image quickly.
"""
from __future__ import annotations

import dataclasses
from typing import Dict, List, Optional, Set

from androguard.core.apk import APK

from .manifest import extract_components, Component


@dataclasses.dataclass
class ApkInfo:
    package: str
    target_sdk: int
    min_sdk: int
    components: List[Component]
    der_hexes: List[str]            # signing certs, hex(DER) upper -- for mac_permissions match


def _target_sdk(apk: APK) -> int:
    for getter in (apk.get_effective_target_sdk_version, apk.get_target_sdk_version):
        try:
            v = getter()
            if v:
                return int(v)
        except Exception:
            pass
    return 10000  # unknown -> treat as newest (most conservative for implicit-export)


def _cert_hexes(apk: APK) -> List[str]:
    out: List[str] = []
    for getter in ("get_certificates_der_v2", "get_certificates_der_v3",
                   "get_certificates_der_v31"):
        try:
            for der in getattr(apk, getter)() or []:
                if der:
                    out.append(der.hex().upper())
        except Exception:
            pass
    # v1 (JAR) certs come by name.
    try:
        for name in apk.get_signature_names() or []:
            der = apk.get_certificate_der(name)
            if der:
                out.append(der.hex().upper())
    except Exception:
        pass
    return sorted(set(out))


def read_manifest(path: str, include_disabled: bool = False) -> ApkInfo:
    """Fast path: parse manifest + certs only. No DEX analysis."""
    apk = APK(path)
    tsdk = _target_sdk(apk)
    try:
        minsdk = int(apk.get_min_sdk_version() or 0)
    except Exception:
        minsdk = 0
    man = apk.get_android_manifest_xml()
    comps = extract_components(man, tsdk, include_disabled=include_disabled)
    return ApkInfo(
        package=apk.get_package() or "",
        target_sdk=tsdk,
        min_sdk=minsdk,
        components=comps,
        der_hexes=_cert_hexes(apk),
    )


# ---- file channel: which classes reference a reachable-writable path --------------------
def _looks_like_path(s: str) -> bool:
    return s.startswith("/") and len(s) > 1


def _path_related(a: str, b: str) -> bool:
    """True if one path is the other, or a directory-prefix of the other."""
    a = a.rstrip("/"); b = b.rstrip("/")
    if a == b:
        return True
    lo, hi = (a, b) if len(a) <= len(b) else (b, a)
    return hi.startswith(lo + "/")


def _class_of(xref_item) -> Optional[str]:
    """Best-effort dotted class name for a get_xref_from() tuple element."""
    for obj in xref_item:
        for attr in ("class_name", "get_class_name"):
            try:
                v = getattr(obj, attr)
                v = v() if callable(v) else v
                if v:
                    return _smali_to_dotted(str(v))
            except Exception:
                continue
    return None


def _smali_to_dotted(t: str) -> str:
    # Lx/y/Z; -> x.y.Z
    if t.startswith("L") and t.endswith(";"):
        t = t[1:-1]
    return t.replace("/", ".")


def dex_path_matches(path: str, needle_paths: Set[str]) -> Dict[str, List[str]]:
    """Run full DEX analysis and return {matched_path: [dotted class names that reference a
    string path-related to it]}. Expensive; call only for APKs in scope.

    Also records APK-level matches under the key "*" when the referencing class can't be
    attributed (so an ingestion point is never silently dropped)."""
    from androguard.misc import AnalyzeAPK
    _apk, _dx_list, dx = AnalyzeAPK(path)
    needles = [n for n in needle_paths if _looks_like_path(n)]
    result: Dict[str, Set[str]] = {}
    if not needles:
        return {}
    for sa in dx.get_strings():
        val = sa.get_value()
        if not _looks_like_path(val):
            continue
        hits = [n for n in needles if _path_related(val, n)]
        if not hits:
            continue
        classes: Set[str] = set()
        try:
            for x in sa.get_xref_from():
                c = _class_of(x)
                if c:
                    classes.add(c)
        except Exception:
            pass
        for n in hits:
            result.setdefault(n, set()).update(classes or {"*"})
    return {k: sorted(v) for k, v in result.items()}
