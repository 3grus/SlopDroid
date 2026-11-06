"""Map an APK to the SELinux process domain(s) it runs in, via seapp_contexts.

seapp_contexts lines are selector->assignment, e.g.:
    user=_app      seinfo=platform            domain=platform_app   type=...
    user=_app      isPrivApp=true             domain=priv_app       type=...
    user=_app                                 domain=untrusted_app  type=...
    user=system    seinfo=platform            domain=system_app     type=...

Fully faithful resolution needs the app's `seinfo`, which comes from matching the signing
certificate against mac_permissions.xml. We resolve seinfo when that file + cert are available
(best effort) and otherwise fall back to location-based selectors (isPrivApp, user). Every
candidate carries a confidence so the report never overstates a match.
"""
from __future__ import annotations

import dataclasses
from typing import Dict, List, Optional


@dataclasses.dataclass
class DomainCandidate:
    domain: str
    confidence: str     # name | seinfo | priv | default | fallback
    reason: str


# Confidence ordering, most specific first.
_RANK = {"name": 0, "seinfo": 1, "priv": 2, "default": 3, "fallback": 4}


@dataclasses.dataclass
class ApkAttrs:
    package: str
    is_priv: bool            # lives in a priv-app dir
    is_system: bool          # lives on system/system_ext/product/vendor (platform image)
    seinfo: Optional[str] = None   # resolved from signature when available


class SeappIndex:
    def __init__(self, seapp: List[dict]):
        # Keep only entries that assign a process domain.
        self.entries = [e for e in seapp if e.get("domain")]
        self.app_domains = {e["domain"] for e in self.entries}

    def app_domains_in(self, domains) -> List[str]:
        """Subset of `domains` that seapp_contexts can assign to an app process."""
        return sorted(d for d in domains if d in self.app_domains)

    def candidates(self, apk: ApkAttrs) -> List[DomainCandidate]:
        out: List[DomainCandidate] = []
        for e in self.entries:
            dom = e["domain"]
            # Hard filters: a present selector that contradicts the APK rules the entry out.
            if "isPrivApp" in e:
                want = e["isPrivApp"].strip().lower() == "true"
                if want != apk.is_priv:
                    continue
            if "isSystemServer" in e and e["isSystemServer"].lower() == "true":
                continue  # not an installed APK
            if "isEphemeralApp" in e and e["isEphemeralApp"].lower() == "true":
                continue
            name_sel = e.get("name")
            if name_sel and not (apk.package == name_sel or apk.package.startswith(name_sel)):
                continue
            seinfo_sel = e.get("seinfo")
            if seinfo_sel and seinfo_sel != "default":
                if apk.seinfo is None:
                    continue                      # cannot confirm this signature class
                if apk.seinfo != seinfo_sel:
                    continue
            # Classify confidence from the strongest selector that matched.
            if name_sel:
                conf, reason = "name", "name=%s" % name_sel
            elif seinfo_sel and seinfo_sel != "default" and apk.seinfo:
                conf, reason = "seinfo", "seinfo=%s" % seinfo_sel
            elif "isPrivApp" in e:
                conf, reason = "priv", "isPrivApp=%s" % e["isPrivApp"]
            else:
                conf, reason = "default", "default selector (user=%s)" % e.get("user", "?")
            out.append(DomainCandidate(dom, conf, reason))
        # De-dup by domain, keeping the most specific tier per domain.
        best: Dict[str, DomainCandidate] = {}
        for c in out:
            if c.domain not in best or _RANK[c.confidence] < _RANK[best[c.domain].confidence]:
                best[c.domain] = c
        ranked = sorted(best.values(), key=lambda c: _RANK[c.confidence])
        # seapp_contexts is most-specific-wins: if any higher-specificity selector matched,
        # the bare "user=_app -> untrusted_app" default does NOT also apply. Keep only the
        # best tier present, so a platform/priv app is not spuriously tagged untrusted_app.
        if ranked:
            best_rank = _RANK[ranked[0].confidence]
            ranked = [c for c in ranked if _RANK[c.confidence] == best_rank]
        if not ranked:
            # Nothing matched (e.g. missing seinfo for a signed system app). Record the honest
            # fallback so the component still surfaces, just at the lowest confidence.
            fb = "untrusted_app" if not apk.is_system else "(unresolved system-app domain)"
            ranked = [DomainCandidate(fb, "fallback", "no seapp selector matched")]
        return ranked
