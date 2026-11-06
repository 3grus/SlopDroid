"""Resolve an app's `seinfo` from its signing certificate via mac_permissions.xml.

mac_permissions.xml maps a signing cert (hex-encoded DER) to a seinfo tag:

    <policy>
      <signer signature="3082...">
        <seinfo value="platform"/>
      </signer>
      <default>
        <seinfo value="default"/>
      </default>
    </policy>

seinfo is the selector seapp_contexts uses to pick a domain (platform_app, etc.). Without it,
platform/vendor-signed system apps fall back to the lowest-confidence domain guess.
"""
from __future__ import annotations

import os
import xml.etree.ElementTree as ET
from typing import Dict, List, Optional

_MAC_FILES = ("mac_permissions.xml",)


class MacPermissions:
    def __init__(self):
        self.by_sig: Dict[str, str] = {}    # upper-hex DER cert -> seinfo
        self.default: Optional[str] = None

    def load(self, path: str):
        try:
            tree = ET.parse(path)
        except Exception:
            return
        root = tree.getroot()
        for signer in root.findall("signer"):
            sig = (signer.get("signature") or "").strip().upper()
            seinfo_el = signer.find("seinfo")
            if sig and seinfo_el is not None:
                val = seinfo_el.get("value")
                if val:
                    self.by_sig[sig] = val
        dflt = root.find("default")
        if dflt is not None:
            se = dflt.find("seinfo")
            if se is not None:
                self.default = se.get("value")

    def seinfo_for(self, der_hexes: List[str]) -> Optional[str]:
        for h in der_hexes:
            if h in self.by_sig:
                return self.by_sig[h]
        return self.default


def load_from_tree(root: str) -> MacPermissions:
    mp = MacPermissions()
    for dirpath, _d, files in os.walk(root):
        for fn in files:
            if fn in _MAC_FILES:
                mp.load(os.path.join(dirpath, fn))
    return mp
