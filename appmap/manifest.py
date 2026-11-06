"""Pure AndroidManifest component extraction + exported/guard resolution.

Operates on the lxml Element returned by androguard's APK.get_android_manifest_xml(),
but takes nothing androguard-specific, so it is unit-testable with hand-built XML.

Exported resolution rules (AOSP / PackageParser semantics):
  * android:exported present  -> that literal value           (confidence: explicit)
  * absent, has <intent-filter>:
        activity/service/receiver -> exported = True           (implicit-filter)
        (On targetSdk >= 31 a missing exported with a filter is actually an install-time
         error; we still surface it as exported but tag it ambiguous-sdk31.)
  * absent, no filter:
        activity/service/receiver -> exported = False          (implicit-default)
  * provider, android:exported absent:
        exported = (targetSdk < 17)                            (implicit-default)
"""
from __future__ import annotations

import dataclasses
from typing import List, Optional

ANDROID_NS = "{http://schemas.android.com/apk/res/android}"
COMPONENT_TAGS = ("activity", "activity-alias", "service", "receiver", "provider")

# Per-kind description of how caller-controlled data enters the component.
_INGEST = {
    "activity": ["getIntent() extras", "intent data URI"],
    "activity-alias": ["getIntent() extras", "intent data URI"],
    "service": ["onBind/onStartCommand intent extras"],
    "receiver": ["onReceive intent extras/data"],
    "provider": ["query/insert/update/delete/call: uri, selection, args, values"],
}


def _a(el, name: str) -> Optional[str]:
    # androguard may expose android: attributes namespaced ({uri}name), as a literal
    # "android:name" key, or (rarely) bare. Try in that order so `exported` is never missed.
    for key in (ANDROID_NS + name, "android:" + name, name):
        v = el.get(key)
        if v is not None:
            return v
    return None


@dataclasses.dataclass
class Component:
    kind: str                       # activity | service | receiver | provider | activity-alias
    name: str                       # fully-qualified class (dotted)
    exported: bool
    export_confidence: str          # explicit | implicit-filter | implicit-default
    enabled: bool
    has_intent_filter: bool
    permission: Optional[str]       # android:permission guard, if any
    # provider-only:
    authorities: Optional[str] = None
    read_permission: Optional[str] = None
    write_permission: Optional[str] = None
    grant_uri_permissions: bool = False
    path_permissions: Optional[List[dict]] = None
    # analysis annotations:
    ingest_points: Optional[List[str]] = None
    flags: Optional[List[str]] = None

    @property
    def unguarded(self) -> bool:
        """No permission stands between an external caller and this component's input."""
        if self.kind == "provider":
            # A provider is reachable for the operation whose permission is absent.
            return not (self.permission or self.read_permission or self.write_permission)
        return self.permission is None


def _resolve_name(el, pkg: str) -> str:
    name = _a(el, "name") or ""
    if name.startswith("."):
        return pkg + name
    if "." not in name and name:
        return pkg + "." + name
    return name


def _resolve_exported(kind: str, el, has_filter: bool, target_sdk: int):
    raw = _a(el, "exported")
    flags: List[str] = []
    if raw is not None:
        return (raw.strip().lower() == "true"), "explicit", flags
    if kind == "provider":
        exported = target_sdk < 17
        return exported, "implicit-default", flags
    # activity / activity-alias / service / receiver
    if has_filter:
        if target_sdk >= 31:
            flags.append("ambiguous-sdk31")  # missing exported + filter is an install error >=S
        return True, "implicit-filter", flags
    return False, "implicit-default", flags


def extract_components(manifest_el, target_sdk: int,
                       include_disabled: bool = False) -> List[Component]:
    """manifest_el: the <manifest> lxml Element. Returns exported (and, if asked, disabled)
    components with their guard + ingest annotations."""
    pkg = manifest_el.get("package") or ""
    app = manifest_el.find("application")
    out: List[Component] = []
    if app is None:
        return out
    for el in app.iter():
        tag = el.tag if isinstance(el.tag, str) else ""
        if tag not in COMPONENT_TAGS:
            continue
        has_filter = el.find("intent-filter") is not None
        enabled = (_a(el, "enabled") or "true").strip().lower() != "false"
        exported, conf, flags = _resolve_exported(tag, el, has_filter, target_sdk)
        comp = Component(
            kind=tag,
            name=_resolve_name(el, pkg),
            exported=exported,
            export_confidence=conf,
            enabled=enabled,
            has_intent_filter=has_filter,
            permission=_a(el, "permission"),
            ingest_points=list(_INGEST.get(tag, [])),
            flags=flags,
        )
        if tag == "provider":
            comp.authorities = _a(el, "authorities")
            comp.read_permission = _a(el, "readPermission")
            comp.write_permission = _a(el, "writePermission")
            comp.grant_uri_permissions = (_a(el, "grantUriPermissions") or "").lower() == "true"
            pps = []
            for pp in el.findall("path-permission"):
                pps.append({
                    "permission": _a(pp, "permission"),
                    "readPermission": _a(pp, "readPermission"),
                    "writePermission": _a(pp, "writePermission"),
                })
            comp.path_permissions = pps or None
            if comp.grant_uri_permissions:
                comp.flags.append("grantUriPermissions")  # perms can be bypassed via granted URIs
        if not comp.enabled and not include_disabled:
            continue
        out.append(comp)
    return out
