"""Canonical, engine-neutral source/sink spec + Stage-1 shortlist extraction.

Both engines are driven from the SAME definitions here, so a difference in their findings is a
difference in the engines -- not in how the question was posed.

Taxonomy
--------
Sources are the points where *caller-controlled* data enters an exported component:
  CALLER_INPUT  -- values read out of an Intent/Bundle/Uri (regardless of how the Intent
                   arrived), and ContentProvider query arguments.
  FILE_READ     -- data read from a file; tied back to the SELinux file channel by
                   post-filtering to components Stage 1 flagged as file-ingesting.
Sinks are dangerous operations:
  EXEC, LOAD_CODE, FILE_WRITE, SQL, REFLECTION, INTENT_REDIRECT, WEBVIEW, LOG.

A `normalized finding` (what both parsers emit) is:
  {engine, apk, package, component, source_cat, sink_cat, sink_method, rule, raw}
compared at the granularity (component, source_cat, sink_cat) -- the finest unit both
engines can express identically.
"""
from __future__ import annotations

import dataclasses
from typing import Dict, List, Optional

# ---- source / sink categories ------------------------------------------------------------
CALLER_INPUT = "CALLER_INPUT"
FILE_READ = "FILE_READ"
SOURCE_CATS = (CALLER_INPUT, FILE_READ)

SINK_CATS = ("EXEC", "LOAD_CODE", "FILE_WRITE", "SQL", "REFLECTION",
             "INTENT_REDIRECT", "WEBVIEW", "LOG")


@dataclasses.dataclass
class Sig:
    """A Java/Android API, in Soot signature form, tagged with our category.
    port: for MT -- 'Return' (value flows out) or 'Argument(N)' (Nth arg is tainted/dangerous).
    """
    cat: str
    cls: str
    ret: str
    name: str
    params: List[str]
    port: str

    def soot(self) -> str:
        return "<%s: %s %s(%s)>" % (self.cls, self.ret, self.name, ",".join(self.params))

    def mt_where(self) -> dict:
        return {"constraint": "signature_match",
                "parent": self.cls, "name": self.name}


# ---- SOURCES -----------------------------------------------------------------------------
SOURCES: List[Sig] = [
    # Intent accessors (return value is caller-controlled)
    Sig(CALLER_INPUT, "android.content.Intent", "java.lang.String", "getStringExtra",
        ["java.lang.String"], "Return"),
    Sig(CALLER_INPUT, "android.content.Intent", "android.os.Bundle", "getExtras", [], "Return"),
    Sig(CALLER_INPUT, "android.content.Intent", "android.net.Uri", "getData", [], "Return"),
    Sig(CALLER_INPUT, "android.content.Intent", "java.lang.String", "getAction", [], "Return"),
    Sig(CALLER_INPUT, "android.content.Intent", "java.lang.String", "getDataString", [], "Return"),
    Sig(CALLER_INPUT, "android.content.Intent", "java.util.ArrayList",
        "getStringArrayListExtra", ["java.lang.String"], "Return"),
    Sig(CALLER_INPUT, "android.content.Intent", "android.os.Parcelable",
        "getParcelableExtra", ["java.lang.String"], "Return"),
    Sig(CALLER_INPUT, "android.os.Bundle", "java.lang.String", "getString",
        ["java.lang.String"], "Return"),
    Sig(CALLER_INPUT, "android.os.Bundle", "java.lang.Object", "get",
        ["java.lang.String"], "Return"),
    Sig(CALLER_INPUT, "android.net.Uri", "java.lang.String", "getQueryParameter",
        ["java.lang.String"], "Return"),
    Sig(CALLER_INPUT, "android.app.Activity", "android.content.Intent", "getIntent", [], "Return"),
    # FILE_READ (tied to the SELinux file channel by post-filter)
    Sig(FILE_READ, "java.io.BufferedReader", "java.lang.String", "readLine", [], "Return"),
    Sig(FILE_READ, "java.io.FileInputStream", "int", "read", ["byte[]"], "Return"),
    Sig(FILE_READ, "android.content.ContentResolver", "java.io.InputStream",
        "openInputStream", ["android.net.Uri"], "Return"),
    Sig(FILE_READ, "android.content.Context", "java.io.FileInputStream", "openFileInput",
        ["java.lang.String"], "Return"),
]

# ---- SINKS -------------------------------------------------------------------------------
SINKS: List[Sig] = [
    Sig("EXEC", "java.lang.Runtime", "java.lang.Process", "exec", ["java.lang.String"], "Argument(1)"),
    Sig("EXEC", "java.lang.ProcessBuilder", "java.lang.Process", "start", [], "Argument(0)"),
    Sig("LOAD_CODE", "java.lang.System", "void", "load", ["java.lang.String"], "Argument(0)"),
    Sig("LOAD_CODE", "java.lang.System", "void", "loadLibrary", ["java.lang.String"], "Argument(0)"),
    Sig("LOAD_CODE", "dalvik.system.DexClassLoader", "void", "<init>",
        ["java.lang.String", "java.lang.String", "java.lang.String", "java.lang.ClassLoader"],
        "Argument(1)"),
    Sig("FILE_WRITE", "java.io.FileOutputStream", "void", "<init>", ["java.lang.String"], "Argument(1)"),
    Sig("FILE_WRITE", "java.io.FileOutputStream", "void", "write", ["byte[]"], "Argument(1)"),
    Sig("SQL", "android.database.sqlite.SQLiteDatabase", "void", "execSQL",
        ["java.lang.String"], "Argument(1)"),
    Sig("SQL", "android.database.sqlite.SQLiteDatabase", "android.database.Cursor", "rawQuery",
        ["java.lang.String", "java.lang.String[]"], "Argument(1)"),
    Sig("REFLECTION", "java.lang.Class", "java.lang.Class", "forName", ["java.lang.String"], "Argument(0)"),
    Sig("REFLECTION", "java.lang.reflect.Method", "java.lang.Object", "invoke",
        ["java.lang.Object", "java.lang.Object[]"], "Argument(1)"),
    Sig("INTENT_REDIRECT", "android.content.Context", "void", "startActivity",
        ["android.content.Intent"], "Argument(1)"),
    Sig("INTENT_REDIRECT", "android.content.Context", "void", "sendBroadcast",
        ["android.content.Intent"], "Argument(1)"),
    Sig("WEBVIEW", "android.webkit.WebView", "void", "loadUrl", ["java.lang.String"], "Argument(1)"),
    Sig("LOG", "android.util.Log", "int", "w", ["java.lang.String", "java.lang.String"], "Argument(1)"),
]


def source_cat_of(soot_sig: str) -> Optional[str]:
    for s in SOURCES:
        if s.soot() == soot_sig:
            return s.cat
    return None


def sink_cat_of(soot_sig: str) -> Optional[str]:
    for s in SINKS:
        if s.soot() == soot_sig:
            return s.cat
    return None


# ---- Stage-1 shortlist -------------------------------------------------------------------
@dataclasses.dataclass
class Target:
    apk: str
    package: str
    components: List[str]           # dotted class names of exported components
    file_ingesting: List[str]       # components Stage 1 tied to a source-writable path


def shortlist(stage1: dict, reachable_only: bool = True,
              unguarded_only: bool = False) -> List[Target]:
    """Pick APKs/components worth the (expensive) taint pass from a Stage-1 report."""
    out: List[Target] = []
    for app in stage1.get("apps", []):
        if reachable_only and not app.get("ipc_reachable"):
            # keep it anyway if it has a file-channel hit (valid cross-domain channel)
            if not any(c.get("file_ingesting") for c in app.get("exported_components", [])):
                continue
        comps, fileing = [], []
        for c in app.get("exported_components", []):
            if unguarded_only and not c.get("unguarded"):
                continue
            comps.append(c["name"])
            if c.get("file_ingesting"):
                fileing.append(c["name"])
        if comps:
            out.append(Target(app["apk"], app["package"], comps, fileing))
    return out


def rules() -> List[dict]:
    """MT rules: every source category paired with every sink category, so MT (like FlowDroid)
    reports any caller-input/file-read -> sink flow. code = stable index."""
    out, code = [], 1000
    for sc in SOURCE_CATS:
        for kc in SINK_CATS:
            out.append({"name": "%s_TO_%s" % (sc, kc), "code": code,
                        "description": "%s reaches %s" % (sc, kc),
                        "sources": [sc], "sinks": [kc]})
            code += 1
    return out


def rule_index() -> Dict[int, dict]:
    return {r["code"]: r for r in rules()}
