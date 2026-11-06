"""Normalize two engines' findings to a common key and report overlap / engine-only.

Comparison key = (package, component, source_cat, sink_cat) -- the finest unit both FlowDroid
and Mariana Trench express identically. Statement/line granularity is intentionally dropped:
the two engines number statements differently, so comparing there would manufacture
differences that are not real capability gaps.
"""
from __future__ import annotations

from typing import Dict, List, Tuple

Key = Tuple[str, str, str, str]


def key_of(f: dict) -> Key:
    return (f.get("package", ""), f.get("component", ""),
            f.get("source_cat") or "?", f.get("sink_cat") or "?")


def _index(findings: List[dict]) -> Dict[Key, List[dict]]:
    out: Dict[Key, List[dict]] = {}
    for f in findings:
        out.setdefault(key_of(f), []).append(f)
    return out


def compare(fd: List[dict], mt: List[dict]) -> dict:
    fdi, mti = _index(fd), _index(mt)
    fk, mk = set(fdi), set(mti)
    both = sorted(fk & mk)
    fd_only = sorted(fk - mk)
    mt_only = sorted(mk - fk)

    def rows(keys, where):
        out = []
        for k in keys:
            pkg, comp, sc, kc = k
            row = {"package": pkg, "component": comp, "source_cat": sc, "sink_cat": kc}
            if where in ("both", "fd"):
                row["flowdroid_hits"] = len(fdi.get(k, []))
            if where in ("both", "mt"):
                row["mariana_hits"] = len(mti.get(k, []))
            out.append(row)
        return out

    return {
        "summary": {
            "flowdroid_findings": len(fd), "mariana_findings": len(mt),
            "flowdroid_keys": len(fk), "mariana_keys": len(mk),
            "agreed_keys": len(both), "flowdroid_only_keys": len(fd_only),
            "mariana_only_keys": len(mt_only),
        },
        "agreed": rows(both, "both"),
        "flowdroid_only": rows(fd_only, "fd"),
        "mariana_only": rows(mt_only, "mt"),
    }


def print_report(rep: dict):
    s = rep["summary"]
    print("\n" + "=" * 78)
    print("ENGINE COMPARISON  (key = package/component/source_cat/sink_cat)")
    print("=" * 78)
    print("FlowDroid: %d findings -> %d keys | Mariana Trench: %d findings -> %d keys"
          % (s["flowdroid_findings"], s["flowdroid_keys"],
             s["mariana_findings"], s["mariana_keys"]))
    print("agreed: %d   flowdroid-only: %d   mariana-only: %d"
          % (s["agreed_keys"], s["flowdroid_only_keys"], s["mariana_only_keys"]))

    def block(title, rows):
        print("\n## %s (%d)" % (title, len(rows)))
        for r in rows:
            print("   %-28s %-34s %s -> %s"
                  % (r["package"], r["component"], r["source_cat"], r["sink_cat"]))

    block("Agreed by both engines", rep["agreed"])
    block("FlowDroid only (missed by Mariana Trench)", rep["flowdroid_only"])
    block("Mariana Trench only (missed by FlowDroid)", rep["mariana_only"])
    print("\nInterpret: 'engine-only' keys are where the engines' reachability/ICC/alias "
          "modeling diverged, or one lacks a model for that flow. Spot-check both.")
