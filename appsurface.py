#!/usr/bin/env python3
"""
appsurface.py -- Stage 1: exported-component attack surface reachable from a SELinux domain.

Consumes the JSON report from `analyze.py reach` and, for the APKs in an unpacked tree
(or under --apk-dir, searched recursively), reports two attacker channels from the source
domain:

  IPC channel  -- exported components (activity/service/receiver/provider) an outside caller
                  can invoke; tagged by whether the hosting app runs in a *reachable* domain.
  File channel -- components whose DEX references a path the source domain can WRITE (per the
                  reachability report): a shared-file ingestion point.

Usage:
  python3 appsurface.py -r <unpacked_root> -i <reach.json> [--apk-dir DIR] [--json out.json]
                        [--file-channel {off,reachable,exported,all}] [--unguarded-only]

Run `analyze.py reach ... --json reach.json` first to produce the input report.
Requires androguard (see requirements.txt); runs independently of the setools stage.
"""
from __future__ import annotations

import argparse
import json
import os
import sys

sys.path.insert(0, os.path.dirname(os.path.abspath(__file__)))
from sepolmap.backing_map import Contexts            # reuse the seapp_contexts parser  # noqa: E402
from appmap import discover, dexscan                 # noqa: E402
from appmap.domains import SeappIndex, ApkAttrs      # noqa: E402
from appmap.macperms import load_from_tree           # noqa: E402

WRITABLE_PERMS = {"write", "append", "create"}
SEAPP_FILES = ("seapp_contexts", "plat_seapp_contexts", "vendor_seapp_contexts")


def load_reach(path: str) -> dict:
    with open(path) as f:
        return json.load(f)


def writable_paths(report: dict) -> set:
    """On-device paths the source domain can write, from the reachability report."""
    paths = set()
    for items in (report.get("by_class", {}) or {}).values():
        for it in items:
            if it.get("backing_kind") != "file":
                continue
            if not (set(it.get("perms", [])) & WRITABLE_PERMS):
                continue
            for a in it.get("artifacts", []):
                if isinstance(a, str) and a.startswith("/"):
                    paths.add(a)
    return paths


def load_seapp(root: str) -> Contexts:
    ctx = Contexts()
    for dirpath, _d, files in os.walk(root):
        for fn in files:
            if fn in SEAPP_FILES:
                try:
                    ctx.load_seapp_contexts(os.path.join(dirpath, fn))
                except Exception as e:
                    print("  warn: seapp parse %s: %s" % (fn, e), file=sys.stderr)
    return ctx


def comp_dict(c) -> dict:
    d = {
        "kind": c.kind, "name": c.name, "exported": c.exported,
        "export_confidence": c.export_confidence, "unguarded": c.unguarded,
        "permission": c.permission, "ingest_points": c.ingest_points,
        "flags": c.flags,
    }
    if c.kind == "provider":
        d.update({"authorities": c.authorities, "read_permission": c.read_permission,
                  "write_permission": c.write_permission,
                  "grant_uri_permissions": c.grant_uri_permissions,
                  "path_permissions": c.path_permissions})
    return d


def cmd(args):
    root = os.path.abspath(args.root)
    report = load_reach(args.reach)
    source = args.source or report.get("source_domain", "<unknown>")
    reached = set(report.get("reached_domains", []) or [])
    wpaths = writable_paths(report)

    print("[*] source domain   :", source)
    print("[*] reached domains :", len(reached))
    print("[*] writable paths  :", len(wpaths), "(file-channel needles)")

    seapp = SeappIndex(load_seapp(root).seapp)
    print("[*] seapp app-domains:", len(seapp.app_domains),
          "| reachable & app-hosting:", ", ".join(seapp.app_domains_in(reached)) or "(none)")
    mac = load_from_tree(root)
    print("[*] mac_permissions signers:", len(mac.by_sig),
          "default seinfo=%s" % mac.default)

    refs = discover.discover(root, args.apk_dir)
    if args.max_apks:
        refs = refs[:args.max_apks]
    print("[*] APKs discovered :", len(refs),
          "(%s)" % ("--apk-dir" if args.apk_dir else "image app dirs"))

    apks = []
    for ref in refs:
        try:
            info = dexscan.read_manifest(ref.path, include_disabled=args.include_disabled)
        except Exception as e:
            print("  warn: manifest %s: %s" % (os.path.basename(ref.path), e), file=sys.stderr)
            continue
        seinfo = mac.seinfo_for(info.der_hexes)
        cands = seapp.candidates(ApkAttrs(info.package, ref.is_priv, ref.is_system, seinfo))
        reached_via = [c.domain for c in cands if c.domain in reached]
        exported = [c for c in info.components if c.exported]
        if args.unguarded_only:
            exported = [c for c in exported if c.unguarded]
        apks.append({
            "ref": ref, "info": info, "seinfo": seinfo, "cands": cands,
            "ipc_reachable": bool(reached_via), "reached_via": reached_via,
            "exported": exported,
            "file_channel": {},
        })

    # ---- file channel: DEX string xref against writable paths -------------------------
    scope = args.file_channel
    if scope != "off" and wpaths:
        def in_scope(a):
            if scope == "all":
                return True
            if scope == "reachable":
                return a["ipc_reachable"]
            return bool(a["exported"])        # "exported" (default)
        targets = [a for a in apks if in_scope(a)]
        print("[*] file-channel DEX scan: %d / %d APKs (scope=%s) ..."
              % (len(targets), len(apks), scope))
        for i, a in enumerate(targets, 1):
            name = os.path.basename(a["ref"].path)
            print("    [%d/%d] %s" % (i, len(targets), name), file=sys.stderr)
            try:
                a["file_channel"] = dexscan.dex_path_matches(a["ref"].path, wpaths)
            except Exception as e:
                print("      warn: dex scan failed: %s" % e, file=sys.stderr)
    elif scope != "off":
        print("[*] file-channel: skipped (report lists no writable paths)")

    out = build_report(source, report, wpaths, apks)
    if args.json:
        with open(args.json, "w") as f:
            json.dump(out, f, indent=2)
        print("[*] wrote JSON report:", args.json)
    _print_human(out)


def build_report(source, reach, wpaths, apks) -> dict:
    apps_out = []
    for a in apks:
        info, ref = a["info"], a["ref"]
        # attribute file-channel class hits back to exported components
        fc = a["file_channel"] or {}
        hit_classes = set()
        for classes in fc.values():
            hit_classes.update(classes)
        comp_out = []
        for c in a["exported"]:
            cd = comp_dict(c)
            cd["file_ingesting"] = c.name in hit_classes
            comp_out.append(cd)
        apps_out.append({
            "apk": ref.path, "package": info.package, "origin": ref.origin,
            "is_priv": ref.is_priv, "is_system": ref.is_system,
            "target_sdk": info.target_sdk, "min_sdk": info.min_sdk, "seinfo": a["seinfo"],
            "domain_candidates": [{"domain": c.domain, "confidence": c.confidence,
                                   "reason": c.reason} for c in a["cands"]],
            "ipc_reachable": a["ipc_reachable"], "reached_via": a["reached_via"],
            "exported_components": comp_out,
            "file_channel_paths": fc,
        })
    return {
        "source_domain": source,
        "reach_report": reach.get("policy"),
        "reached_domains": sorted(reach.get("reached_domains", []) or []),
        "writable_path_count": len(wpaths),
        "apps": sorted(apps_out, key=lambda x: (not x["ipc_reachable"], x["package"])),
    }


def _print_human(out: dict):
    print("\n" + "=" * 78)
    print("EXPORTED-COMPONENT ATTACK SURFACE  |  source domain:", out["source_domain"])
    print("=" * 78)
    n_reach = sum(1 for a in out["apps"] if a["ipc_reachable"])
    n_exp = sum(len(a["exported_components"]) for a in out["apps"])
    n_file = sum(1 for a in out["apps"] for c in a["exported_components"] if c.get("file_ingesting"))
    print("apps: %d total, %d in a reachable domain | exported components: %d | "
          "file-ingesting: %d" % (len(out["apps"]), n_reach, n_exp, n_file))

    for a in out["apps"]:
        if not a["exported_components"] and not a["file_channel_paths"]:
            continue
        tag = "REACHABLE" if a["ipc_reachable"] else "domain-not-reached"
        doms = ",".join(a["reached_via"]) or (a["domain_candidates"][0]["domain"]
                                              + "?" if a["domain_candidates"] else "?")
        print("\n## %s  [%s via %s]  sdk=%s seinfo=%s"
              % (a["package"], tag, doms, a["target_sdk"], a["seinfo"]))
        print("   %s  (%s)" % (a["apk"], a["origin"]))
        for c in a["exported_components"]:
            guard = "UNGUARDED" if c["unguarded"] else ("perm:" + str(c["permission"]
                     or c.get("read_permission") or c.get("write_permission")))
            marks = []
            if c.get("file_ingesting"):
                marks.append("FILE-INGEST")
            marks += c.get("flags") or []
            mstr = ("  <" + ",".join(marks) + ">") if marks else ""
            print("   [%-8s] %-40s %-9s %s%s"
                  % (c["kind"], c["name"], c["export_confidence"], guard, mstr))
        for path, classes in (a["file_channel_paths"] or {}).items():
            shown = ", ".join(classes[:4]) + (" ..." if len(classes) > 4 else "")
            print("      file<- %s  [%s]" % (path, shown))
    print("\nLegend: REACHABLE = app runs in a domain the source can reach (IPC channel).")
    print("        FILE-INGEST = component class references a source-writable path (file channel).")
    print("        export_confidence explicit|implicit-filter|implicit-default; UNGUARDED = no perm.")
    print("Note: IPC delivery is usually brokered by system_server, so 'domain-not-reached'")
    print("      components may still be reachable cross-app; the tag reflects the SELinux layer.")


def main():
    ap = argparse.ArgumentParser(description=__doc__,
                                 formatter_class=argparse.RawDescriptionHelpFormatter)
    ap.add_argument("-r", "--root", required=True, help="unpacked firmware root")
    ap.add_argument("-i", "--reach", required=True, help="JSON report from analyze.py reach")
    ap.add_argument("-s", "--source", help="override source domain (default: from report)")
    ap.add_argument("--apk-dir", help="search this dir recursively for APKs instead of image app dirs")
    ap.add_argument("--file-channel", choices=["off", "reachable", "exported", "all"],
                    default="exported", help="DEX-scan scope for file-channel path matching")
    ap.add_argument("--unguarded-only", action="store_true",
                    help="list only exported components with no permission guard")
    ap.add_argument("--include-disabled", action="store_true",
                    help="also include android:enabled=false components")
    ap.add_argument("--max-apks", type=int, help="cap number of APKs (debug)")
    ap.add_argument("--json", help="write full JSON report here")
    ap.set_defaults(func=cmd)
    args = ap.parse_args()
    args.func(args)


if __name__ == "__main__":
    main()
