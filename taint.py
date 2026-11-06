#!/usr/bin/env python3
"""
taint.py -- Stage 2: static taint analysis of the Stage-1 shortlist, two interchangeable
engines driven from one shared source/sink spec so their results are directly comparable.

  emit       write the engine config files from the shared spec (inspect / hand-tune)
  flowdroid  run FlowDroid over the shortlist -> normalized findings JSON
  mariana    run Mariana Trench over the shortlist -> normalized findings JSON
  compare    diff two normalized findings files (overlap / engine-only)

Typical flow:
  python3 analyze.py reach -r ROOT -s untrusted_app --json reach.json
  python3 appsurface.py   -r ROOT -i reach.json      --json surface.json
  python3 taint.py flowdroid -i surface.json --jar fd.jar --platforms $ANDROID_SDK/platforms \
                             --workdir w --out fd.json
  python3 taint.py mariana   -i surface.json --workdir w --out mt.json
  python3 taint.py compare   --flowdroid fd.json --mariana mt.json --out cmp.json

Install: FlowDroid = the soot-infoflow-cmd jar + an Android platforms dir (android.jar's).
         Mariana Trench = `pip install mariana-trench` (provides the `mariana-trench` binary).
Both operate on one APK at a time -- no directory hierarchy required.
"""
from __future__ import annotations

import argparse
import json
import os
import sys

sys.path.insert(0, os.path.dirname(os.path.abspath(__file__)))
from taint import spec, flowdroid, mariana, compare as cmp_mod   # noqa: E402


def _load(path):
    with open(path) as f:
        return json.load(f)


def _targets(args):
    stage1 = _load(args.reach_surface)
    tgts = spec.shortlist(stage1, reachable_only=not args.all_apps,
                          unguarded_only=args.unguarded_only)
    if args.max_apks:
        tgts = tgts[:args.max_apks]
    return tgts


def _annotate_selinux(findings, target):
    """Tag FILE_READ findings with whether the component was tied to a source-writable path
    by Stage 1 (the SELinux file channel). CALLER_INPUT findings are always SELinux-relevant
    once the app is in scope."""
    fileing = set(target.file_ingesting)
    for f in findings:
        if f.get("source_cat") == spec.FILE_READ:
            f["selinux_tied"] = f.get("component") in fileing
        else:
            f["selinux_tied"] = True
    return findings


def cmd_emit(args):
    os.makedirs(args.out, exist_ok=True)
    if args.engine in ("flowdroid", "both"):
        p = flowdroid.emit_sources_sinks(os.path.join(args.out, "SourcesAndSinks.txt"))
        print("[*] wrote", p, "(%d sources, %d sinks)" % (len(spec.SOURCES), len(spec.SINKS)))
    if args.engine in ("mariana", "both"):
        g = mariana.emit_generators(os.path.join(args.out, "appmap_generators.json"))
        r = mariana.emit_rules(os.path.join(args.out, "rules.json"))
        c = mariana.emit_generator_config(os.path.join(args.out, "generator_config.json"),
                                          os.path.basename(g))
        print("[*] wrote", g, r, c, "(%d rules)" % len(spec.rules()))


def _run_engine(args, engine_name):
    tgts = _targets(args)
    print("[*] shortlist: %d APK(s)" % len(tgts))
    all_findings = []
    for i, t in enumerate(tgts, 1):
        print("  [%d/%d] %s (%d components)" % (i, len(tgts), t.package, len(t.components)),
              file=sys.stderr)
        try:
            if engine_name == "flowdroid":
                fs = flowdroid.analyze(t.apk, t.package, t.components, args.jar,
                                       args.platforms, args.workdir, timeout=args.timeout)
            else:
                fs = mariana.analyze(t.apk, t.package, t.components, args.workdir,
                                     source_root=args.source_root, timeout=args.timeout,
                                     binary=args.binary)
        except Exception as e:
            print("    warn: %s failed on %s: %s" % (engine_name, t.package, e),
                  file=sys.stderr)
            continue
        all_findings += _annotate_selinux(fs, t)
    out = {"engine": engine_name, "generated_from": args.reach_surface,
           "findings": all_findings}
    with open(args.out, "w") as f:
        json.dump(out, f, indent=2)
    print("[*] %s: %d findings -> %s" % (engine_name, len(all_findings), args.out))


def cmd_flowdroid(args):
    _run_engine(args, "flowdroid")


def cmd_mariana(args):
    _run_engine(args, "mariana")


def cmd_compare(args):
    fd = _load(args.flowdroid)
    mt = _load(args.mariana)
    fdf = fd.get("findings", fd) if isinstance(fd, dict) else fd
    mtf = mt.get("findings", mt) if isinstance(mt, dict) else mt
    if args.selinux_tied_only:
        fdf = [f for f in fdf if f.get("selinux_tied", True)]
        mtf = [f for f in mtf if f.get("selinux_tied", True)]
    rep = cmp_mod.compare(fdf, mtf)
    if args.out:
        with open(args.out, "w") as f:
            json.dump(rep, f, indent=2)
        print("[*] wrote", args.out)
    cmp_mod.print_report(rep)


def main():
    ap = argparse.ArgumentParser(description=__doc__,
                                 formatter_class=argparse.RawDescriptionHelpFormatter)
    sub = ap.add_subparsers(dest="cmd", required=True)

    e = sub.add_parser("emit", help="write engine config files from the shared spec")
    e.add_argument("--engine", choices=["flowdroid", "mariana", "both"], default="both")
    e.add_argument("--out", default="taint_spec_out")
    e.set_defaults(func=cmd_emit)

    def common(p):
        p.add_argument("-i", "--reach-surface", required=True, help="Stage-1 appsurface JSON")
        p.add_argument("--out", required=True, help="normalized findings JSON out")
        p.add_argument("--workdir", default="taint_work")
        p.add_argument("--all-apps", action="store_true",
                       help="do not restrict to IPC-reachable apps")
        p.add_argument("--unguarded-only", action="store_true")
        p.add_argument("--max-apks", type=int)

    fd = sub.add_parser("flowdroid", help="run FlowDroid over the shortlist")
    common(fd)
    fd.add_argument("--jar", required=True, help="soot-infoflow-cmd jar")
    fd.add_argument("--platforms", required=True, help="Android platforms dir (android.jar's)")
    fd.add_argument("--timeout", type=int, default=1800)
    fd.set_defaults(func=cmd_flowdroid)

    mt = sub.add_parser("mariana", help="run Mariana Trench over the shortlist")
    common(mt)
    mt.add_argument("--binary", default="mariana-trench")
    mt.add_argument("--source-root", help="optional Java source root for better traces")
    mt.add_argument("--timeout", type=int, default=3600)
    mt.set_defaults(func=cmd_mariana)

    c = sub.add_parser("compare", help="diff two normalized findings files")
    c.add_argument("--flowdroid", required=True)
    c.add_argument("--mariana", required=True)
    c.add_argument("--out", help="write comparison JSON here")
    c.add_argument("--selinux-tied-only", action="store_true",
                   help="drop FILE_READ findings not tied to a source-writable path")
    c.set_defaults(func=cmd_compare)

    args = ap.parse_args()
    args.func(args)


if __name__ == "__main__":
    main()
