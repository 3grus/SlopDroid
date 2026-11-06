#!/usr/bin/env python3
"""
analyze.py -- Step 1 (reachability) + Step 2 (backing-file mapping) for an unpacked
Android firmware tree.

Usage:
  python3 analyze.py selftest -p <sepolicy>
  python3 analyze.py reach   -r <unpacked_root> [-p <sepolicy>] -s <source_domain> \
                             [--layers direct,transition,infoflow] [--json out.json]

Run `unpack_verify.py` first to confirm the tree is complete and to locate the policy and
context files this tool consumes.
"""
from __future__ import annotations

import argparse
import json
import os
import sys

# Run as a script OR a module.
sys.path.insert(0, os.path.dirname(os.path.abspath(__file__)))
from sepolmap.policy_adapter import Policy, require_setools   # noqa: E402
from sepolmap import reachability as R                        # noqa: E402
from sepolmap import backing_map as B                         # noqa: E402
from sepolmap import ownership as O                           # noqa: E402


# ---- locating the policy + context files inside an unpacked tree -------------------------
POLICY_CANDIDATES = [
    "vendor/etc/selinux/precompiled_sepolicy",
    "odm/etc/selinux/precompiled_sepolicy",
    "system/etc/selinux/precompiled_sepolicy",
    "sepolicy",
    "root/sepolicy",
    "vendor/etc/selinux/sepolicy",
]
# (filename in tree) -> parser method on Contexts
CTX_FILES = {
    "file_contexts": "load_file_contexts",
    "plat_file_contexts": "load_file_contexts",
    "system_ext_file_contexts": "load_file_contexts",
    "product_file_contexts": "load_file_contexts",
    "vendor_file_contexts": "load_file_contexts",
    "odm_file_contexts": "load_file_contexts",
    "genfs_contexts": "load_genfs_contexts",
    "plat_genfs_contexts": "load_genfs_contexts",
    "vendor_genfs_contexts": "load_genfs_contexts",
    "service_contexts": "load_service_contexts",
    "plat_service_contexts": "load_service_contexts",
    "vendor_service_contexts": "load_service_contexts",
    "hwservice_contexts": "load_service_contexts",
    "vndservice_contexts": "load_service_contexts",
    "plat_hwservice_contexts": "load_service_contexts",
    "vendor_hwservice_contexts": "load_service_contexts",
    "property_contexts": "load_property_contexts",
    "plat_property_contexts": "load_property_contexts",
    "vendor_property_contexts": "load_property_contexts",
    "seapp_contexts": "load_seapp_contexts",
    "plat_seapp_contexts": "load_seapp_contexts",
    "vendor_seapp_contexts": "load_seapp_contexts",
}


def find_policy(root: str) -> str:
    for c in POLICY_CANDIDATES:
        p = os.path.join(root, c)
        if os.path.isfile(p):
            return p
    raise FileNotFoundError(
        "No sepolicy binary found under %s. Looked for: %s\n"
        "Pass one explicitly with -p/--policy." % (root, ", ".join(POLICY_CANDIDATES)))


def load_contexts(root: str) -> tuple:
    ctx = B.Contexts()
    loaded = []
    for dirpath, _dirs, files in os.walk(root):
        for fn in files:
            meth = CTX_FILES.get(fn)
            if meth:
                full = os.path.join(dirpath, fn)
                try:
                    getattr(ctx, meth)(full)
                    loaded.append(os.path.relpath(full, root))
                except Exception as e:
                    print("  warn: failed to parse %s: %s" % (full, e), file=sys.stderr)
    return ctx, loaded


# ---- resolver dispatch -------------------------------------------------------------------
def resolve_backing(ctx: B.Contexts, index: B.FileLabelIndex, ta: R.TypeAccess) -> B.Backing:
    cls = ta.tclass
    if cls in B.FILE_CLASSES:
        bk = B.resolve_files(index, ta.type, cls)
        if not bk.artifacts and ta.type in ctx.genfs_by_type:
            return B.resolve_genfs(ctx, ta.type, cls)
        return bk
    if cls in ("service_manager", "hwservice_manager", "binder"):
        return B.resolve_service(ctx, ta.type, cls)
    if cls in ("property_service", "service"):
        return B.resolve_property(ctx, ta.type, cls)
    # Unknown/infoflow class: try every source by precedence.
    for fn in (lambda: B.resolve_files(index, ta.type, cls),
               lambda: B.resolve_service(ctx, ta.type, cls),
               lambda: B.resolve_property(ctx, ta.type, cls),
               lambda: B.resolve_genfs(ctx, ta.type, cls)):
        bk = fn()
        if bk.artifacts:
            return bk
    return B.Backing(ta.type, cls, "unresolved", [], note="no backing source matched")


# ---- subcommands -------------------------------------------------------------------------
def cmd_selftest(args):
    require_setools()
    pol = Policy(args.policy)
    print("[ok] loaded:", pol.version)
    types = pol.types()
    print("[ok] %d types, %d classes" % (len(types), len(pol.classes())))
    sample = "untrusted_app" if "untrusted_app" in types else types[0]
    n = sum(1 for _ in pol.allow_rules_from(sample))
    print("[ok] TERuleQuery(source=%s): %d allow/allowxperm rules" % (sample, n))
    try:
        t = next(iter(pol.transitions_from(sample)), None)
        print("[ok] DomainTransitionAnalysis: first edge =",
              (t.source + " -> " + t.target) if t else "(none)")
    except Exception as e:
        print("[WARN] DomainTransitionAnalysis failed (API drift?):", e)
    try:
        it = pol.infoflow_targets(sample)
        first = next(it, None)
        print("[ok] InfoFlowAnalysis: reachable (sample) =", first[0] if first else "(none)")
    except Exception as e:
        print("[WARN] InfoFlowAnalysis failed (API drift / missing perm map?):", e)
    print("\nSelftest complete. Warnings above mean that layer needs a tweak in "
          "sepolmap/policy_adapter.py for your installed setools version.")


def cmd_reach(args):
    root = os.path.abspath(args.root)
    policy_path = args.policy or find_policy(root)
    print("[*] policy :", policy_path)
    pol = Policy(policy_path)
    print("[*] engine :", pol.version)

    layers = tuple(x.strip() for x in args.layers.split(",") if x.strip())
    print("[*] layers :", ", ".join(layers))
    res = R.compute_reach(pol, args.source, layers=layers,
                          infoflow_min_weight=args.infoflow_min_weight)
    print("[*] source %s reaches %d (type,class) pairs; folded %d transition domains"
          % (args.source, len(res.access), len(res.reached_domains)))

    print("[*] loading context files + walking tree ...")
    ctx, loaded = load_contexts(root)
    print("    parsed context files:", ", ".join(loaded) or "(none found!)")
    tree = B.Tree(root, system_as_root=args.system_as_root).walk()
    print("    indexed %d filesystem nodes" % len(tree.nodes))
    index = B.FileLabelIndex(ctx, tree)   # single tree pass; shared by all file resolution
    print("    labeled %d file types" % len(index.by_type))

    print("[*] resolving domain entrypoints + init services ...")
    entrypoints = O.domain_entrypoints(pol, ctx, tree, index=index)
    initsvc = O.init_services(tree)

    # Build the report.
    report = {
        "source_domain": args.source,
        "policy": policy_path,
        "engine": pol.version,
        "layers": list(layers),
        "reached_domains": sorted(res.reached_domains),
        "reached_domain_binaries": {d: entrypoints.get(d, []) for d in sorted(res.reached_domains)},
        "by_class": {},
    }
    for tclass, accesses in res.by_class().items():
        cls_out = []
        for ta in accesses:
            bk = resolve_backing(ctx, index, ta)
            # attach service hosts if applicable
            hosts = []
            if bk.kind == "service":
                for name in bk.artifacts:
                    svc = initsvc["sockets"].get(name) or name
                    exe = initsvc["services"].get(svc)
                    if exe:
                        hosts.append("%s -> %s" % (name, exe))
            cls_out.append({
                "type": ta.type,
                "perms": sorted(ta.perms),
                "layers": sorted(ta.layers),
                "via_domains": sorted(ta.via_domains),
                "backing_kind": bk.kind,
                "artifacts": bk.artifacts[:args.max_artifacts],
                "artifacts_truncated": len(bk.artifacts) > args.max_artifacts,
                "service_hosts": hosts,
                "note": bk.note,
                "verify": ta.sample_sesearch,
            })
        report["by_class"][tclass] = cls_out

    if args.json:
        with open(args.json, "w") as f:
            json.dump(report, f, indent=2)
        print("[*] wrote JSON report:", args.json)

    _print_human(report)


def _print_human(report: dict):
    print("\n" + "=" * 78)
    print("REACHABILITY + BACKING MAP  |  source domain:", report["source_domain"])
    print("=" * 78)
    if report["reached_domains"]:
        print("\n## Domains reachable via process transition (code this domain can cause to run)")
        for d in report["reached_domains"]:
            bins = report["reached_domain_binaries"].get(d) or ["<entrypoint binary not resolved>"]
            print("  %-32s %s" % (d, ", ".join(bins)))
    for tclass, items in report["by_class"].items():
        print("\n## class %s  (%d reachable types)" % (tclass, len(items)))
        for it in items:
            arts = it["artifacts"]
            shown = ", ".join(arts[:6]) + (" ..." if it["artifacts_truncated"] or len(arts) > 6 else "")
            tag = "+".join(l[0].upper() for l in it["layers"])  # D/T/I
            print("  [%s] %-28s %-10s %s" % (tag, it["type"], it["backing_kind"], shown or it["note"]))
            for h in it["service_hosts"]:
                print("        host: %s" % h)
    print("\nLegend: layer tags  D=direct  T=via-transition  I=infoflow-closure")
    print("Verify any edge with the `verify` field (sesearch) in the JSON report.")


def main():
    ap = argparse.ArgumentParser(description=__doc__,
                                 formatter_class=argparse.RawDescriptionHelpFormatter)
    sub = ap.add_subparsers(dest="cmd", required=True)

    st = sub.add_parser("selftest", help="confirm the setools API binds against a policy")
    st.add_argument("-p", "--policy", required=True)
    st.set_defaults(func=cmd_selftest)

    rc = sub.add_parser("reach", help="compute reachable types and map them to backing files")
    rc.add_argument("-r", "--root", required=True, help="unpacked firmware root")
    rc.add_argument("-p", "--policy", help="sepolicy binary (auto-detected in tree if omitted)")
    rc.add_argument("-s", "--source", required=True, help="source process domain, e.g. untrusted_app")
    rc.add_argument("--layers", default="direct,transition,infoflow")
    rc.add_argument("--infoflow-min-weight", type=int, default=1)
    rc.add_argument("--system-as-root", action="store_true",
                    help="tree root IS the system partition mounted at / (system-as-root layout)")
    rc.add_argument("--max-artifacts", type=int, default=50)
    rc.add_argument("--json", help="write full JSON report here")
    rc.set_defaults(func=cmd_reach)

    args = ap.parse_args()
    args.func(args)


if __name__ == "__main__":
    main()
