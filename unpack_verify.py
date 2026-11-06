#!/usr/bin/env python3
"""
unpack_verify.py -- verify an unpacked Android firmware tree is complete and exhaustive
(and, optionally, help unpack raw images first). Separate from analyze.py on purpose.

  python3 unpack_verify.py verify -r <unpacked_root>
  python3 unpack_verify.py unpack -i <image_or_dir> -o <out_dir>   # best-effort, uses
                                                                   # external extractors

VERIFY answers: do I have everything analyze.py needs, and did extraction leave anything
behind? It checks partitions, the SELinux policy + context files, leftover un-extracted
images, system-as-root layout, and reports the build fingerprint so you know what this is.

Exit code is non-zero if any ERROR-level check fails.
"""
from __future__ import annotations

import argparse
import os
import shutil
import struct
import subprocess
import sys

# ---- image-format sniffing ---------------------------------------------------------------
SPARSE_MAGIC = 0xED26FF3A
EROFS_MAGIC = 0xE0F5E1E2       # at offset 1024
SQUASHFS_MAGIC_LE = b"hsqs"
LP_MAGIC = 0x616C4467          # "gDla" LP metadata geometry (super.img)


def sniff(path: str) -> str:
    try:
        with open(path, "rb") as f:
            head = f.read(4)
            if len(head) == 4 and struct.unpack("<I", head)[0] == SPARSE_MAGIC:
                return "android-sparse"
            if head == SQUASHFS_MAGIC_LE:
                return "squashfs"
            f.seek(1024)
            m = f.read(4)
            if len(m) == 4 and struct.unpack("<I", m)[0] == EROFS_MAGIC:
                return "erofs"
    except OSError:
        return "unreadable"
    if path.endswith(".br"):
        return "brotli"
    if os.path.basename(path) == "payload.bin":
        return "ota-payload"
    if os.path.basename(path).startswith("super"):
        return "super(maybe-lp)"
    return "unknown/raw"


# ---- verify ------------------------------------------------------------------------------
ERRORS = 0
WARNS = 0


def err(msg):
    global ERRORS
    ERRORS += 1
    print("  [ERROR] " + msg)


def warn(msg):
    global WARNS
    WARNS += 1
    print("  [warn ] " + msg)


def ok(msg):
    print("  [ ok  ] " + msg)


def _find(root, names):
    found = []
    for dp, _d, fs in os.walk(root):
        for fn in fs:
            if fn in names:
                found.append(os.path.relpath(os.path.join(dp, fn), root))
    return found


def verify(root: str) -> int:
    root = os.path.abspath(root)
    print("Verifying unpacked tree:", root)

    # 1. partitions present
    print("\n[1] Partitions")
    tops = set(os.listdir(root)) if os.path.isdir(root) else set()
    system_as_root = ("init" in tops or "init.rc" in tops) and "system" not in tops
    if system_as_root:
        ok("system-as-root layout detected (root is the system partition); pass "
           "--system-as-root to analyze.py")
    for p in ("system", "vendor"):
        if p in tops or system_as_root:
            ok("%s present" % p)
        else:
            err("missing core partition: %s" % p)
    for p in ("product", "system_ext", "odm", "vendor_dlkm", "system_dlkm"):
        if p in tops:
            ok("%s present" % p)

    # 2. SELinux policy binary
    print("\n[2] SELinux policy")
    pols = _find(root, {"precompiled_sepolicy", "sepolicy"})
    if pols:
        for p in pols:
            size = os.path.getsize(os.path.join(root, p))
            ok("policy: %s (%d bytes)" % (p, size))
            if size < 10000:
                warn("policy file %s looks suspiciously small" % p)
    else:
        err("no sepolicy / precompiled_sepolicy binary found -- analyze.py cannot run")

    # 3. context files
    print("\n[3] SELinux context files")
    need = {
        "file_contexts": ["file_contexts", "plat_file_contexts", "vendor_file_contexts"],
        "service_contexts": ["service_contexts", "plat_service_contexts",
                             "vendor_service_contexts", "hwservice_contexts"],
        "property_contexts": ["property_contexts", "plat_property_contexts",
                             "vendor_property_contexts"],
        "genfs_contexts": ["genfs_contexts", "plat_genfs_contexts", "vendor_genfs_contexts"],
        "seapp_contexts": ["seapp_contexts", "plat_seapp_contexts", "vendor_seapp_contexts"],
    }
    for group, names in need.items():
        hits = _find(root, set(names))
        if hits:
            ok("%s: %s" % (group, ", ".join(hits)))
        elif group in ("file_contexts", "service_contexts"):
            err("no %s found (needed for backing-file mapping)" % group)
        else:
            warn("no %s found (that mapping layer will be empty)" % group)

    # 4. leftover un-extracted images
    print("\n[4] Leftover un-extracted images (extraction should leave none)")
    leftovers = 0
    for dp, _d, fs in os.walk(root):
        for fn in fs:
            full = os.path.join(dp, fn)
            if fn.endswith((".img", ".br")) or fn == "payload.bin" or fn.startswith("super"):
                kind = sniff(full)
                if kind not in ("unknown/raw",):
                    warn("un-extracted %s: %s (%s)" % (kind, os.path.relpath(full, root), kind))
                    leftovers += 1
    if leftovers == 0:
        ok("no sparse/erofs/squashfs/brotli/payload images left behind")

    # 5. exhaustiveness sanity: file counts + key binaries
    print("\n[5] Content sanity")
    nfiles = sum(len(fs) for _dp, _d, fs in os.walk(root))
    (ok if nfiles > 2000 else warn)("total files in tree: %d" % nfiles)
    init = _find(root, {"init"})
    (ok if init else warn)("init binary: %s" % (init[0] if init else "not found"))
    rc = [1 for dp, _d, fs in os.walk(root) for f in fs if f.endswith(".rc")]
    (ok if rc else warn)("init .rc files: %d" % len(rc))

    # 6. build fingerprint (what IS this image?)
    print("\n[6] Build identity")
    for bp in _find(root, {"build.prop"})[:4]:
        try:
            with open(os.path.join(root, bp), errors="replace") as f:
                props = dict(l.strip().split("=", 1) for l in f
                             if "=" in l and not l.startswith("#"))
            fp = props.get("ro.build.fingerprint") or props.get("ro.vendor.build.fingerprint")
            sdk = props.get("ro.build.version.sdk") or props.get("ro.vendor.build.version.sdk")
            if fp or sdk:
                ok("%s: fingerprint=%s sdk=%s" % (bp, fp, sdk))
        except OSError:
            pass

    print("\n%s  errors=%d  warnings=%d" %
          ("FAIL" if ERRORS else "PASS", ERRORS, WARNS))
    return 1 if ERRORS else 0


# ---- unpack (best-effort orchestration) --------------------------------------------------
EXTRACTORS = {
    "android-sparse": ("simg2img", "simg2img {inp} {out}.raw"),
    "super(maybe-lp)": ("lpunpack", "lpunpack {inp} {outdir}"),
    "ota-payload": ("payload-dumper-go", "payload-dumper-go -o {outdir} {inp}"),
    "squashfs": ("unsquashfs", "unsquashfs -d {outdir}/squashfs-root {inp}"),
    "erofs": ("fsck.erofs", "fsck.erofs --extract={outdir} {inp}"),
    "brotli": ("brotli", "brotli -d {inp}"),
}


def unpack(inp: str, outdir: str) -> int:
    os.makedirs(outdir, exist_ok=True)
    kind = sniff(inp) if os.path.isfile(inp) else "dir"
    print("Detected:", kind)
    if kind == "dir":
        print("Input is a directory; nothing to extract. Run `verify` on it.")
        return 0
    tool, template = EXTRACTORS.get(kind, (None, None))
    if not tool:
        print("No known extractor for %r. Inspect manually." % kind)
        return 2
    cmd = template.format(inp=inp, out=os.path.join(outdir, os.path.basename(inp)),
                          outdir=outdir)
    if shutil.which(tool) is None:
        print("Extractor '%s' is NOT installed. Run this yourself:\n    %s" % (tool, cmd))
        print("(Suggested sources: simg2img/android-sdk-libsparse-utils, lpunpack from AOSP,\n"
              " payload-dumper-go, squashfs-tools, erofs-utils, brotli.)")
        return 3
    print("Running:", cmd)
    rc = subprocess.call(cmd, shell=True)
    print("extractor exit:", rc)
    print("Note: extraction is often multi-stage (super->partitions->erofs/sparse->tree). "
          "Re-run `unpack` on each produced image until `verify` passes.")
    return rc


def main():
    ap = argparse.ArgumentParser(description=__doc__,
                                 formatter_class=argparse.RawDescriptionHelpFormatter)
    sub = ap.add_subparsers(dest="cmd", required=True)
    v = sub.add_parser("verify", help="check an unpacked tree is complete/exhaustive")
    v.add_argument("-r", "--root", required=True)
    u = sub.add_parser("unpack", help="best-effort extract a raw image (uses external tools)")
    u.add_argument("-i", "--image", required=True)
    u.add_argument("-o", "--out", required=True)
    args = ap.parse_args()
    if args.cmd == "verify":
        sys.exit(verify(args.root))
    else:
        sys.exit(unpack(args.image, args.out))


if __name__ == "__main__":
    main()
