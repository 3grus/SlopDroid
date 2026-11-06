"""Mariana Trench engine binding.

emit   : write model-generators JSON (our sources/sinks), rules.json, and a generator config
run    : mariana-trench --apk-path APK --rules-paths rules.json
                        --model-generator-configuration-paths genconfig.json
                        --model-generator-search-paths <dir> --output-directory out/
parse  : scan out/models@* for embedded `issues`, map issue.rule (our code) -> categories

NOTE: MT's `where` constraint dialect has shifted across releases. All generator constraints
live in one file (emit_generators) so a version tweak is a one-place fix, mirroring how the
setools calls are isolated in sepolmap/policy_adapter.py.
"""
from __future__ import annotations

import glob
import json
import os
import subprocess
from typing import List, Optional

from . import spec


def _dalvik_type(cls: str) -> str:
    # "android.content.Intent" -> "Landroid/content/Intent;" (the form MT matches on)
    return "L%s;" % cls.replace(".", "/")


def _generator_entry(sig: spec.Sig, role: str) -> dict:
    model = {("sources" if role == "source" else "sinks"):
             [{"kind": sig.cat, "port": sig.port}]}
    return {
        "find": "methods",
        "where": [{"constraint": "signature_match", "parent": _dalvik_type(sig.cls),
                   "name": sig.name}],
        "model": model,
    }


def emit_generators(path: str) -> str:
    gens = [_generator_entry(s, "source") for s in spec.SOURCES]
    gens += [_generator_entry(s, "sink") for s in spec.SINKS]
    with open(path, "w") as f:
        json.dump({"model_generators": gens}, f, indent=2)
    return path


def emit_rules(path: str) -> str:
    with open(path, "w") as f:
        json.dump(spec.rules(), f, indent=2)
    return path


def emit_generator_config(path: str, generator_name: str) -> str:
    # MT resolves {"name": X} to X.models in the search paths.
    with open(path, "w") as f:
        json.dump([{"name": generator_name}], f, indent=2)
    return path


def run(apk: str, rules_path: str, genconfig: str, search_dir: str, out_dir: str,
        source_root: Optional[str] = None, timeout: int = 3600,
        binary: str = "mariana-trench", system_jar: Optional[str] = None) -> None:
    os.makedirs(out_dir, exist_ok=True)
    cmd = [binary, "--apk-path", apk, "--rules-paths", rules_path,
           "--model-generator-configuration-paths", genconfig,
           "--model-generator-search-paths", search_dir,
           "--output-directory", out_dir]
    if system_jar:
        # Without android.jar, MT cannot resolve framework methods and generates 0 models.
        cmd += ["--system-jar-configuration-path", system_jar]
    if source_root:
        cmd += ["--source-root-directory", source_root]
    subprocess.run(cmd, check=True, timeout=timeout)


def _mt_class(method_sig: str) -> str:
    # "Lcom/x/Y;.onCreate:(...)V" -> "com.x.Y"
    s = method_sig
    if s.startswith("L"):
        s = s[1:]
    s = s.split(";", 1)[0]
    return s.replace("/", ".")


def _match_component(cls: str, components: List[str]) -> Optional[str]:
    for comp in components:
        if cls == comp or cls.startswith(comp + "$"):
            return comp
    return None


def _iter_models(out_dir: str):
    """Yield model dicts from out/model@* shards (JSON array or JSON-lines, defensively).

    MT 1.0.8 writes model@*; models@* is kept for other releases."""
    for fp in sorted(glob.glob(os.path.join(out_dir, "model@*"))
                     + glob.glob(os.path.join(out_dir, "models@*"))):
        with open(fp, errors="replace") as f:
            text = f.read().strip()
        if not text:
            continue
        try:
            obj = json.loads(text)
            for m in (obj if isinstance(obj, list) else [obj]):
                yield m
            continue
        except json.JSONDecodeError:
            pass
        for line in text.splitlines():
            line = line.strip()
            if not line:
                continue
            try:
                yield json.loads(line)
            except json.JSONDecodeError:
                continue


def parse(out_dir: str, apk: str, package: str, components: List[str]) -> List[dict]:
    idx = spec.rule_index()
    findings: List[dict] = []
    for m in _iter_models(out_dir):
        method = m.get("method") or m.get("name") or ""
        enclosing = _mt_class(method) if method else ""
        for issue in m.get("issues", []) or []:
            code = issue.get("rule")
            rule = idx.get(code)
            if not rule:
                continue
            src_cat = rule["sources"][0]
            sink_cat = rule["sinks"][0]
            callee = issue.get("callee") or issue.get("sink") or ""
            comp = _match_component(enclosing, components) or enclosing
            findings.append({
                "engine": "mariana", "apk": apk, "package": package,
                "component": comp, "source_cat": src_cat, "sink_cat": sink_cat,
                "sink_method": callee,
                "rule": rule["name"],
                "raw": {"enclosing_method": method, "code": code,
                        "position": issue.get("position")},
            })
    return findings


def analyze(apk: str, package: str, components: List[str], workdir: str,
            source_root: Optional[str] = None, timeout: int = 3600,
            binary: str = "mariana-trench", system_jar: Optional[str] = None) -> List[dict]:
    os.makedirs(workdir, exist_ok=True)
    gens = emit_generators(os.path.join(workdir, "appmap_generators.models"))
    rules_path = emit_rules(os.path.join(workdir, "rules.json"))
    genconfig = emit_generator_config(os.path.join(workdir, "generator_config.json"),
                                      os.path.splitext(os.path.basename(gens))[0])
    out_dir = os.path.join(workdir, "mt_out_%s" % package)
    run(apk, rules_path, genconfig, workdir, out_dir, source_root=source_root,
        timeout=timeout, binary=binary, system_jar=system_jar)
    return parse(out_dir, apk, package, components)
