"""FlowDroid engine binding.

emit   : write SourcesAndSinks.txt from spec.py
run    : java -jar <fd.jar> -a APK -p <platforms> -s sas.txt -o out.xml [-ol -ps]
parse  : DataFlowResults XML -> normalized findings (keyed to exported components)
"""
from __future__ import annotations

import os
import subprocess
import xml.etree.ElementTree as ET
from typing import List, Optional

from . import spec


def emit_sources_sinks(path: str) -> str:
    lines = []
    for s in spec.SOURCES:
        lines.append("%s -> _SOURCE_" % s.soot())
    for s in spec.SINKS:
        lines.append("%s -> _SINK_" % s.soot())
    with open(path, "w") as f:
        f.write("\n".join(lines) + "\n")
    return path


def run(apk: str, jar: str, platforms: str, sas: str, out_xml: str,
        timeout: int = 1800, extra: Optional[List[str]] = None) -> None:
    cmd = ["java", "-jar", jar, "-a", apk, "-p", platforms, "-s", sas,
           "-o", out_xml, "-ol", "-ps"]
    if extra:
        cmd += extra
    subprocess.run(cmd, check=True, timeout=timeout)


def _class_of(method_sig: str) -> str:
    # "<com.x.Y$1: void onClick(...)>" -> "com.x.Y$1"
    s = method_sig.strip()
    if s.startswith("<"):
        s = s[1:]
    return s.split(":", 1)[0].strip()


def _match_component(cls: str, components: List[str]) -> Optional[str]:
    for comp in components:
        if cls == comp or cls.startswith(comp + "$"):
            return comp
    return None


def _cat_from_statement(stmt: str, table, which: str) -> Optional[str]:
    """Scan our source/sink signatures and return the category whose soot sig appears in the
    Jimple statement text."""
    for sig in table:
        if sig.soot() in stmt:
            return sig.cat
    return None


def parse(out_xml: str, apk: str, package: str, components: List[str]) -> List[dict]:
    findings: List[dict] = []
    if not os.path.isfile(out_xml):
        return findings
    try:
        root = ET.parse(out_xml).getroot()
    except ET.ParseError:
        return findings
    for result in root.iter("Result"):
        sink = result.find("Sink")
        if sink is None:
            continue
        sink_stmt = sink.get("Statement", "")
        sink_method = sink.get("Method", "")
        sink_cat = _cat_from_statement(sink_stmt, spec.SINKS, "sink") \
            or spec.sink_cat_of(sink.get("MethodSourceSinkDefinition", ""))
        srcs = result.find("Sources")
        for source in (srcs.iter("Source") if srcs is not None else []):
            src_stmt = source.get("Statement", "")
            src_method = source.get("Method", "")
            src_cat = _cat_from_statement(src_stmt, spec.SOURCES, "source")
            enclosing = _class_of(src_method) or _class_of(sink_method)
            comp = (_match_component(_class_of(src_method), components)
                    or _match_component(_class_of(sink_method), components)
                    or enclosing)
            findings.append({
                "engine": "flowdroid", "apk": apk, "package": package,
                "component": comp, "source_cat": src_cat, "sink_cat": sink_cat,
                "sink_method": sink_method,
                "rule": "%s_TO_%s" % (src_cat, sink_cat),
                "raw": {"source_stmt": src_stmt, "sink_stmt": sink_stmt,
                        "source_method": src_method},
            })
    return findings


def analyze(apk: str, package: str, components: List[str], jar: str, platforms: str,
            workdir: str, timeout: int = 1800) -> List[dict]:
    os.makedirs(workdir, exist_ok=True)
    sas = emit_sources_sinks(os.path.join(workdir, "SourcesAndSinks.txt"))
    out_xml = os.path.join(workdir, "flowdroid_%s.xml" % package)
    run(apk, jar, platforms, sas, out_xml, timeout=timeout)
    return parse(out_xml, apk, package, components)
