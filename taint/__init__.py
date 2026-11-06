"""Stage 2: static taint analysis of the Stage-1 shortlist, with two interchangeable engines.

A single canonical source/sink spec (spec.py) is compiled to each engine's native config so
the two runs ask the *same question* -- "can caller-controlled input (Intent/Bundle/Uri
accessors, ContentProvider args) or data read from a source-writable file reach a dangerous
sink inside an exported component?" -- and their findings normalize to one schema for diffing.

  spec.py       canonical SourceDef/SinkDef + rules; shortlist extraction from Stage-1 JSON.
  flowdroid.py  emit SourcesAndSinks.txt, run the CLI jar, parse DataFlowResults XML.
  mariana.py    emit model-generators + rules.json, run mariana-trench, parse models@* issues.
  compare.py    normalize both result sets and report overlap / engine-only findings.
"""
