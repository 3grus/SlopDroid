# sepolmap — SELinux reachability + backing-file mapping for unpacked Android images

Given a **source process domain** (an SELinux domain an Android process executes in), this
tool computes the **exhaustive set of types it can reach**, categorized by object class
(Step 1), then maps each reachable type to the **concrete backing artifact** in the unpacked
image — the file/device/socket on disk, the binder service and its host daemon, the property
prefix, or the kernel-backed pseudo-fs node (Step 2).

Analyzing the code inside those artifacts is deliberately out of scope here; this produces the
*target list* for that work.

## Why the setools library (not sesearch/seinfo)

`sesearch` and `seinfo` are the two single-query CLI front-ends shipped on top of the
`setools` Python package. We use the library API directly because:

1. **The transitive engines are API-only.** `DomainTransitionAnalysis` and
   `InfoFlowAnalysis` — which perform exactly the "follow process transitions" and "follow
   IPC/read-write flows" closures Step 1 needs — are not exposed by the CLIs.
2. **Parse once.** `sesearch` reparses the whole binary policy on every invocation; a closure
   over hundreds of domains means thousands of invocations. The API loads once, queries in
   memory.
3. **Typed results.** Attributes, xperms, and conditional rules come back as objects, not text
   to re-parse.

Every finding in the report carries a `verify` field with the equivalent **`sesearch`**
command, so any single edge can be checked by hand with the CLI.

## Layout

| File | Role |
|------|------|
| `unpack_verify.py` | **Separate** script: verify an unpacked tree is complete/exhaustive; best-effort unpack of raw images. |
| `analyze.py` | Entry point for Step 1 + Step 2 (`selftest`, `reach` subcommands). |
| `graph.py` | Visualize a `reach` JSON report as a process-transition graph (DOT + interactive HTML). |
| `appsurface.py` + `appmap/` | **Stage 1:** map reachable domains → APKs → exported components + the IPC/file attacker channels (androguard). |
| `taint.py` + `taint/` | **Stage 2:** static taint over the Stage-1 shortlist via FlowDroid **and** Mariana Trench, from one shared spec, with a comparison. |
| `sepolmap/policy_adapter.py` | **The only module that touches setools.** Version drift fixes go here. |
| `sepolmap/reachability.py` | Step 1: layered reachable-type set (direct / transition / infoflow) with provenance. |
| `sepolmap/backing_map.py` | Step 2: context-file parsing, tree walk, type→artifact resolvers. |
| `sepolmap/ownership.py` | domain→entrypoint-binary and init-service→daemon mappings. |

## Install

Dependencies are managed by [uv](https://docs.astral.sh/uv/) (`pyproject.toml`); tools run
in-tree via `uv run`. **See [`QUICKSTART.md`](QUICKSTART.md) for full setup**, including the two
external engines. In short:

```bash
curl -LsSf https://astral.sh/uv/install.sh | sh     # install uv
uv sync                 # core (androguard): Stage 1 + Stage 2 harness
uv sync --group taint   # + Mariana Trench (Stage 2 engine)
```

`setools` (Stage 0, `analyze.py`) is **not on PyPI** — install it from your distro
(`apt install setools python3-setools`) and expose it with `uv venv --system-site-packages`
(QUICKSTART step 3). Then confirm the API binds before a big run:

```bash
uv run python analyze.py selftest -p <sepolicy>
```

If `selftest` prints `[WARN]` for a layer, that layer's setools call needs a small tweak for
your installed version — all such calls live in `sepolmap/policy_adapter.py`.

## Use

```bash
# 1. Confirm the tree is complete and nothing is left un-extracted.
uv run python unpack_verify.py verify -r /path/to/unpacked

# 2. Reachability + backing map from a domain, full transitive IPC closure (default).
uv run python analyze.py reach -r /path/to/unpacked -s untrusted_app --json out.json

#    Dial the closure with --layers (comma list of: direct,transition,infoflow)
uv run python analyze.py reach -r /path/to/unpacked -s hal_camera_default --layers direct,transition
```

Key flags: `--system-as-root` (tree root *is* the system partition at `/`), `--partition map`
defaults are in `backing_map.DEFAULT_PARTITION_MAP`, `--infoflow-min-weight` raises the
infoflow bandwidth bar to cut noise, `--max-artifacts` caps paths shown per type.

## Visualize a report (`graph.py`)

The `reach` text output lists targets; `graph.py` turns the `--json` report into a
**process-transition graph** so each reachable domain can be drilled and re-audited the same
way. Scope is domains-only: the source plus every domain it can cause to run, each annotated
with its entrypoint binary. No dependencies; the HTML is self-contained and opens offline.

```bash
uv run python analyze.py reach -r /path/to/unpacked -s <domain> --json out.json
uv run python graph.py out.json      # writes out.dot and out.html (--format dot|html|both)
dot -Tsvg out.dot -o out.svg       # static render (needs graphviz)
```

- **`out.dot`** — Graphviz source for a precise static SVG/PNG, good for large graphs/printing.
- **`out.html`** — interactive graph (pan/zoom/drag); click a domain to see its entrypoint
  binary, sample types reached through it, and the ready-to-run `analyze.py reach -s <that
  domain>` command for the next ring.

Topology note: the report folds the reachable-domain set, so edges are drawn source→reached
domain ("can cause to run"), not full A→B→C chains; intermediate hops from a finding's
`via_domains` appear on hover in the HTML.

## Exported-component attack surface (`appsurface.py`, Stage 1)

Once reachability says *which domains and which writable paths* the source can touch, Stage 1
asks *which exported app components can ingest caller-controlled data from there*. It consumes
the `reach` JSON and reports two attacker channels:

- **IPC channel** — exported `activity`/`service`/`receiver`/`provider` an outside caller can
  invoke. Each hosting app is mapped to its SELinux domain via `seapp_contexts` (+ `seinfo`
  from `mac_permissions.xml` when resolvable) and tagged **REACHABLE** when that domain is in
  the reachable set. Components are classed `explicit`/`implicit-filter`/`implicit-default` and
  flagged `UNGUARDED` when no permission stands in front of them.
- **File channel** — components whose DEX references a path the source domain can **write**
  (per the report), i.e. a shared-file ingestion point, flagged `FILE-INGEST`.

```bash
uv sync                                                          # installs androguard (see QUICKSTART.md)
uv run python appsurface.py -r /path/to/unpacked -i reach.json --json surface.json
#   --apk-dir DIR      search a directory recursively for APKs instead of the image app dirs
#   --file-channel {off,reachable,exported,all}   DEX-scan scope (default: exported)
#   --unguarded-only   only components with no permission guard
```

Honest caveats: app→domain is best-effort (full fidelity needs signature→`seinfo`), so each
candidate carries a confidence. IPC delivery is usually brokered by `system_server`, so a
`domain-not-reached` component may still be reachable cross-app — the tag reflects the SELinux
layer only. File-path matching is string-based (dynamically built paths can be missed).

## Static taint over the shortlist (`taint.py`, Stage 2)

Stage 2 answers the harder question — does caller-controlled input actually **flow to a
dangerous sink** inside those components — with two engines run from **one shared source/sink
spec** (`taint/spec.py`) so any difference is the engine's, not the question's. Both normalize
to the key `(package, component, source_cat, sink_cat)` for an apples-to-apples diff.

```bash
uv run python taint.py emit --engine both --out spec_out       # inspect/tune the generated configs
uv run python taint.py flowdroid -i surface.json --out fd.json --jar soot-infoflow-cmd.jar \
                 --platforms $ANDROID_SDK/platforms --workdir w
uv run python taint.py mariana   -i surface.json --out mt.json --workdir w      # needs mariana-trench
uv run python taint.py compare   --flowdroid fd.json --mariana mt.json --out cmp.json
```

- **Sources** = `CALLER_INPUT` (Intent/Bundle/Uri accessors, provider args) and `FILE_READ`
  (tied back to the SELinux file channel by `--selinux-tied-only` in `compare`).
- **Sinks** = exec, code-load, file-write, SQL, reflection, intent-redirect, WebView, log.
- Both engines analyze one APK at a time — **no directory hierarchy is required**; `--apk-dir`
  discovery of loose APKs is fine.

Soundness is *accurate-ish, not exhaustive*: static taint under-approximates through
reflection, native/JNI, dynamic code loading and some ICC. The two-engine diff is itself a
signal — an `engine-only` key is where their reachability/alias/ICC modeling diverged and is
worth a manual look (jadx), or dynamic confirmation (drozer).

## Reachability layers (Step 1)

Each reachable `(type, class)` is tagged with the layer(s) that produced it, so you can filter
noise after the fact:

- **D — direct**: targets of `allow`/`allowxperm` rules sourced directly at the domain
  (attribute-expanded via `source_indirect`).
- **T — transition**: domains reachable via `process:transition` (entrypoint exec +
  `type_transition`), unioned with each reached domain's direct targets. Models code the start
  domain can cause to run.
- **I — infoflow**: transitive outbound information-flow closure (shared fd/socket/pipe/binder,
  write-then-read on files, …). Maximal and noisiest — this is the "full transitive IPC
  closure" you asked for; filter with min-weight or by dropping the `I` layer.

## Backing resolution (Step 2)

| Object class | Source | Result |
|---|---|---|
| file/dir/lnk/chr/blk/sock/fifo | `file_contexts` → regex matched against the tree walk | on-device paths that carry the label |
| (pseudo-fs types) | `genfs_contexts` | `fs:path` (kernel-backed; owner is a driver/subsystem) |
| service_manager / hwservice_manager | `service_contexts` + init `.rc` | binder service name → host daemon exec path |
| property_service | `property_contexts` | property prefix(es) |
| process (a reached domain) | `type_transition …:process` + `file_contexts` | the binary that executes as that domain |

## Known limitations / extension points

- **fc regex dialect**: libselabel uses PCRE2; we use Python `re`. Covers the dialect used in
  practice; exotic patterns may need adjustment (one place: `backing_map._fc_regex`).
- **fc precedence**: each tree node is assigned its single *most-specific* `file_contexts`
  label (libselabel-style most-specific-match-wins), computed in one tree pass by
  `backing_map.FileLabelIndex` and shared by all file-class resolution and by
  `ownership.domain_entrypoints`. Specificity is approximated by (stem length, pattern length,
  explicit file-type spec), not exact PCRE2 ordering — a path shadowed by a more specific line
  of a *different* type is no longer attributed to the generic type, but a pathological tie
  could pick the wrong one of two equally-specific labels.
- **Partition→mountpoint mapping** varies by vendor/layout. Defaults cover AOSP-like trees;
  `--system-as-root` handles the other common case. Odd layouts: edit `DEFAULT_PARTITION_MAP`.
- **Service→host binary** uses init `.rc` `service{}` blocks. Services registered purely from
  C++/Java at runtime (no init entry) resolve to the service *name* only; a string-scan of
  binaries for `addService("name")` is the natural next step (not yet implemented).
- **Infoflow class attribution**: the flow graph yields target *types*, not the object class of
  each flow; Step 2 recovers classes from the context files, else tags `<infoflow>`.
- **setools API drift** across 4.x is isolated to `policy_adapter.py`; `selftest` tells you if a
  call needs updating.
