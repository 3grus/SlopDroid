# Quickstart

End-to-end setup and a full run, from an unpacked Android image to a cross-engine taint
comparison. All dependencies are managed by [uv](https://docs.astral.sh/uv/) via
`pyproject.toml`; the tools run in-tree through `uv run` (nothing is installed as a package).

The pipeline is four stages, each feeding the next by JSON:

```
analyze.py reach ─▶ reach.json ─▶ appsurface.py ─▶ surface.json ─▶ taint.py {flowdroid,mariana} ─▶ taint.py compare
   (setools)                        (androguard)                      (FlowDroid / Mariana Trench)
```

---

## 1. Install uv

```bash
curl -LsSf https://astral.sh/uv/install.sh | sh      # then restart the shell, or:
export PATH="$HOME/.local/bin:$PATH"
uv --version
```

## 2. Get the Python dependencies

From the project root (the directory with `pyproject.toml`):

```bash
uv sync                    # core: androguard  → Stage 1 + the Stage 2 harness
uv sync --group taint      # also installs Mariana Trench (Stage 2 engine)
```

`uv sync` is declarative: pass `--group taint` **every** time you want Mariana Trench kept in
the environment (a bare `uv sync` prunes it). A `uv.lock` is written for reproducible installs.
Run any tool with `uv run python <script> ...`.

Quick check:

```bash
uv run python appsurface.py --help
uv run mariana-trench --version        # only if you synced --group taint
```

## 3. Two external engines (not Python packages)

**Policy engine — SELinux `setools`** (needed only for `analyze.py`, Stage 0). It is *not* on
PyPI; install it from your distro, then make the uv venv able to import it:

```bash
sudo apt install setools python3-setools     # Debian/Ubuntu  (Fedora/RHEL: dnf install setools)
uv venv --clear --system-site-packages        # recreate the venv so it can see system packages
uv sync --group taint                          # re-install project deps into the new venv
uv run python -c "import setools; print(setools.__version__)"   # confirm
```

(The `--system-site-packages` flag survives later `uv sync` runs. If you only need Stages 1–2,
skip this entirely.)

**FlowDroid** (Stage 2 engine) — a Java jar you build once, plus an Android `platforms` dir:

```bash
java -version                                  # JDK 8+ (JDK 21 is fine)
git clone https://github.com/secure-software-engineering/FlowDroid
cd FlowDroid && mvn -q package -DskipTests
#   jar: soot-infoflow-cmd/target/soot-infoflow-cmd-jar-with-dependencies.jar
# platforms dir = the Android SDK's "platforms" folder containing android.jar's, e.g.
#   $ANDROID_SDK_ROOT/platforms   (or copy android-XX/android.jar's into one folder)
```

---

## 4. Run the pipeline

Set a couple of paths for convenience:

```bash
ROOT=/path/to/unpacked           # verified with: uv run python unpack_verify.py verify -r $ROOT
FD_JAR=/path/to/soot-infoflow-cmd-jar-with-dependencies.jar
PLATFORMS=$ANDROID_SDK_ROOT/platforms
```

**Stage 0 — SELinux reachability** (needs setools; see step 3):

```bash
uv run python analyze.py selftest -p $ROOT/.../sepolicy          # confirm setools binds first
uv run python analyze.py reach -r $ROOT -s untrusted_app --json reach.json
uv run python graph.py reach.json                                # optional: reach.dot + reach.html
```

**Stage 1 — exported-component attack surface** (androguard):

```bash
uv run python appsurface.py -r $ROOT -i reach.json --json surface.json
#   --apk-dir DIR          search a directory recursively for APKs instead of the image app dirs
#   --file-channel all     widen the DEX path-xref scope (default: exported components only)
#   --unguarded-only       only components with no permission guard
```

**Stage 2 — static taint, both engines, then compare**:

```bash
# FlowDroid
uv run python taint.py flowdroid -i surface.json --out fd.json \
     --jar $FD_JAR --platforms $PLATFORMS --workdir work

# Mariana Trench  (installed via `uv sync --group taint`)
uv run python taint.py mariana   -i surface.json --out mt.json --workdir work

# Diff the two (same shared source/sink spec → apples-to-apples)
uv run python taint.py compare   --flowdroid fd.json --mariana mt.json --out compare.json
uv run python taint.py compare   --flowdroid fd.json --mariana mt.json --selinux-tied-only
```

Inspect the shared spec the engines are driven from at any time:

```bash
uv run python taint.py emit --engine both --out spec_out      # SourcesAndSinks.txt + MT configs
```

---

## Notes

- **No APK hierarchy needed.** Both taint engines analyze one APK at a time; `--apk-dir`
  discovery of loose APKs is fine.
- **Soundness.** Static taint is accurate-ish, not exhaustive (reflection / native / dynamic
  loading / some ICC are under-approximated). The `engine-only` rows from `compare` are exactly
  where FlowDroid and Mariana Trench disagree — spot-check those (jadx) or confirm dynamically
  (drozer).
- **MT constraint drift.** If `mariana` errors on a generator constraint, adjust the one place
  that builds them: `taint/mariana.py:emit_generators` (same pattern `sepolmap/policy_adapter.py`
  uses to isolate setools version drift).
- Full design, layers, and caveats are in `README.md`.
