# Android call-graph security measurement — experiment bundle

This repository bundles the **Python measurement pipeline**, **frozen derived tables and text views**, and **tool sources / drivers** used for static–dynamic call-graph comparison work with security-oriented tagging.

`WORKROOT` in the measurement code is the **repository root** (the parent of the `scripts` directory), so paths to `data/` resolve consistently when you run jobs from a normal checkout.

---

## What is in this tree

At the top level you should see:

- **`LICENSE`** — distribution terms (verify year and holder before a public release).
- **`README.md`** — this overview.
- **`scripts/`** — measurement and reporting entry points (`run_security_measurement.py`, view builders, corpus helpers, `security_common.py` shared layout).
- **`data/`** — derived CSV/JSON, configuration lists, and text corpora used by the scripts:
  - **`config/`** — e.g. library-prefix lists for library vs non-library slices.
  - **`droidbench_source/`** — DroidBench-oriented inputs (dynamic summaries, missed-edge style artifacts where shipped).
  - **`corpus_from_graphs/`** — graph-derived text and union-style extracts.
  - **`method_views/`** — per-tag or per-tool method sets and missed lists used in tables and case studies.
- **`TOOLS/`** — third-party and modified tool trees, plus call-graph driver scripts. This subtree is **large**; treat it as an artifact drop (separate archive, partial clone, or Git LFS) rather than something you always push in full to a small remote.

A **`.gitignore`** may be present when the bundle is maintained under version control.

---

## How the pieces relate

| Area | Role |
|------|------|
| **Scripts** | Compute coverage, tagging, proxies, and paper-style tables from the frozen `data/` inputs. |
| **Data** | Single place for shipped **derived** artifacts so runs are reproducible without regenerating everything from raw logs. |
| **Tools** | Optional local rebuild / rerun of static analyzers; not required to **recompute** every table if you only consume the frozen `data/` outputs. |

If you extend the pipeline with extra corpora or raw analysis trees, you may need to align path constants in the Python modules with **your** machine layout—the defaults in this bundle assume a particular research layout.

---

## Running the pipeline (sketch)

Use a virtual environment and install dependencies from whatever requirements file you maintain alongside these scripts. From the **`scripts`** directory:

```bash
python3 -m venv .venv
source .venv/bin/activate
pip install -r requirements.txt
python3 run_security_measurement.py --help
```

Create the venv **next to** `scripts` or **inside** it according to your preference; what matters is that imports and `WORKROOT` resolution match how you invoke Python.

---

## Version control and size

Pushing the **entire** repository (especially **`TOOLS/`** and large `data/` subtrees) to a generic Git host often hits size limits. Typical patterns: ship **code + small tables** in Git, ship **large binaries and tool trees** as a separate archive or object storage, or use Git LFS with a clear quota plan.

---

## License

See **`LICENSE`**.
