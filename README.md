# Android call-graph security measurement — experiment bundle

**Path on this machine:** `/local-storage/RESEARCH/android-callgraph-security-experiment`

This tree holds the **measurement scripts**, **frozen tables / views**, **tool sources & drivers**, and **DroidBench analysis artifacts**, aligned with the CCS / thesis “static vs dynamic + security tagging” work. **`WORKROOT`** in `scripts/security_common.py` resolves to **this directory** (not `$HOME/RESEARCH/ccs_security_measurement`).

---

## Directory layout (current)

```text
android-callgraph-security-experiment/
├── README.md                 # This file
├── LICENSE                   # MIT (confirm before public release)
├── NOT_SHIPPED.md            # Large / omitted / symlink notes
├── .gitignore
│
├── scripts/                  # Python measurement pipeline
│   └── security_common.py    # WORKROOT = repo root; libraries + DroidBench paths under data/
│
├── data/                     # Frozen CSV/JSON + method views + corpus extracts
│   ├── config/
│   │   └── libraries.lst     # Library-prefix list (non-library slice)
│   ├── droidbench_source/    # dynamic_summary, missed edges, method-only misses
│   ├── corpus_from_graphs/   # DYNAMIC union text, stem summaries, etc.
│   ├── method_views/         # Per-tag dynamic sets + per-tool missed lists (~260MB class)
│   └── *.csv, *.json         # Paper / RQ tables, canonical stems, taxonomy snapshot
│
├── docs/                     # Paper + methodology markdown + thesis PDF (tracked in Git)
│
├── TOOLS/                    # Toolchains & call-graph drivers (~9GB)
│   ├── generate_callgraphs_*.py
│   ├── GATOR/, MAMADROID/, NATIDROID/, MaMaDroid_Modification/, NatiDroid_Modification/
│   ├── Modification-Androguard/androguard/
│   └── Call-Graph-Soundness-in-Android-Static-Analysis/   # Samhi et al.–style artifact tree
│
└── ANALYSIS/                 # Empirical runs (DroidBench + link to APKPure corpora)
    ├── README.md             # ANALYSIS-specific map
    ├── APKPURE_ANALYSIS      # → symlink to /local-storage/RESEARCH/APKPURE_ANALYSIS (~1.2TB)
    └── DROIDBENCH_ANALYSIS/  # Wrapper matching upstream layout
        ├── DROIDBENCH_STATIC_ANALYSIS/   # Per-tool static outputs (Androguard, FlowDroid, …)
        └── DYNAMIC_ANALYSIS/             # DroidBench dynamic: ARTIFACTS, TOOL/AndroLog, RESULT/
```

**Note:** If `docs/` is missing on disk but you expect it, restore from Git:  
`git checkout HEAD -- docs/`

---

## What each top-level area is for

| Path | Purpose |
|------|---------|
| **`scripts/`** | Security tagging, static–dynamic coverage, entry points, downstream proxies, RQ5 report (`generate_rq5_report.py`), dataset freeze helpers. |
| **`data/`** | All **derived** CSV/JSON used in tables/figures, `method_views/` text sets, `corpus_from_graphs/` including the dynamic method union file, **`data/config/libraries.lst`**, **`data/droidbench_source/`** inputs. |
| **`docs/`** | Narrative: RQ5 baseline write-up, taxonomy examples, failure taxonomy, paper draft, thesis PDF. |
| **`TOOLS/`** | Runnable / buildable tool sides: modified Androguard, Gator/MaMaDroid/NatiDroid Maven trees, `generate_callgraphs_*.py`. **Large** — use Zenodo or disk, not a bare GitHub push of the whole tree. |
| **`ANALYSIS/`** | **DroidBench** static + dynamic trees live under **`ANALYSIS/DROIDBENCH_ANALYSIS/`**. **APKPure** real-app corpora are **not copied**: **`ANALYSIS/APKPURE_ANALYSIS`** is a **symlink** to `/local-storage/RESEARCH/APKPURE_ANALYSIS`. |

---

## Omitted on purpose (see `NOT_SHIPPED.md`)

- **`data/static_unique_methods_graph_corpus/`** — merged per-tool unique-method text files (~500MB+). Copy or symlink from your canonical location if you need every pipeline step without hitting `/local-storage/RESULTS` layouts.

---

## External paths (code still references these)

`security_common.py` / `generate_rq5_report.py` still use **absolute** paths under:

- **`/local-storage/RESEARCH/APKPURE_ANALYSIS/APKPURE_DYNAMIC_ANALYSIS/`** — graphs, logs, `summary_dynamic.csv`, non-obf strict list, etc.
- **`/local-storage/RESEARCH/RESULTS/`** — static graph artifacts for some tools (see `find_static_graph_path` in `security_common.py`).

The **`ANALYSIS/APKPURE_ANALYSIS`** symlink keeps a single place in this repo that “points at” the APKPure tree without duplicating **~1.2TB**.

---

## Run (example)

```bash
cd /local-storage/RESEARCH/android-callgraph-security-experiment/scripts
python3 -m venv ../.venv
source ../.venv/bin/activate
pip install -r requirements.txt   # pin/fill as needed
python3 run_security_measurement.py --help
```

---

## Git remote (repo already initialized)

```bash
cd /local-storage/RESEARCH/android-callgraph-security-experiment
git remote add origin https://github.com/shafiqul92/<REPO>.git   # once
git push -u origin main    # as user shafiqul; PAT or SSH — whole tree is large
```

---

## License

See **`LICENSE`** (update copyright year / holder if needed).
