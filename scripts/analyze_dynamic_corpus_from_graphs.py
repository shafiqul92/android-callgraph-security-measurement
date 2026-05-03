#!/usr/bin/env python3
"""
Derive corpus statistics from RESULT/graphs/*_dynamic_callgraph.txt only.

Writes under ccs_security_measurement/data/corpus_from_graphs/ — does not
modify APKPURE_DYNAMIC_ANALYSIS originals or STATIC_UNIQUE_METHODS_241_*.
"""
from __future__ import annotations

import argparse
import json
from collections import Counter, defaultdict
from pathlib import Path
from typing import Dict, Iterable, List, Set, Tuple

from security_common import (
    RESULT_GRAPHS,
    extract_class_name,
    extract_method_name,
    is_library_sig,
    is_security_relevant,
    load_library_prefixes,
    security_tags,
    write_csv,
    write_json,
)

WORKROOT = Path(__file__).resolve().parents[1]
DATADIR = WORKROOT / "data" / "corpus_from_graphs"
STEMS_241 = Path(
    "/local-storage/RESEARCH/APKPURE_ANALYSIS/APKPURE_DYNAMIC_ANALYSIS"
    "/STATIC_UNIQUE_METHODS_241_DYNAMIC_APPS/dynamic_stems_241.txt"
)


def load_stems_241() -> Set[str]:
    p = STEMS_241
    if not p.is_file():
        return set()
    return {ln.strip() for ln in p.read_text(encoding="utf-8", errors="replace").splitlines() if ln.strip()}


def graph_stems(graphs_dir: Path) -> List[str]:
    out: List[str] = []
    for p in sorted(graphs_dir.glob("*_dynamic_callgraph.txt")):
        out.append(p.name[: -len("_dynamic_callgraph.txt")])
    return out


def iter_signatures_from_graph(path: Path) -> Set[str]:
    """Unique callee/caller Soot-style signatures on one dynamic graph file."""
    local: Set[str] = set()
    with path.open("r", encoding="utf-8", errors="replace") as f:
        for line in f:
            if "-->" not in line:
                continue
            a, b = line.split("-->", 1)
            for sig in (a.strip(), b.strip()):
                if sig.startswith("<") and sig.endswith(">"):
                    local.add(sig)
    return local


def per_graph_one(path: Path) -> Tuple[str, int, int, int]:
    sigs = iter_signatures_from_graph(path)
    stem = path.name[: -len("_dynamic_callgraph.txt")]
    sec = sum(1 for s in sigs if is_security_relevant(s))
    return stem, path.stat().st_size, len(sigs), sec


def union_signatures_across_graphs(paths: List[Path], jobs: int) -> Set[str]:
    if jobs <= 1:
        union: Set[str] = set()
        for p in paths:
            union |= iter_signatures_from_graph(p)
        return union

    from concurrent.futures import ProcessPoolExecutor, as_completed

    union = set()
    with ProcessPoolExecutor(max_workers=min(jobs, len(paths))) as ex:
        futs = {ex.submit(iter_signatures_from_graph, p): p for p in paths}
        for fut in as_completed(futs):
            union |= fut.result()
    return union


def per_graph_stats(paths: List[Path], jobs: int) -> List[Dict[str, object]]:
    rows: List[Dict[str, object]] = []

    if jobs <= 1:
        for p in paths:
            stem, sz, n, sec = per_graph_one(p)
            rows.append(
                {
                    "stem": stem,
                    "file_bytes": sz,
                    "unique_methods_in_graph": n,
                    "security_relevant_methods_in_graph": sec,
                }
            )
    else:
        from concurrent.futures import ProcessPoolExecutor, as_completed

        with ProcessPoolExecutor(max_workers=min(jobs, len(paths))) as ex:
            futs = {ex.submit(per_graph_one, p): p for p in paths}
            for fut in as_completed(futs):
                stem, sz, n, sec = fut.result()
                rows.append(
                    {
                        "stem": stem,
                        "file_bytes": sz,
                        "unique_methods_in_graph": n,
                        "security_relevant_methods_in_graph": sec,
                    }
                )
    rows.sort(key=lambda r: str(r["stem"]))
    return rows


def tag_counts(signatures: Iterable[str]) -> Counter[str]:
    c: Counter[str] = Counter()
    for sig in signatures:
        if not is_security_relevant(sig):
            continue
        for tag in security_tags(sig):
            c[tag] += 1
    return c


def main() -> None:
    ap = argparse.ArgumentParser()
    ap.add_argument("--graphs-dir", type=Path, default=RESULT_GRAPHS)
    ap.add_argument("--jobs", type=int, default=8)
    ap.add_argument("--skip-union", action="store_true", help="Only per-graph stats + stem diff (faster)")
    args = ap.parse_args()

    graphs_dir: Path = args.graphs_dir
    DATADIR.mkdir(parents=True, exist_ok=True)

    stems = graph_stems(graphs_dir)
    paths = [graphs_dir / f"{s}_dynamic_callgraph.txt" for s in stems]

    stems_241 = load_stems_241()
    new_stems = sorted(set(stems) - stems_241)
    missing_from_356_vs_241 = sorted(stems_241 - set(stems)) if stems_241 else []

    stem_rows = [
        {
            "stem": s,
            "in_241_baseline_list": "yes" if s in stems_241 else "no",
        }
        for s in stems
    ]
    stem_rows.sort(key=lambda r: (r["in_241_baseline_list"], str(r["stem"])))
    write_csv(DATADIR / "corpus_stems.csv", stem_rows, ["stem", "in_241_baseline_list"])

    per_rows = per_graph_stats(paths, args.jobs)
    write_csv(
        DATADIR / "corpus_per_graph_method_counts.csv",
        per_rows,
        ["stem", "file_bytes", "unique_methods_in_graph", "security_relevant_methods_in_graph"],
    )

    summary: Dict[str, object] = {
        "graphs_dir": str(graphs_dir),
        "graph_count": len(stems),
        "baseline_241_stem_file": str(STEMS_241),
        "baseline_241_stem_count": len(stems_241),
        "stems_also_in_241_list": len(set(stems) & stems_241) if stems_241 else None,
        "stems_not_in_241_list": len(new_stems),
        "baseline_stems_missing_from_current_graphs": len(missing_from_356_vs_241),
    }

    if args.skip_union:
        write_json(DATADIR / "corpus_summary.json", summary)
        (DATADIR / "new_stems_not_in_241.txt").write_text("\n".join(new_stems) + ("\n" if new_stems else ""), encoding="utf-8")
        print(json.dumps(summary, indent=2))
        return

    library_prefixes = load_library_prefixes()
    print("Building union of dynamic method signatures across", len(paths), "graphs...")
    union = union_signatures_across_graphs(paths, args.jobs)

    union_path = DATADIR / "DYNAMIC_unique_methods_from_graphs.txt"
    union_path.write_text("\n".join(sorted(union)) + "\n", encoding="utf-8")

    sec_sigs = {s for s in union if is_security_relevant(s)}
    sec_nonlib = {s for s in sec_sigs if not is_library_sig(s, library_prefixes)}

    tag_counter = tag_counts(union)
    tag_rows = [{"tag": t, "dynamic_security_method_hits": c} for t, c in tag_counter.most_common()]
    write_csv(DATADIR / "corpus_security_tag_counts.csv", tag_rows, ["tag", "dynamic_security_method_hits"])

    summary.update(
        {
            "unique_methods_union": len(union),
            "security_relevant_union": len(sec_sigs),
            "security_relevant_non_library_union": len(sec_nonlib),
            "top_tags": tag_rows[:15],
            "union_signatures_file": str(union_path),
        }
    )
    write_json(DATADIR / "corpus_summary.json", summary)

    (DATADIR / "new_stems_not_in_241.txt").write_text("\n".join(new_stems) + ("\n" if new_stems else ""), encoding="utf-8")

    print(json.dumps({k: v for k, v in summary.items() if k != "top_tags"}, indent=2))
    print("Wrote:", DATADIR)


if __name__ == "__main__":
    main()
