#!/usr/bin/env python3
from __future__ import annotations

import argparse
from collections import defaultdict
from concurrent.futures import ProcessPoolExecutor, as_completed
from pathlib import Path
from typing import DefaultDict, Dict, List, Sequence, Set, Tuple

from security_common import (
    DATADIR,
    RESULT_ROOT,
    TOOLS,
    entry_points_from_edges,
    extract_class_method,
    extract_class_name,
    extract_method_name,
    iter_androguard_edges,
    iter_dynamic_edges,
    iter_flowdroid_edges,
    iter_soot_edges,
    is_library_sig,
    is_security_relevant,
    load_library_prefixes,
    load_signature_set,
    read_csv_rows,
    resolve_dynamic_graph_path,
    security_tags,
    write_csv,
)


CANONICAL_REAL = DATADIR / "canonical_real_apps_356.csv"
NONOBF_DYNAMIC_STRICT = RESULT_ROOT / "DYNAMIC_unique_methods_nonobf_STRICT.txt"


def set_metrics(dynamic_set: Set[str], static_set: Set[str]) -> Dict[str, object]:
    inter = dynamic_set & static_set
    d_names = {n for sig in dynamic_set if (n := extract_method_name(sig))}
    s_names = {n for sig in static_set if (n := extract_method_name(sig))}
    d_cm = {cm for sig in dynamic_set if (cm := extract_class_method(sig))}
    s_cm = {cm for sig in static_set if (cm := extract_class_method(sig))}
    return {
        "dynamic_count": len(dynamic_set),
        "static_count": len(static_set),
        "intersection_count": len(inter),
        "full_signature_coverage_pct": round(100.0 * len(inter) / len(dynamic_set), 2) if dynamic_set else 0.0,
        "dynamic_name_count": len(d_names),
        "static_hit_name_count": len(d_names & s_names),
        "name_intersection_count": len(d_names & s_names),
        "name_only_coverage_pct": round(100.0 * len(d_names & s_names) / len(d_names), 2) if d_names else 0.0,
        "dynamic_class_method_count": len(d_cm),
        "static_hit_class_method_count": len(d_cm & s_cm),
        "class_method_intersection_count": len(d_cm & s_cm),
        "class_method_coverage_pct": round(100.0 * len(d_cm & s_cm) / len(d_cm), 2) if d_cm else 0.0,
    }


def build_static_path_index(tool: str) -> Dict[str, Path]:
    root = Path("/local-storage/RESEARCH/RESULTS") / tool / "ALL_APKS"
    index: Dict[str, Path] = {}
    for path in root.rglob("*.txt"):
        if path.name.endswith("-stderr.log"):
            continue
        if tool == "FLOWDROID":
            suffix = "-SPARK-callgraph.txt"
            if not path.name.endswith(suffix):
                continue
            stem = path.name[: -len(suffix)]
        else:
            stem = path.stem
        index[stem] = path
    return index


def _entry_worker(args: Tuple[str, str]) -> Set[str]:
    path_s, kind = args
    path = Path(path_s)
    if kind == "dynamic":
        return entry_points_from_edges(iter_dynamic_edges(path))
    if kind == "androguard":
        return entry_points_from_edges(iter_androguard_edges(path))
    if kind == "flowdroid":
        return entry_points_from_edges(iter_flowdroid_edges(path))
    return entry_points_from_edges(iter_soot_edges(path))


def dynamic_entry_frequency(paths: Sequence[Path], jobs: int) -> DefaultDict[str, int]:
    freq: DefaultDict[str, int] = defaultdict(int)
    with ProcessPoolExecutor(max_workers=max(1, min(jobs, len(paths)))) as ex:
        futs = [ex.submit(_entry_worker, (str(path), "dynamic")) for path in paths]
        for fut in as_completed(futs):
            for sig in fut.result():
                freq[sig] += 1
    return freq


def union_entries(paths: Sequence[Path], kind: str, jobs: int) -> Set[str]:
    out: Set[str] = set()
    with ProcessPoolExecutor(max_workers=max(1, min(jobs, len(paths)))) as ex:
        futs = [ex.submit(_entry_worker, (str(path), kind)) for path in paths]
        for fut in as_completed(futs):
            out |= fut.result()
    return out


def main() -> None:
    ap = argparse.ArgumentParser()
    ap.add_argument("--jobs", type=int, default=12)
    args = ap.parse_args()

    library_prefixes = load_library_prefixes()
    nonobf = load_signature_set(NONOBF_DYNAMIC_STRICT)
    canonical_rows = read_csv_rows(CANONICAL_REAL)
    stems = [row["stem"] for row in canonical_rows]
    dynamic_paths = [
        resolve_dynamic_graph_path(row["stem"], row.get("dynamic_graph_path", "")) for row in canonical_rows
    ]

    dyn_freq = dynamic_entry_frequency(dynamic_paths, args.jobs)
    d_union = set(dyn_freq.keys())
    d_variants = {
        "entry_all": d_union,
        "entry_security_all": {sig for sig in d_union if is_security_relevant(sig)},
        "entry_security_nonlib": {sig for sig in d_union if is_security_relevant(sig) and not is_library_sig(sig, library_prefixes)},
        "entry_security_nonobf_strict": {sig for sig in d_union if is_security_relevant(sig) and sig in nonobf},
    }

    coverage_rows: List[Dict[str, object]] = []
    missed_rows: List[Dict[str, object]] = []
    kind_map = {
        "ANDROGUARD": "androguard",
        "FLOWDROID": "flowdroid",
        "MAMADROID": "soot",
        "NATIDROID": "soot",
        "GATOR": "soot",
    }

    for tool in TOOLS:
        index = build_static_path_index(tool)
        static_paths = [index[stem] for stem in stems if stem in index]
        s_union = union_entries(static_paths, kind_map[tool], args.jobs)
        for variant, dynamic_set in d_variants.items():
            static_set = s_union
            if variant != "entry_all":
                static_set = {sig for sig in static_set if is_security_relevant(sig)}
            if "nonlib" in variant:
                static_set = {sig for sig in static_set if not is_library_sig(sig, library_prefixes)}
            coverage_rows.append({"tool": tool, "variant": variant, **set_metrics(dynamic_set, static_set)})

        security_static = {sig for sig in s_union if is_security_relevant(sig)}
        for sig in sorted(d_variants["entry_security_all"] - security_static):
            tags = sorted(security_tags(sig))
            missed_rows.append(
                {
                    "tool": tool,
                    "signature": sig,
                    "apps_as_dynamic_entry": dyn_freq[sig],
                    "class_name": extract_class_name(sig) or "",
                    "method_name": extract_method_name(sig) or "",
                    "primary_tag": tags[0] if tags else "other",
                    "all_tags": "|".join(tags),
                    "non_library": "yes" if not is_library_sig(sig, library_prefixes) else "no",
                    "nonobf_strict": "yes" if sig in nonobf else "no",
                }
            )

    missed_rows.sort(key=lambda row: (row["tool"], -int(row["apps_as_dynamic_entry"]), row["signature"]))
    write_csv(
        DATADIR / "realapp_entrypoint_security_coverage.csv",
        coverage_rows,
        [
            "tool",
            "variant",
            "dynamic_count",
            "static_count",
            "intersection_count",
            "full_signature_coverage_pct",
            "dynamic_name_count",
            "static_hit_name_count",
            "name_intersection_count",
            "name_only_coverage_pct",
            "dynamic_class_method_count",
            "static_hit_class_method_count",
            "class_method_intersection_count",
            "class_method_coverage_pct",
        ],
    )
    write_csv(
        DATADIR / "failure_taxonomy_realapp_missed_entrypoints.csv",
        missed_rows,
        [
            "tool",
            "signature",
            "apps_as_dynamic_entry",
            "class_name",
            "method_name",
            "primary_tag",
            "all_tags",
            "non_library",
            "nonobf_strict",
        ],
    )


if __name__ == "__main__":
    main()
