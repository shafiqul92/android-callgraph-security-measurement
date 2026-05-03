#!/usr/bin/env python3
from __future__ import annotations

import argparse
import statistics
from collections import Counter, defaultdict
from concurrent.futures import ProcessPoolExecutor, as_completed
from pathlib import Path
from typing import DefaultDict, Dict, Iterable, List, Optional, Sequence, Set, Tuple

from security_common import (
    DATADIR,
    DOCSDIR,
    DROIDBENCH_MISSED,
    DYNAMIC_CORPUS_METHODS,
    RESULT_ROOT,
    THIRD_PARTY_LIBRARY_PREFIXES,
    TOOLS,
    RUNTIME_LIBRARY_PREFIXES,
    SECURITY_METHOD_NAMES,
    SECURITY_PREFIX_TAGS,
    COMPONENT_SUFFIXES,
    LIFECYCLE_METHODS,
    extract_class_method,
    extract_class_name,
    extract_method_name,
    entry_points_from_edges,
    find_static_graph_path,
    is_library_sig,
    is_security_relevant,
    iter_androguard_edges,
    iter_dynamic_edges,
    iter_flowdroid_edges,
    iter_soot_edges,
    load_dynamic_stems,
    load_library_prefixes,
    load_signature_set,
    read_csv_rows,
    resolve_dynamic_graph_path,
    security_tags,
    security_tags_from_parts,
    tool_static_unique_methods_file,
    write_csv,
    write_json,
)


NONOBF_DYNAMIC_STRICT = RESULT_ROOT / "DYNAMIC_unique_methods_nonobf_STRICT.txt"
CANONICAL_REAL = DATADIR / "canonical_real_apps_356.csv"
CANONICAL_DROIDBENCH = DATADIR / "canonical_droidbench_summary.csv"

PRIMARY_TAG_ORDER = [
    "telephony",
    "location",
    "accounts",
    "webview",
    "tls",
    "network",
    "content_provider",
    "content_resolver",
    "ipc",
    "component",
    "callback",
    "reflection",
    "dynamic_loading",
    "crypto",
    "sdk_mediated",
    "sensitive_api",
    "entrypoint",
]

METHOD_DYNAMIC_CONTEXT: Dict[str, Dict[str, Set[str]]] = {}
METHOD_DYNAMIC_TAG_CONTEXT: Dict[str, Dict[str, Set[str]]] = {}
METHOD_DYNAMIC_SIG_TO_TAGS: Dict[str, Set[str]] = {}
METHOD_DYNAMIC_NAME_TO_TAGS: DefaultDict[str, Set[str]] = defaultdict(set)
METHOD_DYNAMIC_CM_TO_TAGS: DefaultDict[str, Set[str]] = defaultdict(set)
METHOD_LIBRARY_PREFIXES: Set[str] = set()


def set_metrics(dynamic_set: Set[str], static_set: Set[str]) -> Dict[str, object]:
    inter = dynamic_set & static_set
    cov = 100.0 * len(inter) / len(dynamic_set) if dynamic_set else 0.0

    d_names = {name for sig in dynamic_set if (name := extract_method_name(sig))}
    s_names = {name for sig in static_set if (name := extract_method_name(sig))}
    name_inter = d_names & s_names
    name_cov = 100.0 * len(name_inter) / len(d_names) if d_names else 0.0

    d_cm = {key for sig in dynamic_set if (key := extract_class_method(sig))}
    s_cm = {key for sig in static_set if (key := extract_class_method(sig))}
    cm_inter = d_cm & s_cm
    cm_cov = 100.0 * len(cm_inter) / len(d_cm) if d_cm else 0.0

    return {
        "dynamic_count": len(dynamic_set),
        "static_count": len(static_set),
        "intersection_count": len(inter),
        "full_signature_coverage_pct": round(cov, 2),
        "dynamic_name_count": len(d_names),
        "static_name_count": len(s_names),
        "name_intersection_count": len(name_inter),
        "name_only_coverage_pct": round(name_cov, 2),
        "dynamic_class_method_count": len(d_cm),
        "static_class_method_count": len(s_cm),
        "class_method_intersection_count": len(cm_inter),
        "class_method_coverage_pct": round(cm_cov, 2),
    }


def primary_tag(tags: Iterable[str]) -> str:
    tag_set = set(tags)
    for tag in PRIMARY_TAG_ORDER:
        if tag in tag_set:
            return tag
    return "other"


def export_taxonomy_snapshot() -> None:
    snapshot = {
        "runtime_library_prefixes": list(RUNTIME_LIBRARY_PREFIXES),
        "third_party_library_prefixes": list(THIRD_PARTY_LIBRARY_PREFIXES),
        "component_suffixes": list(COMPONENT_SUFFIXES),
        "lifecycle_methods": sorted(LIFECYCLE_METHODS),
        "security_method_names": sorted(SECURITY_METHOD_NAMES),
        "security_prefix_tags": [{"prefix": prefix, "tag": tag} for prefix, tag in SECURITY_PREFIX_TAGS],
    }
    write_json(DATADIR / "security_taxonomy_snapshot.json", snapshot)


def load_tool_method_sets() -> Dict[str, Set[str]]:
    out: Dict[str, Set[str]] = {"DYNAMIC": load_signature_set(DYNAMIC_CORPUS_METHODS)}
    for tool in TOOLS:
        out[tool] = load_signature_set(tool_static_unique_methods_file(tool))
    return out


def build_dynamic_variants(dynamic_methods: Set[str], library_prefixes: Set[str], dynamic_nonobf: Set[str]) -> Dict[str, Set[str]]:
    variants = {
        "overall": dynamic_methods,
        "security_all": {sig for sig in dynamic_methods if is_security_relevant(sig)},
        "security_nonlib": {
            sig
            for sig in dynamic_methods
            if is_security_relevant(sig) and not is_library_sig(sig, library_prefixes)
        },
        "security_nonobf_strict": {sig for sig in dynamic_methods if is_security_relevant(sig) and sig in dynamic_nonobf},
        "security_nonlib_nonobf_strict": {
            sig
            for sig in dynamic_methods
            if is_security_relevant(sig) and sig in dynamic_nonobf and not is_library_sig(sig, library_prefixes)
        },
    }
    return variants


def build_dynamic_context(
    dynamic_methods: Set[str],
    library_prefixes: Set[str],
    dynamic_nonobf: Set[str],
) -> Tuple[Dict[str, Dict[str, Set[str]]], Dict[str, Dict[str, Set[str]]]]:
    variants = build_dynamic_variants(dynamic_methods, library_prefixes, dynamic_nonobf)
    context: Dict[str, Dict[str, Set[str]]] = {}
    for variant_name, sigs in variants.items():
        context[variant_name] = {
            "sigs": sigs,
            "names": {name for sig in sigs if (name := extract_method_name(sig))},
            "cms": {cm for sig in sigs if (cm := extract_class_method(sig))},
        }

    tag_context: Dict[str, Dict[str, Set[str]]] = {}
    for sig in variants["security_all"]:
        for tag in security_tags(sig):
            bucket = tag_context.setdefault(tag, {"sigs": set(), "names": set(), "cms": set()})
            bucket["sigs"].add(sig)
            name = extract_method_name(sig)
            if name:
                bucket["names"].add(name)
            cm = extract_class_method(sig)
            if cm:
                bucket["cms"].add(cm)
    return context, tag_context


def filter_static_variant(
    signatures: Set[str],
    variant_name: str,
    library_prefixes: Set[str],
) -> Set[str]:
    filtered = signatures
    if variant_name != "overall":
        filtered = {sig for sig in filtered if is_security_relevant(sig)}
    if "nonlib" in variant_name:
        filtered = {sig for sig in filtered if not is_library_sig(sig, library_prefixes)}
    return filtered


def _scan_tool_method_file(tool: str) -> Tuple[List[Dict[str, object]], List[Dict[str, object]], Dict[str, object], Set[str]]:
    """Intersect dynamic variant sets with the merged static unique-signature set (one load)."""
    tool_path = tool_static_unique_methods_file(tool)
    variant_names = list(METHOD_DYNAMIC_CONTEXT.keys())
    print(f"[{tool}] loading static unique methods: {tool_path}", flush=True)
    static_set = load_signature_set(tool_path)
    static_total_count = len(static_set)

    static_names: Set[str] = set()
    static_cms: Set[str] = set()
    for sig in static_set:
        n = extract_method_name(sig)
        if n:
            static_names.add(n)
        cm = extract_class_method(sig)
        if cm:
            static_cms.add(cm)

    seen_sig_hits: Dict[str, Set[str]] = {}
    seen_name_hits: Dict[str, Set[str]] = {}
    seen_cm_hits: Dict[str, Set[str]] = {}
    for variant in variant_names:
        dyn = METHOD_DYNAMIC_CONTEXT[variant]
        seen_sig_hits[variant] = dyn["sigs"] & static_set
        seen_name_hits[variant] = dyn["names"] & static_names
        seen_cm_hits[variant] = dyn["cms"] & static_cms

    tag_sig_hits = {tag: METHOD_DYNAMIC_TAG_CONTEXT[tag]["sigs"] & static_set for tag in METHOD_DYNAMIC_TAG_CONTEXT}
    tag_name_hits: Dict[str, Set[str]] = {tag: set() for tag in METHOD_DYNAMIC_TAG_CONTEXT}
    tag_cm_hits: Dict[str, Set[str]] = {tag: set() for tag in METHOD_DYNAMIC_TAG_CONTEXT}
    for name in static_names:
        tags = METHOD_DYNAMIC_NAME_TO_TAGS.get(name)
        if not tags:
            continue
        for tag in tags:
            tag_name_hits[tag].add(name)
    for cm in static_cms:
        tags = METHOD_DYNAMIC_CM_TO_TAGS.get(cm)
        if not tags:
            continue
        for tag in tags:
            tag_cm_hits[tag].add(cm)

    missed_security = set(METHOD_DYNAMIC_CONTEXT["security_all"]["sigs"] - seen_sig_hits["security_all"])

    coverage_rows: List[Dict[str, object]] = []
    for variant in variant_names:
        dyn = METHOD_DYNAMIC_CONTEXT[variant]
        sig_inter = len(seen_sig_hits[variant])
        cov = 100.0 * sig_inter / len(dyn["sigs"]) if dyn["sigs"] else 0.0
        name_inter = len(seen_name_hits[variant])
        name_cov = 100.0 * name_inter / len(dyn["names"]) if dyn["names"] else 0.0
        cm_inter = len(seen_cm_hits[variant])
        cm_cov = 100.0 * cm_inter / len(dyn["cms"]) if dyn["cms"] else 0.0
        coverage_rows.append(
            {
                "tool": tool,
                "variant": variant,
                "dynamic_count": len(dyn["sigs"]),
                "static_total_count": static_total_count,
                "intersection_count": sig_inter,
                "full_signature_coverage_pct": round(cov, 2),
                "dynamic_name_count": len(dyn["names"]),
                "static_hit_name_count": name_inter,
                "name_intersection_count": name_inter,
                "name_only_coverage_pct": round(name_cov, 2),
                "dynamic_class_method_count": len(dyn["cms"]),
                "static_hit_class_method_count": cm_inter,
                "class_method_intersection_count": cm_inter,
                "class_method_coverage_pct": round(cm_cov, 2),
            }
        )

    breakdown_rows: List[Dict[str, object]] = []
    for tag, dyn in sorted(METHOD_DYNAMIC_TAG_CONTEXT.items()):
        name_inter = len(tag_name_hits[tag])
        cm_inter = len(tag_cm_hits[tag])
        breakdown_rows.append(
            {
                "tool": tool,
                "tag": tag,
                "dynamic_count": len(dyn["sigs"]),
                "static_total_count": static_total_count,
                "intersection_count": len(tag_sig_hits[tag]),
                "full_signature_coverage_pct": round(100.0 * len(tag_sig_hits[tag]) / len(dyn["sigs"]), 2) if dyn["sigs"] else 0.0,
                "dynamic_name_count": len(dyn["names"]),
                "static_hit_name_count": name_inter,
                "name_intersection_count": name_inter,
                "name_only_coverage_pct": round(100.0 * name_inter / len(dyn["names"]), 2) if dyn["names"] else 0.0,
                "dynamic_class_method_count": len(dyn["cms"]),
                "static_hit_class_method_count": cm_inter,
                "class_method_intersection_count": cm_inter,
                "class_method_coverage_pct": round(100.0 * cm_inter / len(dyn["cms"]), 2) if dyn["cms"] else 0.0,
            }
        )

    sec_dynamic = METHOD_DYNAMIC_CONTEXT["security_all"]["sigs"]
    inflation_row = {
        "tool": tool,
        "static_total_methods": static_total_count,
        "dynamic_total_methods": len(METHOD_DYNAMIC_CONTEXT["overall"]["sigs"]),
        "dynamic_security_methods": len(sec_dynamic),
        "matched_dynamic_security_methods": len(seen_sig_hits["security_all"]),
        "inflation_ratio_total": round(static_total_count / len(METHOD_DYNAMIC_CONTEXT["overall"]["sigs"]), 3),
        "security_hit_ratio": round(len(seen_sig_hits["security_all"]) / len(sec_dynamic), 3) if sec_dynamic else 0.0,
    }

    return coverage_rows, breakdown_rows, inflation_row, missed_security


def compute_method_coverage(
    library_prefixes: Set[str],
    dynamic_nonobf: Set[str],
) -> Tuple[List[Dict[str, object]], List[Dict[str, object]], List[Dict[str, object]], Dict[str, Set[str]]]:
    global METHOD_DYNAMIC_CONTEXT
    global METHOD_DYNAMIC_TAG_CONTEXT
    global METHOD_DYNAMIC_SIG_TO_TAGS
    global METHOD_DYNAMIC_NAME_TO_TAGS
    global METHOD_DYNAMIC_CM_TO_TAGS
    global METHOD_LIBRARY_PREFIXES

    dynamic_methods = load_signature_set(DYNAMIC_CORPUS_METHODS)
    dynamic_context, dynamic_tag_context = build_dynamic_context(dynamic_methods, library_prefixes, dynamic_nonobf)
    dynamic_sig_to_tags: Dict[str, Set[str]] = {}
    dynamic_name_to_tags: DefaultDict[str, Set[str]] = defaultdict(set)
    dynamic_cm_to_tags: DefaultDict[str, Set[str]] = defaultdict(set)
    for tag, ctx in dynamic_tag_context.items():
        for sig in ctx["sigs"]:
            dynamic_sig_to_tags.setdefault(sig, set()).add(tag)
        for name in ctx["names"]:
            dynamic_name_to_tags[name].add(tag)
        for cm in ctx["cms"]:
            dynamic_cm_to_tags[cm].add(tag)

    coverage_rows: List[Dict[str, object]] = []
    breakdown_rows: List[Dict[str, object]] = []
    inflation_rows: List[Dict[str, object]] = []
    missed_security_by_tool: Dict[str, Set[str]] = {}
    METHOD_DYNAMIC_CONTEXT = dynamic_context
    METHOD_DYNAMIC_TAG_CONTEXT = dynamic_tag_context
    METHOD_DYNAMIC_SIG_TO_TAGS = dynamic_sig_to_tags
    METHOD_DYNAMIC_NAME_TO_TAGS = dynamic_name_to_tags
    METHOD_DYNAMIC_CM_TO_TAGS = dynamic_cm_to_tags
    METHOD_LIBRARY_PREFIXES = library_prefixes

    # Sequential per tool to cap peak RAM (each tool loads a full static signature set).
    for tool in TOOLS:
        tool_cov, tool_breakdown, tool_inflation, tool_missed = _scan_tool_method_file(tool)
        coverage_rows.extend(tool_cov)
        breakdown_rows.extend(tool_breakdown)
        inflation_rows.append(tool_inflation)
        missed_security_by_tool[tool] = tool_missed

    write_csv(
        DATADIR / "realapp_method_security_coverage.csv",
        coverage_rows,
        [
            "tool",
            "variant",
            "dynamic_count",
            "static_total_count",
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
        DATADIR / "realapp_method_security_tag_breakdown.csv",
        breakdown_rows,
        [
            "tool",
            "tag",
            "dynamic_count",
            "static_total_count",
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
        DATADIR / "realapp_security_inflation_summary.csv",
        inflation_rows,
        [
            "tool",
            "static_total_methods",
            "dynamic_total_methods",
            "dynamic_security_methods",
            "matched_dynamic_security_methods",
            "inflation_ratio_total",
            "security_hit_ratio",
        ],
    )
    return coverage_rows, breakdown_rows, inflation_rows, missed_security_by_tool


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


def _dynamic_entry_freq(paths: Sequence[Path], jobs: int) -> DefaultDict[str, int]:
    freq: DefaultDict[str, int] = defaultdict(int)
    tasks = [(str(p), "dynamic") for p in paths]
    with ProcessPoolExecutor(max_workers=max(1, min(jobs, len(tasks)))) as ex:
        futs = [ex.submit(_entry_worker, task) for task in tasks]
        for fut in as_completed(futs):
            for sig in fut.result():
                freq[sig] += 1
    return freq


def _union_entries(paths: Sequence[Path], kind: str, jobs: int) -> Set[str]:
    out: Set[str] = set()
    tasks = [(str(p), kind) for p in paths]
    if not tasks:
        return out
    with ProcessPoolExecutor(max_workers=max(1, min(jobs, len(tasks)))) as ex:
        futs = [ex.submit(_entry_worker, task) for task in tasks]
        for fut in as_completed(futs):
            out |= fut.result()
    return out


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


def compute_entrypoint_coverage(
    library_prefixes: Set[str],
    nonobf_dynamic: Set[str],
    jobs: int,
) -> Tuple[List[Dict[str, object]], List[Dict[str, object]]]:
    canonical_rows = read_csv_rows(CANONICAL_REAL)
    dynamic_paths = [
        resolve_dynamic_graph_path(row["stem"], row.get("dynamic_graph_path", ""))
        for row in canonical_rows
        if row.get("stem")
    ]
    stems = [row["stem"] for row in canonical_rows]

    dyn_freq = _dynamic_entry_freq(dynamic_paths, jobs)
    d_union = set(dyn_freq.keys())
    d_variants = {
        "entry_all": d_union,
        "entry_security_all": {sig for sig in d_union if is_security_relevant(sig)},
        "entry_security_nonlib": {sig for sig in d_union if is_security_relevant(sig) and not is_library_sig(sig, library_prefixes)},
        "entry_security_nonobf_strict": {sig for sig in d_union if is_security_relevant(sig) and sig in nonobf_dynamic},
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
        s_union = _union_entries(static_paths, kind_map[tool], jobs)
        for variant_name, dynamic_set in d_variants.items():
            static_set = s_union
            if variant_name != "entry_all":
                static_set = {sig for sig in static_set if is_security_relevant(sig)}
            if "nonlib" in variant_name:
                static_set = {sig for sig in static_set if not is_library_sig(sig, library_prefixes)}
            metrics = set_metrics(dynamic_set, static_set)
            coverage_rows.append({"tool": tool, "variant": variant_name, **metrics})

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
                    "primary_tag": primary_tag(tags),
                    "all_tags": "|".join(tags),
                    "non_library": "yes" if not is_library_sig(sig, library_prefixes) else "no",
                    "nonobf_strict": "yes" if sig in nonobf_dynamic else "no",
                }
            )

    missed_rows.sort(key=lambda r: (r["tool"], -int(r["apps_as_dynamic_entry"]), str(r["signature"])))
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
            "static_name_count",
            "name_intersection_count",
            "name_only_coverage_pct",
            "dynamic_class_method_count",
            "static_class_method_count",
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
    return coverage_rows, missed_rows


def compute_transfer_gap(method_rows: List[Dict[str, object]], entry_rows: List[Dict[str, object]]) -> Tuple[List[Dict[str, object]], List[Dict[str, object]]]:
    benchmark_rows = read_csv_rows(CANONICAL_DROIDBENCH)

    by_tool_cov: DefaultDict[str, List[float]] = defaultdict(list)
    by_category_tool_cov: DefaultDict[Tuple[str, str], List[float]] = defaultdict(list)
    for row in benchmark_rows:
        cov_text = row.get("coverage", "")
        if not cov_text:
            continue
        cov = float(cov_text) * 100.0 if float(cov_text) <= 1.0 else float(cov_text)
        by_tool_cov[row["tool"].upper()].append(cov)
        by_category_tool_cov[(row["category"], row["tool"].upper())].append(cov)

    bench_summary: List[Dict[str, object]] = []
    for tool in TOOLS:
        values = by_tool_cov[tool]
        bench_summary.append(
            {
                "tool": tool,
                "benchmark_mean_coverage_pct": round(statistics.mean(values), 2),
                "benchmark_median_coverage_pct": round(statistics.median(values), 2),
                "benchmark_num_rows": len(values),
                "benchmark_perfect_count": sum(1 for v in values if abs(v - 100.0) < 1e-9),
            }
        )

    category_rows: List[Dict[str, object]] = []
    for (category, tool), values in sorted(by_category_tool_cov.items()):
        category_rows.append(
            {
                "category": category,
                "tool": tool,
                "mean_coverage_pct": round(statistics.mean(values), 2),
                "median_coverage_pct": round(statistics.median(values), 2),
                "rows": len(values),
            }
        )

    method_map = {
        (row["tool"], row["variant"]): row
        for row in method_rows
    }
    entry_map = {
        (row["tool"], row["variant"]): row
        for row in entry_rows
    }

    merged: List[Dict[str, object]] = []
    for row in bench_summary:
        tool = row["tool"]
        sec_method = method_map[(tool, "security_all")]
        sec_entry = entry_map[(tool, "entry_security_all")]
        merged.append(
            {
                **row,
                "realapp_security_method_full_cov_pct": sec_method["full_signature_coverage_pct"],
                "realapp_security_entry_full_cov_pct": sec_entry["full_signature_coverage_pct"],
            }
        )

    bench_rank = {row["tool"]: idx + 1 for idx, row in enumerate(sorted(merged, key=lambda r: (-float(r["benchmark_mean_coverage_pct"]), r["tool"])))}
    method_rank = {row["tool"]: idx + 1 for idx, row in enumerate(sorted(merged, key=lambda r: (-float(r["realapp_security_method_full_cov_pct"]), r["tool"])))}
    entry_rank = {row["tool"]: idx + 1 for idx, row in enumerate(sorted(merged, key=lambda r: (-float(r["realapp_security_entry_full_cov_pct"]), r["tool"])))}

    transfer_rows: List[Dict[str, object]] = []
    for row in merged:
        tool = row["tool"]
        transfer_rows.append(
            {
                **row,
                "benchmark_rank": bench_rank[tool],
                "realapp_security_method_rank": method_rank[tool],
                "realapp_security_entry_rank": entry_rank[tool],
                "method_rank_shift": method_rank[tool] - bench_rank[tool],
                "entry_rank_shift": entry_rank[tool] - bench_rank[tool],
            }
        )

    write_csv(
        DATADIR / "benchmark_tool_overall.csv",
        bench_summary,
        [
            "tool",
            "benchmark_mean_coverage_pct",
            "benchmark_median_coverage_pct",
            "benchmark_num_rows",
            "benchmark_perfect_count",
        ],
    )
    write_csv(
        DATADIR / "benchmark_category_coverage.csv",
        category_rows,
        ["category", "tool", "mean_coverage_pct", "median_coverage_pct", "rows"],
    )
    write_csv(
        DATADIR / "benchmark_to_reality_transfer_gap.csv",
        transfer_rows,
        [
            "tool",
            "benchmark_mean_coverage_pct",
            "benchmark_median_coverage_pct",
            "benchmark_num_rows",
            "benchmark_perfect_count",
            "realapp_security_method_full_cov_pct",
            "realapp_security_entry_full_cov_pct",
            "benchmark_rank",
            "realapp_security_method_rank",
            "realapp_security_entry_rank",
            "method_rank_shift",
            "entry_rank_shift",
        ],
    )
    return category_rows, transfer_rows


def compute_failure_taxonomy(
    missed_security_by_tool: Dict[str, Set[str]],
    missed_entry_rows: List[Dict[str, object]],
    library_prefixes: Set[str],
    nonobf_dynamic: Set[str],
) -> Tuple[List[Dict[str, object]], List[Dict[str, object]], List[Dict[str, object]]]:
    droid_rows = read_csv_rows(DROIDBENCH_MISSED)
    tagged_droidbench: List[Dict[str, object]] = []
    summary_counter: DefaultDict[Tuple[str, str], int] = defaultdict(int)

    for row in droid_rows:
        class_name = row.get("callee_receiver", "")
        method_name = row.get("callee_method", "")
        tags = sorted(security_tags_from_parts(class_name, method_name))
        ptag = primary_tag(tags)
        summary_counter[(row.get("tool", "").upper(), ptag)] += 1
        tagged_droidbench.append(
            {
                "category": row.get("category", ""),
                "benchmark": row.get("benchmark", ""),
                "tool": row.get("tool", "").upper(),
                "caller_class": row.get("caller_class", ""),
                "caller_method": row.get("caller_method", ""),
                "callee_receiver": class_name,
                "callee_method": method_name,
                "primary_tag": ptag,
                "all_tags": "|".join(tags),
            }
        )

    droid_summary_rows = [
        {"tool": tool, "primary_tag": tag, "count": count}
        for (tool, tag), count in sorted(summary_counter.items(), key=lambda item: (item[0][0], -item[1], item[0][1]))
    ]

    missed_method_rows: List[Dict[str, object]] = []
    for tool in TOOLS:
        for sig in sorted(missed_security_by_tool[tool]):
            tags = sorted(security_tags(sig))
            missed_method_rows.append(
                {
                    "tool": tool,
                    "signature": sig,
                    "class_name": extract_class_name(sig) or "",
                    "method_name": extract_method_name(sig) or "",
                    "primary_tag": primary_tag(tags),
                    "all_tags": "|".join(tags),
                    "non_library": "yes" if not is_library_sig(sig, library_prefixes) else "no",
                    "nonobf_strict": "yes" if sig in nonobf_dynamic else "no",
                }
            )

    write_csv(
        DATADIR / "failure_taxonomy_droidbench_missed_edges.csv",
        tagged_droidbench,
        [
            "category",
            "benchmark",
            "tool",
            "caller_class",
            "caller_method",
            "callee_receiver",
            "callee_method",
            "primary_tag",
            "all_tags",
        ],
    )
    write_csv(
        DATADIR / "failure_taxonomy_droidbench_summary.csv",
        droid_summary_rows,
        ["tool", "primary_tag", "count"],
    )
    write_csv(
        DATADIR / "failure_taxonomy_realapp_missed_methods.csv",
        missed_method_rows,
        ["tool", "signature", "class_name", "method_name", "primary_tag", "all_tags", "non_library", "nonobf_strict"],
    )

    lines = [
        "# Failure Taxonomy",
        "",
        "This note is derived-only and leaves the original result dataset unchanged.",
        "",
        "## DroidBench Missed-Edge Taxonomy",
        "",
    ]
    for tool in TOOLS:
        tool_rows = [row for row in droid_summary_rows if row["tool"] == tool]
        top = tool_rows[:5]
        lines.append(f"### {tool}")
        if not top:
            lines.append("- No missed-edge rows tagged for this tool.")
        else:
            for row in top:
                lines.append(f"- `{row['primary_tag']}`: {row['count']} missed edges")
        lines.append("")

    lines.extend(
        [
            "## Real-App Missed Security Entry Points",
            "",
            "Representative high-frequency missed dynamic security entrypoints:",
            "",
        ]
    )
    by_tool_entries: DefaultDict[str, List[Dict[str, object]]] = defaultdict(list)
    for row in missed_entry_rows:
        by_tool_entries[str(row["tool"])].append(row)
    for tool in TOOLS:
        lines.append(f"### {tool}")
        for row in by_tool_entries[tool][:5]:
            lines.append(
                f"- `{row['primary_tag']}` in {row['apps_as_dynamic_entry']} apps: `{row['signature']}`"
            )
        lines.append("")

    path = DOCSDIR / "failure_taxonomy.md"
    path.parent.mkdir(parents=True, exist_ok=True)
    path.write_text("\n".join(lines) + "\n", encoding="utf-8")
    return tagged_droidbench, droid_summary_rows, missed_method_rows


def write_paper_outline(
    method_rows: List[Dict[str, object]],
    entry_rows: List[Dict[str, object]],
    transfer_rows: List[Dict[str, object]],
    inflation_rows: List[Dict[str, object]],
) -> None:
    sec_methods = [row for row in method_rows if row["variant"] == "security_all"]
    sec_entries = [row for row in entry_rows if row["variant"] == "entry_security_all"]
    best_method = max(sec_methods, key=lambda row: float(row["full_signature_coverage_pct"]))
    best_entry = max(sec_entries, key=lambda row: float(row["full_signature_coverage_pct"]))
    largest_shift = max(transfer_rows, key=lambda row: abs(int(row["method_rank_shift"])))
    most_inflated = max(inflation_rows, key=lambda row: float(row["inflation_ratio_total"]))

    lines = [
        "# CCS Security Measurement Narrative Bundle",
        "",
        "## Candidate Titles",
        "",
        "1. Security-Critical Coverage Gaps in Android Static Call Graphs",
        "2. Benchmark Success Does Not Transfer: A Security Measurement of Android Static Call-Graph Tools",
        "3. Inflated Yet Unsound: Measuring Security-Relevant Runtime Coverage in Android Call Graph Analysis",
        "",
        "## Thesis",
        "",
        "Popular Android static call-graph tools are an unreliable substrate for downstream security analyses because benchmark coverage does not transfer to real executed behavior, and graph inflation often hides failures on security-relevant methods and entrypoints.",
        "",
        "## Key Numbers To Lead With",
        "",
        f"- Best real-app security-method full-signature coverage: `{best_method['tool']}` at `{best_method['full_signature_coverage_pct']}%`.",
        f"- Best real-app security-entry full-signature coverage: `{best_entry['tool']}` at `{best_entry['full_signature_coverage_pct']}%`.",
        f"- Largest benchmark-to-reality method-rank shift: `{largest_shift['tool']}` moved by `{largest_shift['method_rank_shift']}` rank positions.",
        f"- Largest total-method inflation ratio: `{most_inflated['tool']}` at `{most_inflated['inflation_ratio_total']}`x dynamic union size.",
        "",
        "## Recommended Contributions",
        "",
        "- A large-scale security-oriented comparison of Android static call-graph tools against executed real-app behavior.",
        "- Evidence that DroidBench-style benchmark rankings do not transfer cleanly to real security-relevant runtime behavior.",
        "- Quantification of the tension between graph inflation and security-relevant recall, including library-filtered and non-obfuscated slices.",
        "- A failure taxonomy showing which missed behaviors matter most for privacy, malware, and reachability analyses.",
        "",
        "## Figure Mapping",
        "",
        f"- Figure 1 pipeline: use `docs/dataset_definition.md` and `data/security_taxonomy_snapshot.json`.",
        f"- Figure 2 benchmark vs real-app ranking: use `data/benchmark_to_reality_transfer_gap.csv`.",
        f"- Figure 3 security-relevant real-app coverage: use `data/realapp_method_security_coverage.csv` and `data/realapp_entrypoint_security_coverage.csv`.",
        f"- Figure 4 inflation vs recall: use `data/realapp_security_inflation_summary.csv`.",
        f"- Figure 5 failure taxonomy: use `docs/failure_taxonomy.md`, `data/failure_taxonomy_droidbench_summary.csv`, and `data/failure_taxonomy_realapp_missed_entrypoints.csv`.",
        "",
        "## Writing Order",
        "",
        "1. Motivation and threat model for downstream security analyses.",
        "2. Dataset definition and measurement caveats.",
        "3. Security taxonomy and slicing methodology.",
        "4. Real-app coverage results.",
        "5. Benchmark transfer-gap results.",
        "6. Failure taxonomy and case studies.",
        "7. Implications for privacy, malware, and vulnerability reachability.",
        "",
        "## Strong Caveats To Keep",
        "",
        "- Dynamic traces capture executed behavior under the current harness, not full app behavior.",
        "- The paper measures analysis substrate quality, not end-to-end privacy leak detection or malware detection accuracy.",
        "- Third-party SDK/library labeling is heuristic and should be reported as such.",
    ]

    path = DOCSDIR / "paper_outline.md"
    path.parent.mkdir(parents=True, exist_ok=True)
    path.write_text("\n".join(lines) + "\n", encoding="utf-8")


def main() -> None:
    ap = argparse.ArgumentParser()
    ap.add_argument("--jobs", type=int, default=12)
    args = ap.parse_args()

    export_taxonomy_snapshot()
    library_prefixes = load_library_prefixes()
    nonobf_dynamic = load_signature_set(NONOBF_DYNAMIC_STRICT)
    method_rows, breakdown_rows, inflation_rows, missed_security_by_tool = compute_method_coverage(
        library_prefixes,
        nonobf_dynamic,
    )
    entry_rows, missed_entry_rows = compute_entrypoint_coverage(library_prefixes, nonobf_dynamic, args.jobs)
    category_rows, transfer_rows = compute_transfer_gap(method_rows, entry_rows)
    compute_failure_taxonomy(missed_security_by_tool, missed_entry_rows, library_prefixes, nonobf_dynamic)
    write_paper_outline(method_rows, entry_rows, transfer_rows, inflation_rows)


if __name__ == "__main__":
    main()
