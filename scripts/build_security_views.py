#!/usr/bin/env python3
from __future__ import annotations

import shlex
import subprocess
from pathlib import Path
from typing import Dict, Iterable, List, Set

from security_common import (
    DATADIR,
    DYNAMIC_CORPUS_METHODS,
    RESULT_ROOT,
    TOOLS,
    extract_class_name,
    extract_class_method,
    extract_method_name,
    is_library_sig,
    is_security_relevant,
    load_library_prefixes,
    load_signature_set,
    security_tags,
    tool_static_unique_methods_file,
    write_csv,
)


NONOBF_DYNAMIC_STRICT = RESULT_ROOT / "DYNAMIC_unique_methods_nonobf_STRICT.txt"
VIEWS = DATADIR / "method_views"


def run_count(command: str) -> int:
    out = subprocess.check_output(["bash", "-lc", command], text=True)
    return int(out.strip() or "0")


def write_sorted_lines(path: Path, values: Iterable[str]) -> None:
    path.parent.mkdir(parents=True, exist_ok=True)
    uniq = sorted(set(v for v in values if v))
    with path.open("w", encoding="utf-8") as f:
        for value in uniq:
            f.write(value + "\n")


def build_dynamic_views() -> Dict[str, Path]:
    library_prefixes = load_library_prefixes()
    dynamic_methods = load_signature_set(DYNAMIC_CORPUS_METHODS)
    nonobf = load_signature_set(NONOBF_DYNAMIC_STRICT)

    variants: Dict[str, Set[str]] = {
        "overall": dynamic_methods,
        "security_all": {sig for sig in dynamic_methods if is_security_relevant(sig)},
        "security_nonlib": {
            sig for sig in dynamic_methods if is_security_relevant(sig) and not is_library_sig(sig, library_prefixes)
        },
        "security_nonobf_strict": {sig for sig in dynamic_methods if is_security_relevant(sig) and sig in nonobf},
        "security_nonlib_nonobf_strict": {
            sig
            for sig in dynamic_methods
            if is_security_relevant(sig) and sig in nonobf and not is_library_sig(sig, library_prefixes)
        },
    }

    out: Dict[str, Path] = {}
    for variant, sigs in variants.items():
        sig_path = VIEWS / f"dynamic_{variant}.txt"
        write_sorted_lines(sig_path, sigs)
        out[f"{variant}_sig"] = sig_path
        write_sorted_lines(VIEWS / f"dynamic_{variant}_names.txt", (extract_method_name(sig) or "" for sig in sigs))
        write_sorted_lines(VIEWS / f"dynamic_{variant}_class_method.txt", (extract_class_method(sig) or "" for sig in sigs))
        out[f"{variant}_name"] = VIEWS / f"dynamic_{variant}_names.txt"
        out[f"{variant}_cm"] = VIEWS / f"dynamic_{variant}_class_method.txt"

    tag_map: Dict[str, Set[str]] = {}
    for sig in variants["security_all"]:
        for tag in security_tags(sig):
            tag_map.setdefault(tag, set()).add(sig)
    for tag, sigs in tag_map.items():
        write_sorted_lines(VIEWS / f"dynamic_tag_{tag}.txt", sigs)
    return out


def build_tool_name_views(tool: str) -> Dict[str, Path]:
    tool_file = tool_static_unique_methods_file(tool)
    name_file = VIEWS / f"{tool.lower()}_names.txt"
    cm_file = VIEWS / f"{tool.lower()}_class_method.txt"
    names: Set[str] = set()
    cms: Set[str] = set()
    with tool_file.open("r", encoding="utf-8", errors="replace") as f:
        for line in f:
            sig = line.rstrip("\n")
            if not sig:
                continue
            name = extract_method_name(sig)
            if name:
                names.add(name)
            cm = extract_class_method(sig)
            if cm:
                cms.add(cm)
    write_sorted_lines(name_file, names)
    write_sorted_lines(cm_file, cms)
    return {"sig": tool_file, "name": name_file, "cm": cm_file}


def comm_count(left: Path, right: Path) -> int:
    cmd = f"comm -12 {shlex.quote(str(left))} {shlex.quote(str(right))} | wc -l"
    return run_count(cmd)


def build_method_tables() -> None:
    views = build_dynamic_views()
    coverage_rows: List[Dict[str, object]] = []
    inflation_rows: List[Dict[str, object]] = []
    breakdown_rows: List[Dict[str, object]] = []
    failure_rows: List[Dict[str, object]] = []

    dynamic_security_count = run_count(f"wc -l < {shlex.quote(str(views['security_all_sig']))}")

    for tool in TOOLS:
        tool_views = build_tool_name_views(tool)
        static_total = run_count(f"wc -l < {shlex.quote(str(tool_views['sig']))}")

        for variant in ("overall", "security_all", "security_nonlib", "security_nonobf_strict", "security_nonlib_nonobf_strict"):
            d_sig = views[f"{variant}_sig"]
            d_name = views[f"{variant}_name"]
            d_cm = views[f"{variant}_cm"]
            dynamic_count = run_count(f"wc -l < {shlex.quote(str(d_sig))}")
            dynamic_name_count = run_count(f"wc -l < {shlex.quote(str(d_name))}")
            dynamic_cm_count = run_count(f"wc -l < {shlex.quote(str(d_cm))}")
            inter_sig = comm_count(d_sig, tool_views["sig"])
            inter_name = comm_count(d_name, tool_views["name"])
            inter_cm = comm_count(d_cm, tool_views["cm"])
            coverage_rows.append(
                {
                    "tool": tool,
                    "variant": variant,
                    "dynamic_count": dynamic_count,
                    "static_total_count": static_total,
                    "intersection_count": inter_sig,
                    "full_signature_coverage_pct": round(100.0 * inter_sig / dynamic_count, 2) if dynamic_count else 0.0,
                    "dynamic_name_count": dynamic_name_count,
                    "static_hit_name_count": inter_name,
                    "name_intersection_count": inter_name,
                    "name_only_coverage_pct": round(100.0 * inter_name / dynamic_name_count, 2) if dynamic_name_count else 0.0,
                    "dynamic_class_method_count": dynamic_cm_count,
                    "static_hit_class_method_count": inter_cm,
                    "class_method_intersection_count": inter_cm,
                    "class_method_coverage_pct": round(100.0 * inter_cm / dynamic_cm_count, 2) if dynamic_cm_count else 0.0,
                }
            )

        security_hits = comm_count(views["security_all_sig"], tool_views["sig"])
        inflation_rows.append(
            {
                "tool": tool,
                "static_total_methods": static_total,
                "dynamic_total_methods": run_count(f"wc -l < {shlex.quote(str(views['overall_sig']))}"),
                "dynamic_security_methods": dynamic_security_count,
                "matched_dynamic_security_methods": security_hits,
                "inflation_ratio_total": round(static_total / run_count(f"wc -l < {shlex.quote(str(views['overall_sig']))}"), 3),
                "security_hit_ratio": round(security_hits / dynamic_security_count, 3) if dynamic_security_count else 0.0,
            }
        )

        for tag_file in sorted(VIEWS.glob("dynamic_tag_*.txt")):
            tag = tag_file.stem.replace("dynamic_tag_", "")
            dynamic_count = run_count(f"wc -l < {shlex.quote(str(tag_file))}")
            inter = comm_count(tag_file, tool_views["sig"])
            breakdown_rows.append(
                {
                    "tool": tool,
                    "tag": tag,
                    "dynamic_count": dynamic_count,
                    "static_total_count": static_total,
                    "intersection_count": inter,
                    "full_signature_coverage_pct": round(100.0 * inter / dynamic_count, 2) if dynamic_count else 0.0,
                }
            )

        missed_file = VIEWS / f"{tool.lower()}_missed_security.txt"
        subprocess.run(
            [
                "bash",
                "-lc",
                f"comm -23 {shlex.quote(str(views['security_all_sig']))} {shlex.quote(str(tool_views['sig']))} > {shlex.quote(str(missed_file))}",
            ],
            check=True,
        )
        with missed_file.open("r", encoding="utf-8", errors="replace") as f:
            for line in f:
                sig = line.rstrip("\n")
                if not sig:
                    continue
                tags = sorted(security_tags(sig))
                failure_rows.append(
                    {
                        "tool": tool,
                        "signature": sig,
                        "class_name": extract_class_name(sig) or "",
                        "method_name": extract_method_name(sig) or "",
                        "primary_tag": tags[0] if tags else "other",
                        "all_tags": "|".join(tags),
                    }
                )

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
    write_csv(
        DATADIR / "realapp_method_security_tag_breakdown.csv",
        breakdown_rows,
        ["tool", "tag", "dynamic_count", "static_total_count", "intersection_count", "full_signature_coverage_pct"],
    )
    write_csv(
        DATADIR / "failure_taxonomy_realapp_missed_methods.csv",
        failure_rows,
        ["tool", "signature", "class_name", "method_name", "primary_tag", "all_tags"],
    )


if __name__ == "__main__":
    VIEWS.mkdir(parents=True, exist_ok=True)
    build_method_tables()
