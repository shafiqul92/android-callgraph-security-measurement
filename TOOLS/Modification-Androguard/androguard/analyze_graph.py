#!/usr/bin/env python3
"""
analyze_graph.py

Compute per-APK metrics from normalized call-graph edge lists produced by e.g. androguard:
    <src> ==> <tgt>

Supports:
- Node/edge counts (unique)
- ICC/reflection heuristics (string-based)
- Callback heuristics:
  (A) lifecycle method-name hits (works with graph only)
  (B) FlowDroid-style callback TYPE list (e.g., AndroidCallbacks.txt / callback.txt)
      If --apk-dir is provided, we parse the APK to detect app classes implementing those
      callback interfaces, and then count how many graph nodes/edges touch those classes.

Usage examples:
  # graph-only metrics:
  python3 analyze_graph.py graphs/ --output metrics.csv

  # use callback type list + APK parsing:
  python3 analyze_graph.py graphs/ --apk-dir apks/ --callback-types callback.txt --output metrics.csv
"""

import argparse
import csv
from pathlib import Path
from typing import Dict, Iterable, Optional, Set, Tuple

# --- Graph-only (string) heuristics ------------------------------------------

DEFAULT_LIFECYCLE_METHODS = {
    # Activity lifecycle
    "onCreate", "onStart", "onResume", "onPause", "onStop", "onDestroy",
    "onRestart", "onNewIntent", "onSaveInstanceState", "onTrimMemory",
    # BroadcastReceiver / Service-ish common names
    "onReceive", "onBind", "onStartCommand",
}

DEFAULT_ICC_APIS = {
    "startActivity", "startActivityForResult",
    "startService", "startForegroundService",
    "sendBroadcast", "sendOrderedBroadcast",
    "bindService",
}

# Reflection: keep this intentionally broad but not crazy.
DEFAULT_REFLECTION_KEYWORDS = {
    "java.lang.reflect.", "kotlin.reflect.",
    "Class.forName", ".forName(",
    ".invoke(", "Method.invoke",
    ".newInstance(", "Constructor.newInstance",
}

EDGE_SEP = " ==> "


# --- Helpers: name normalization ---------------------------------------------

def _descriptor_to_dotted(name: str) -> str:
    """
    Convert a Dalvik descriptor or internal name into dotted form.
    Examples:
      Landroid/view/View$OnClickListener; -> android.view.View$OnClickListener
      android/view/View$OnClickListener   -> android.view.View$OnClickListener
      com.example.Foo                    -> com.example.Foo  (unchanged)
    """
    s = name.strip()
    if s.startswith("L") and s.endswith(";") and len(s) > 2:
        s = s[1:-1]
    s = s.replace("/", ".")
    return s


def _extract_declaring_class(method_str: str) -> Optional[str]:
    """
    Try to extract declaring class from a node string.
    Handles common forms:
      Lcom/foo/Bar;->baz(I)V
      com.foo.Bar.baz(I)V
      com.foo.Bar:baz(I)V
    Returns dotted class name, or None if unknown.
    """
    s = method_str.strip()

    if "->" in s:
        cls = s.split("->", 1)[0].strip()
        return _descriptor_to_dotted(cls)

    # Try common Java-ish forms
    if "(" in s:
        head = s.split("(", 1)[0]
        if ":" in head:
            head = head.split(":", 1)[0]
        if "." in head:
            # last '.' separates class and method
            cls = head.rsplit(".", 1)[0]
            return _descriptor_to_dotted(cls)

    return None


# --- Callback types file (FlowDroid-style) -----------------------------------

def load_callback_types(path: Path) -> Set[str]:
    """
    Load callback *types* (interfaces/classes) from a file like FlowDroid's AndroidCallbacks.txt.
    One fully-qualified type per line. Lines can include $ for nested classes.
    Ignores blank lines and lines starting with '#'.
    """
    types: Set[str] = set()
    with path.open("r", encoding="utf-8", errors="replace") as fp:
        for line in fp:
            line = line.strip()
            if not line or line.startswith("#"):
                continue
            types.add(line)
    return types


# --- APK parsing (optional) ---------------------------------------------------

def build_apk_index(apk_dir: Path) -> Dict[str, Path]:
    """
    Build a stem->path index for *.apk and *.xapk found under apk_dir (recursive).
    If duplicates exist, first one wins (stable enough for your pipeline).
    """
    index: Dict[str, Path] = {}
    for ext in ("*.apk", "*.xapk"):
        for p in apk_dir.rglob(ext):
            index.setdefault(p.stem, p)
    return index


def compute_callback_classes_from_apk(
    apk_path: Path,
    callback_types: Set[str],
) -> Set[str]:
    """
    Return a set of dotted class names (from the APK) that:
      - directly implement one of callback_types, OR
      - inherit (via app-to-app superclass chain) from a class that implements one of callback_types.

    Note: we can’t traverse Android framework class/interface hierarchies because they are not
    inside the APK dex. So this focuses on what the APK itself declares.
    """
    try:
        from androguard.core.bytecodes.apk import APK
        from androguard.core.bytecodes.dvm import DalvikVMFormat
    except Exception:
        raise RuntimeError(
            "Androguard Python package not available. Install it or run without --apk-dir."
        )

    a = APK(str(apk_path))

    class_supertypes: Dict[str, Set[str]] = {}

    for dex_bytes in a.get_all_dex():
        try:
            d = DalvikVMFormat(dex_bytes)
        except Exception:
            continue

        for c in d.get_classes():
            cls = _descriptor_to_dotted(c.get_name())
            supers: Set[str] = set()

            sc = c.get_superclassname()
            if sc:
                supers.add(_descriptor_to_dotted(sc))

            for itf in c.get_interfaces() or []:
                supers.add(_descriptor_to_dotted(itf))

            class_supertypes.setdefault(cls, set()).update(supers)

    # Memoized DFS over *APK-local* inheritance only
    memo: Dict[str, bool] = {}

    def is_callback_class(cls: str, stack: Set[str]) -> bool:
        if cls in memo:
            return memo[cls]
        if cls in stack:
            memo[cls] = False
            return False
        stack.add(cls)

        supers = class_supertypes.get(cls, set())
        if any(st in callback_types for st in supers):
            memo[cls] = True
        else:
            # only recurse into supertypes that exist in the APK
            memo[cls] = any(
                is_callback_class(st, stack) for st in supers if st in class_supertypes
            )

        stack.remove(cls)
        return memo[cls]

    callback_classes: Set[str] = set()
    for cls in class_supertypes.keys():
        if is_callback_class(cls, set()):
            callback_classes.add(cls)

    return callback_classes


# --- Graph parsing / metrics --------------------------------------------------

def parse_graph(
    graph_path: Path,
    callback_classes: Optional[Set[str]] = None,
) -> Dict[str, int]:
    nodes: Set[str] = set()
    edges: Set[Tuple[str, str]] = set()

    lifecycle_nodes = 0
    icc_edges = 0
    reflection_edges = 0

    callback_class_nodes = 0
    callback_class_edges = 0

    parse_errors = 0

    # To avoid double-counting lifecycle_nodes on duplicates:
    lifecycle_node_set: Set[str] = set()
    callback_class_node_set: Set[str] = set()

    with graph_path.open("r", encoding="utf-8", errors="replace") as fp:
        for line in fp:
            line = line.strip()
            if not line:
                continue

            parts = line.split(EDGE_SEP)
            if len(parts) != 2:
                parse_errors += 1
                continue

            src, tgt = parts[0].strip(), parts[1].strip()
            nodes.add(src)
            nodes.add(tgt)

            e = (src, tgt)
            if e in edges:
                continue
            edges.add(e)

            # --- heuristics on endpoints (string-based) ---
            if any(m in src or m in tgt for m in DEFAULT_LIFECYCLE_METHODS):
                if src not in lifecycle_node_set:
                    if any(m in src for m in DEFAULT_LIFECYCLE_METHODS):
                        lifecycle_node_set.add(src)
                if tgt not in lifecycle_node_set:
                    if any(m in tgt for m in DEFAULT_LIFECYCLE_METHODS):
                        lifecycle_node_set.add(tgt)

            if any(api in src or api in tgt for api in DEFAULT_ICC_APIS):
                icc_edges += 1

            if any(k in src or k in tgt for k in DEFAULT_REFLECTION_KEYWORDS):
                reflection_edges += 1

            # --- callback class metrics (needs APK-derived callback_classes) ---
            if callback_classes:
                src_cls = _extract_declaring_class(src)
                tgt_cls = _extract_declaring_class(tgt)

                src_is_cb = (src_cls in callback_classes) if src_cls else False
                tgt_is_cb = (tgt_cls in callback_classes) if tgt_cls else False

                if src_is_cb and src not in callback_class_node_set:
                    callback_class_node_set.add(src)
                if tgt_is_cb and tgt not in callback_class_node_set:
                    callback_class_node_set.add(tgt)

                if src_is_cb or tgt_is_cb:
                    callback_class_edges += 1

    lifecycle_nodes = len(lifecycle_node_set)
    callback_class_nodes = len(callback_class_node_set)

    return {
        "nodes": len(nodes),
        "edges": len(edges),
        "lifecycle_nodes": lifecycle_nodes,
        "icc_edges": icc_edges,
        "reflection_edges": reflection_edges,
        "callback_class_nodes": callback_class_nodes,
        "callback_class_edges": callback_class_edges,
        "parse_errors": parse_errors,
    }


def main() -> None:
    p = argparse.ArgumentParser(description="Compute per-APK metrics from txt call graphs")
    p.add_argument("graphs_dir", type=Path, help="Directory containing *.txt call graphs")
    p.add_argument("--output", type=Path, default=Path("graph_metrics.csv"), help="CSV output path")

    # FlowDroid-style callback types (interfaces/classes)
    p.add_argument(
        "--callback-types",
        type=Path,
        default=None,
        help="Path to callback type list (e.g., FlowDroid AndroidCallbacks.txt / your callback.txt)",
    )

    # Optional APK parsing to map callback types -> app callback classes
    p.add_argument(
        "--apk-dir",
        type=Path,
        default=None,
        help="Directory containing APK/XAPK files (matched by stem to graph filename)",
    )

    args = p.parse_args()

    callback_types: Set[str] = set()
    if args.callback_types:
        callback_types = load_callback_types(args.callback_types)

    apk_index: Dict[str, Path] = {}
    if args.apk_dir:
        apk_index = build_apk_index(args.apk_dir)

    rows = []
    for graph_path in sorted(args.graphs_dir.glob("*.txt")):
        apk_name = graph_path.stem

        callback_classes: Optional[Set[str]] = None
        if args.apk_dir and callback_types:
            apk_path = apk_index.get(apk_name)
            if apk_path and apk_path.exists():
                try:
                    callback_classes = compute_callback_classes_from_apk(apk_path, callback_types)
                except Exception:
                    callback_classes = None  # fallback to graph-only metrics

        stats = parse_graph(graph_path, callback_classes=callback_classes)
        rows.append({"apk": apk_name, **stats})

    fieldnames = [
        "apk",
        "nodes", "edges",
        "lifecycle_nodes",
        "icc_edges", "reflection_edges",
        "callback_class_nodes", "callback_class_edges",
        "parse_errors",
    ]

    with args.output.open("w", newline="", encoding="utf-8") as fp:
        w = csv.DictWriter(fp, fieldnames=fieldnames)
        w.writeheader()
        for r in rows:
            w.writerow(r)


if __name__ == "__main__":
    main()
