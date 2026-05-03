from __future__ import annotations

import csv
import json
from collections import defaultdict
from pathlib import Path
from typing import DefaultDict, Dict, Iterable, Iterator, List, Optional, Sequence, Set, Tuple


# Repository root (this file lives in …/scripts/security_common.py)
WORKROOT = Path(__file__).resolve().parent.parent
DATADIR = WORKROOT / "data"
DOCSDIR = WORKROOT / "docs"

RESULT_ROOT = Path("/local-storage/RESEARCH/APKPURE_ANALYSIS/APKPURE_DYNAMIC_ANALYSIS")
RESULT_GRAPHS = RESULT_ROOT / "RESULT" / "graphs"
RESULT_LOGS = RESULT_ROOT / "RESULT" / "logs"
RESULT_SUMMARY = RESULT_ROOT / "RESULT" / "summary_dynamic.csv"

# Real-app corpus: one stem per file under RESULT/graphs (356 apps). Per-tool unique
# method unions live here (from collect_unique_static_methods_241dynamic.py --outdir).
# Filenames still say "241_dynamic_apps" for historical compatibility with that script.
STATIC_CORPUS_DIR = WORKROOT / "data" / "static_unique_methods_graph_corpus"
REAL_APPS_STEMS = STATIC_CORPUS_DIR / "dynamic_stems_241.txt"
DYNAMIC_CORPUS_METHODS = WORKROOT / "data" / "corpus_from_graphs" / "DYNAMIC_unique_methods_from_graphs.txt"

# Legacy 241-only slice under the original APKPURE tree (unchanged upstream artifacts).
STATIC_241_DIR = RESULT_ROOT / "STATIC_UNIQUE_METHODS_241_DYNAMIC_APPS"

DROIDBENCH_SUMMARY = WORKROOT / "data" / "droidbench_source" / "dynamic_summary.csv"
DROIDBENCH_MISSED = WORKROOT / "data" / "droidbench_source" / "dynamic_missed_edges.csv"
DROIDBENCH_MISSED_METHODS = WORKROOT / "data" / "droidbench_source" / "droidbench_methodonly_missed_methods_all.csv"

LIBRARIES_FILE = WORKROOT / "data" / "config" / "libraries.lst"


def tool_static_unique_methods_file(tool: str) -> Path:
    """Merged unique-method list for `tool` over the current graph-corpus stems."""
    return STATIC_CORPUS_DIR / f"{tool}_unique_methods_241_dynamic_apps.txt"

TOOLS = ["ANDROGUARD", "FLOWDROID", "MAMADROID", "NATIDROID", "GATOR"]

RUNTIME_LIBRARY_PREFIXES = (
    "android.",
    "androidx.",
    "com.android.",
    "com.google.android.",
    "java.",
    "javax.",
    "jdk.",
    "sun.",
    "dalvik.",
    "libcore.",
    "org.apache.",
    "org.json.",
    "kotlin.",
    "kotlinx.",
    "j$.",
)

THIRD_PARTY_LIBRARY_PREFIXES = (
    "okhttp3.",
    "okio.",
    "retrofit2.",
    "com.bumptech.glide.",
    "com.facebook.react.",
    "com.swmansion.",
    "com.reactnativecommunity.",
    "com.learnium.",
    "app.notifee.",
    "com.baseflow.",
    "com.getcapacitor.",
    "io.flutter.",
    "dev.flutter.",
    "expo.",
    "org.unimodules.",
    "com.google.firebase.",
    "com.google.android.gms.",
    "com.google.protobuf.",
    "io.reactivex.",
    "io.netty.",
    "org.bouncycastle.",
    "com.squareup.okhttp3.",
    "com.squareup.okio.",
)

COMPONENT_SUFFIXES = (
    "Activity",
    "Service",
    "Receiver",
    "Provider",
    "Fragment",
    "WebViewClient",
    "ChromeClient",
)

LIFECYCLE_METHODS = {
    "onCreate",
    "onStart",
    "onResume",
    "onPause",
    "onStop",
    "onDestroy",
    "onNewIntent",
    "onActivityResult",
    "onRequestPermissionsResult",
    "onStartCommand",
    "onBind",
    "onRebind",
    "onUnbind",
    "onHandleIntent",
    "onReceive",
    "attachInfo",
    "query",
    "insert",
    "delete",
    "update",
    "call",
    "loadUrl",
    "shouldInterceptRequest",
    "shouldOverrideUrlLoading",
    "evaluateJavascript",
}

SECURITY_METHOD_NAMES = {
    "getDeviceId",
    "getImei",
    "getMeid",
    "getSubscriberId",
    "getLine1Number",
    "sendTextMessage",
    "sendMultipartTextMessage",
    "requestLocationUpdates",
    "getLastKnownLocation",
    "getLatitude",
    "getLongitude",
    "openCamera",
    "startRecording",
    "setJavaScriptEnabled",
    "loadUrl",
    "evaluateJavascript",
    "shouldInterceptRequest",
    "verify",
    "configureTlsExtensions",
    "exec",
    "forName",
    "loadClass",
    "bindService",
    "startService",
    "startForegroundService",
    "sendBroadcast",
    "registerReceiver",
    "query",
    "insert",
    "delete",
    "update",
    "encrypt",
    "decrypt",
    "doFinal",
}

SECURITY_PREFIX_TAGS: Sequence[Tuple[str, str]] = (
    ("android.telephony.", "telephony"),
    ("android.location.", "location"),
    ("android.accounts.", "accounts"),
    ("android.webkit.", "webview"),
    ("android.content.ContentResolver", "content_resolver"),
    ("android.provider.", "content_provider"),
    ("android.hardware.Camera", "camera"),
    ("android.hardware.camera2.", "camera"),
    ("android.media.AudioRecord", "microphone"),
    ("android.media.MediaRecorder", "microphone"),
    ("javax.net.ssl.", "tls"),
    ("java.net.", "network"),
    ("okhttp3.", "network"),
    ("okio.", "network"),
    ("java.lang.reflect.", "reflection"),
    ("java.lang.Runtime", "reflection"),
    ("java.lang.Class", "reflection"),
    ("dalvik.system.", "dynamic_loading"),
    ("javax.crypto.", "crypto"),
    ("java.security.", "crypto"),
    ("android.content.Intent", "ipc"),
    ("android.content.Context", "ipc"),
    ("android.app.Activity", "component"),
    ("android.app.Service", "component"),
    ("android.content.BroadcastReceiver", "component"),
    ("android.content.ContentProvider", "component"),
    ("com.facebook.react.", "sdk_mediated"),
    ("com.swmansion.", "sdk_mediated"),
    ("com.reactnativecommunity.", "sdk_mediated"),
    ("com.learnium.", "sdk_mediated"),
    ("app.notifee.", "sdk_mediated"),
    ("com.baseflow.", "sdk_mediated"),
    ("com.getcapacitor.", "sdk_mediated"),
    ("io.flutter.", "sdk_mediated"),
    ("dev.flutter.", "sdk_mediated"),
)


def read_csv_rows(path: Path) -> List[Dict[str, str]]:
    with path.open("r", encoding="utf-8", errors="replace", newline="") as f:
        return list(csv.DictReader(f))


def write_csv(path: Path, rows: List[Dict[str, object]], fieldnames: Sequence[str]) -> None:
    path.parent.mkdir(parents=True, exist_ok=True)
    with path.open("w", encoding="utf-8", newline="") as f:
        writer = csv.DictWriter(f, fieldnames=fieldnames)
        writer.writeheader()
        for row in rows:
            writer.writerow(row)


def write_json(path: Path, obj: object) -> None:
    path.parent.mkdir(parents=True, exist_ok=True)
    with path.open("w", encoding="utf-8") as f:
        json.dump(obj, f, indent=2, sort_keys=True)


def load_dynamic_stems() -> List[str]:
    return [
        line.strip()
        for line in REAL_APPS_STEMS.read_text(encoding="utf-8", errors="replace").splitlines()
        if line.strip()
    ]


def resolve_dynamic_graph_path(stem: str, edges_path: str) -> Path:
    """Prefer an existing file; fall back to RESULT_GRAPHS when run logs use legacy prefixes."""
    alt = RESULT_GRAPHS / f"{stem}_dynamic_callgraph.txt"
    if edges_path:
        p = Path(edges_path.strip())
        if p.is_file():
            return p
    if alt.is_file():
        return alt
    if edges_path:
        return Path(edges_path.strip())
    return alt


def resolve_dynamic_log_path(stem: str, log_path: str) -> Path:
    alt = RESULT_LOGS / f"{stem}.log"
    if log_path:
        p = Path(log_path.strip())
        if p.is_file():
            return p
    if alt.is_file():
        return alt
    if log_path:
        return Path(log_path.strip())
    return alt


def stem_from_graph_name(name: str) -> str:
    suffix = "_dynamic_callgraph.txt"
    return name[: -len(suffix)] if name.endswith(suffix) else name


def stem_from_edges_path(path_value: str) -> str:
    return stem_from_graph_name(Path(path_value).name)


def maybe_int(value: str) -> Optional[int]:
    if value is None:
        return None
    value = str(value).strip()
    if not value:
        return None
    try:
        return int(value)
    except ValueError:
        return None


def extract_class_name(sig: str) -> Optional[str]:
    s = sig.strip()
    if len(s) < 3 or not s.startswith("<") or not s.endswith(">"):
        return None
    inner = s[1:-1]
    sep = inner.find(": ")
    if sep == -1:
        return None
    class_name = inner[:sep].strip()
    return class_name or None


def extract_method_name(sig: str) -> Optional[str]:
    s = sig.strip()
    if len(s) < 3 or not s.startswith("<") or not s.endswith(">"):
        return None
    inner = s[1:-1]
    sep = inner.find(": ")
    if sep == -1:
        return None
    rest = inner[sep + 2 :]
    lp = rest.find("(")
    if lp == -1:
        return None
    head = rest[:lp].rstrip()
    if not head:
        return None
    parts = head.split()
    return parts[-1] if parts else None


def extract_class_method(sig: str) -> Optional[str]:
    class_name = extract_class_name(sig)
    method_name = extract_method_name(sig)
    if class_name is None or method_name is None:
        return None
    return f"{class_name}::{method_name}"


def load_library_prefixes() -> Set[str]:
    prefixes: Set[str] = set()
    with LIBRARIES_FILE.open("r", encoding="utf-8", errors="replace") as f:
        for line in f:
            line = line.strip()
            if line and not line.startswith("#"):
                prefixes.add(line)
    return prefixes


def is_library_class(class_name: str, library_prefixes: Set[str]) -> bool:
    class_name = class_name.replace("[]", "")
    for prefix in RUNTIME_LIBRARY_PREFIXES + THIRD_PARTY_LIBRARY_PREFIXES:
        base = prefix[:-1] if prefix.endswith(".") else prefix
        if class_name == base or class_name.startswith(prefix):
            return True
    for prefix in library_prefixes:
        if class_name == prefix or class_name.startswith(prefix + "."):
            return True
    return False


def is_library_sig(sig: str, library_prefixes: Set[str]) -> bool:
    class_name = extract_class_name(sig)
    if class_name is None:
        return False
    return is_library_class(class_name, library_prefixes)


def security_tags_from_parts(class_name: str, method_name: str) -> Set[str]:
    tags: Set[str] = set()
    for prefix, tag in SECURITY_PREFIX_TAGS:
        base = prefix[:-1] if prefix.endswith(".") else prefix
        if class_name == base or class_name.startswith(prefix):
            tags.add(tag)

    if method_name in SECURITY_METHOD_NAMES:
        tags.add("sensitive_api")

    if method_name in LIFECYCLE_METHODS:
        tags.add("entrypoint")

    if any(class_name.endswith(suffix) for suffix in COMPONENT_SUFFIXES):
        if method_name.startswith("on") or method_name in LIFECYCLE_METHODS:
            tags.add("entrypoint")
            tags.add("callback")

    if method_name.startswith("on") and class_name.startswith("android."):
        tags.add("callback")

    if method_name in {"bindService", "startService", "sendBroadcast", "registerReceiver"}:
        tags.add("ipc")

    if method_name in {"loadUrl", "evaluateJavascript", "shouldInterceptRequest", "shouldOverrideUrlLoading"}:
        tags.add("webview")

    return tags


def security_tags(sig: str) -> Set[str]:
    class_name = extract_class_name(sig)
    method_name = extract_method_name(sig)
    if class_name is None or method_name is None:
        return set()
    return security_tags_from_parts(class_name, method_name)


def is_security_relevant(sig: str) -> bool:
    return bool(security_tags(sig))


def load_signature_set(path: Path) -> Set[str]:
    out: Set[str] = set()
    with path.open("r", encoding="utf-8", errors="replace") as f:
        for line in f:
            sig = line.rstrip("\n")
            if sig:
                out.add(sig)
    return out


def iter_dynamic_edges(path: Path) -> Iterator[Tuple[str, str]]:
    with path.open("r", encoding="utf-8", errors="replace") as f:
        for line in f:
            if "-->" not in line:
                continue
            a, b = line.split("-->", 1)
            yield a.strip(), b.strip()


def iter_androguard_edges(path: Path) -> Iterator[Tuple[str, str]]:
    with path.open("r", encoding="utf-8", errors="replace") as f:
        for line in f:
            if " ==>" not in line:
                continue
            a, b = line.split("==>", 1)
            yield a.strip(), b.strip()


def iter_flowdroid_edges(path: Path) -> Iterator[Tuple[str, str]]:
    in_edges = False
    with path.open("r", encoding="utf-8", errors="replace") as f:
        for line in f:
            if not in_edges:
                if line.strip() == "Call Graph Edges":
                    in_edges = True
                continue
            if " -> " not in line or not line.strip().startswith("<"):
                continue
            a, b = line.split(" -> ", 1)
            yield a.strip(), b.strip()


def iter_soot_edges(path: Path) -> Iterator[Tuple[str, str]]:
    state = 0
    with path.open("r", encoding="utf-8", errors="replace") as f:
        for line in f:
            if state == 0:
                if line.startswith("Call Graph:"):
                    state = 1
                continue
            if " -> " not in line:
                continue
            a, b = line.split(" -> ", 1)
            yield a.strip(), b.strip()


def entry_points_from_edges(edges: Iterable[Tuple[str, str]]) -> Set[str]:
    preds: DefaultDict[str, Set[str]] = defaultdict(set)
    nodes: Set[str] = set()
    for caller, callee in edges:
        if not caller or not callee:
            continue
        nodes.add(caller)
        nodes.add(callee)
        preds[callee].add(caller)
    return {node for node in nodes if len(preds[node]) == 0}


def find_static_graph_path(stem: str, tool: str) -> Optional[Path]:
    results_root = Path("/local-storage/RESEARCH/RESULTS")
    if tool == "ANDROGUARD":
        root = results_root / "ANDROGUARD" / "ALL_APKS"
        hits = [p for p in root.rglob(f"{stem}.txt") if not p.name.endswith("-stderr.log")]
        return hits[0] if hits else None
    if tool == "FLOWDROID":
        root = results_root / "FLOWDROID" / "ALL_APKS"
        hits = [p for p in root.rglob(f"{stem}-SPARK-callgraph.txt") if not p.name.endswith("-stderr.log")]
        return hits[0] if hits else None
    if tool in {"MAMADROID", "NATIDROID", "GATOR"}:
        root = results_root / tool / "ALL_APKS"
        hits = [p for p in root.rglob(f"{stem}.txt") if not p.name.endswith("-stderr.log")]
        return hits[0] if hits else None
    raise ValueError(tool)
