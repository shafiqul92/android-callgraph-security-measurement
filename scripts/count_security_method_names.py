#!/usr/bin/env python3
"""Count simple method names among security-relevant signatures across all tool corpora."""
from __future__ import annotations

from collections import Counter
from typing import Optional

from security_common import (
    COMPONENT_SUFFIXES,
    LIFECYCLE_METHODS,
    SECURITY_METHOD_NAMES,
    SECURITY_PREFIX_TAGS,
    TOOLS,
    tool_static_unique_methods_file,
)


def _parse_sig(sig: str) -> tuple[Optional[str], Optional[str]]:
    s = sig.strip()
    if len(s) < 3 or not s.startswith("<") or not s.endswith(">"):
        return None, None
    inner = s[1:-1]
    sep = inner.find(": ")
    if sep == -1:
        return None, None
    class_name = inner[:sep].strip()
    rest = inner[sep + 2 :]
    lp = rest.find("(")
    if lp == -1:
        return class_name, None
    head = rest[:lp].rstrip()
    if not head:
        return class_name, None
    parts = head.split()
    method_name = parts[-1] if parts else None
    return class_name, method_name


def _security_relevant_fast(class_name: str, method_name: str) -> bool:
    """Mirror of security_tags_from_parts without allocating a set."""
    if not class_name or not method_name:
        return False
    for prefix, _tag in SECURITY_PREFIX_TAGS:
        base = prefix[:-1] if prefix.endswith(".") else prefix
        if class_name == base or class_name.startswith(prefix):
            return True
    if method_name in SECURITY_METHOD_NAMES:
        return True
    if method_name in LIFECYCLE_METHODS:
        return True
    if any(class_name.endswith(suffix) for suffix in COMPONENT_SUFFIXES):
        if method_name.startswith("on") or method_name in LIFECYCLE_METHODS:
            return True
    if method_name.startswith("on") and class_name.startswith("android."):
        return True
    if method_name in {
        "bindService",
        "startService",
        "sendBroadcast",
        "registerReceiver",
    }:
        return True
    if method_name in {
        "loadUrl",
        "evaluateJavascript",
        "shouldInterceptRequest",
        "shouldOverrideUrlLoading",
    }:
        return True
    return False


def main() -> None:
    # One scan: summed rows per tool + union counts (first time we see a sig).
    cnt_sum: Counter[str] = Counter()
    cnt_union: Counter[str] = Counter()
    seen: set[str] = set()
    total_lines = 0
    total_sec_rows = 0
    for tool in TOOLS:
        path = tool_static_unique_methods_file(tool)
        if not path.exists():
            print(f"missing {path}")
            continue
        with path.open("r", encoding="utf-8", errors="replace") as f:
            for line in f:
                total_lines += 1
                sig = line.rstrip("\n")
                if not sig:
                    continue
                c, m = _parse_sig(sig)
                if c is None or m is None:
                    continue
                if not _security_relevant_fast(c, m):
                    continue
                total_sec_rows += 1
                cnt_sum[m] += 1
                if sig not in seen:
                    seen.add(sig)
                    cnt_union[m] += 1

    print("=== Summed across five tool corpora (multi-count if same sig in multiple tools) ===")
    print(f"lines_read\t{total_lines}")
    print(f"security_relevant_rows\t{total_sec_rows}")
    print("rank\tcount\tmethod_name")
    for i, (name, c) in enumerate(cnt_sum.most_common(10), 1):
        print(f"{i}\t{c}\t{name}")

    print()
    print("=== Union of unique signatures (each Soot sig counted once) ===")
    print(f"unique_security_sigs\t{len(seen)}")
    print("rank\tcount\tmethod_name")
    for i, (name, c) in enumerate(cnt_union.most_common(10), 1):
        print(f"{i}\t{c}\t{name}")


if __name__ == "__main__":
    main()
