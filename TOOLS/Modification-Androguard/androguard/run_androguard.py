import argparse
import csv
import hashlib
import shlex
import shutil
import subprocess
import sys
import tempfile
import time
import zipfile
from pathlib import Path
from typing import Optional

import psutil


def extract_base_apk_from_xapk(xapk_path: Path, temp_dir: Path) -> Optional[Path]:
    """
    Extract base APK from XAPK file.
    Heuristic: 1) file named 'base.apk' if present, 2) otherwise, the largest APK by bytes.
    Returns Path to extracted base APK, or None if extraction fails.
    """
    try:
        with zipfile.ZipFile(xapk_path, 'r') as zip_ref:
            # First, try to find base.apk
            base_apk_name = None
            for name in zip_ref.namelist():
                if name.lower() == 'base.apk' or name.endswith('/base.apk'):
                    base_apk_name = name
                    break
            
            # If base.apk not found, find all APKs and pick the largest
            if base_apk_name is None:
                apk_files = [name for name in zip_ref.namelist() 
                             if name.lower().endswith('.apk')]
                if not apk_files:
                    return None
                
                # Find the largest APK
                largest_size = 0
                for apk_name in apk_files:
                    info = zip_ref.getinfo(apk_name)
                    if info.file_size > largest_size:
                        largest_size = info.file_size
                        base_apk_name = apk_name
            
            if base_apk_name is None:
                return None
            
            # Extract the base APK to temp directory
            extracted_path = temp_dir / Path(base_apk_name).name
            with zip_ref.open(base_apk_name) as source, open(extracted_path, 'wb') as target:
                target.write(source.read())
            
            return extracted_path
    except (zipfile.BadZipFile, KeyError, OSError) as e:
        print(f"[ERROR] Failed to extract base APK from {xapk_path.name}: {e}", file=sys.stderr)
        return None


def parse_callgraph_metrics(output_file: Path) -> dict:
    """Parse call graph output file to extract metrics."""
    metrics = {
        'total_methods': 0,
        'library_methods': 0,
        'app_methods': 0,
        'total_edges': 0,
        'library_edges': 0,
        'app_edges': 0,
    }
    
    if not output_file.exists():
        return metrics
    
    try:
        with open(output_file, 'r', encoding='utf-8', errors='ignore') as f:
            content = f.read()
        
        # Collect all unique methods from edges
        methods_seen = set()
        edges = []
        
        # Parse edges - format can be: "method1 -> method2" or similar
        for line in content.split('\n'):
            line = line.strip()
            if not line or line.startswith('#'):
                continue
            
            # Look for edge patterns: " -> " or "->" or arrow-like patterns
            if ' -> ' in line or '->' in line:
                metrics['total_edges'] += 1
                # Extract caller and callee
                if ' -> ' in line:
                    parts = line.split(' -> ', 1)
                else:
                    parts = line.split('->', 1)
                
                if len(parts) == 2:
                    caller = parts[0].strip()
                    callee = parts[1].strip()
                    edges.append((caller, callee))
                    methods_seen.add(caller)
                    methods_seen.add(callee)
        
        # Count methods by type
        metrics['total_methods'] = len(methods_seen)
        for method in methods_seen:
            # Check if it's a library method (Android/Java framework)
            if (method.startswith('Landroid/') or 
                method.startswith('Ljava/') or 
                method.startswith('Ljavax/') or
                method.startswith('Lcom/android/') or
                method.startswith('Lsun/') or
                method.startswith('Lorg/apache/') or
                method.startswith('Lorg/json/') or
                method.startswith('Lorg/xml/')):
                metrics['library_methods'] += 1
            else:
                metrics['app_methods'] += 1
        
        # Count edge types
        for caller, callee in edges:
            caller_is_lib = (caller.startswith('Landroid/') or caller.startswith('Ljava/') or 
                           caller.startswith('Ljavax/') or caller.startswith('Lcom/android/') or
                           caller.startswith('Lsun/') or caller.startswith('Lorg/apache/') or
                           caller.startswith('Lorg/json/') or caller.startswith('Lorg/xml/'))
            callee_is_lib = (callee.startswith('Landroid/') or callee.startswith('Ljava/') or 
                           callee.startswith('Ljavax/') or callee.startswith('Lcom/android/') or
                           callee.startswith('Lsun/') or callee.startswith('Lorg/apache/') or
                           callee.startswith('Lorg/json/') or callee.startswith('Lorg/xml/'))
            
            if caller_is_lib or callee_is_lib:
                metrics['library_edges'] += 1
            else:
                metrics['app_edges'] += 1
                
    except Exception as e:
        pass  # Return default metrics on error
    
    return metrics


def run_callgraph(apk_path: Path, output_dir: Path, extra_args: str, verbose: bool = False, original_name: str = None) -> tuple:
    """Run androguard call graph analysis and return metrics."""
    sha256 = hashlib.sha256(apk_path.read_bytes()).hexdigest()
    size_bytes = apk_path.stat().st_size
    
    # Use original name for output file if provided (for XAPK files)
    if original_name:
        out_path = output_dir / f"{Path(original_name).stem}.txt"
    else:
        out_path = output_dir / f"{apk_path.stem}.txt"
    
    verbose_flag = "--verbose " if verbose else ""
    cmd = f"python3 -m androguard.cli.cli {verbose_flag}cg \"{apk_path}\" --output \"{out_path}\" --output-type txt {extra_args}"
    start = time.time()
    proc = subprocess.Popen(shlex.split(cmd), stdin=subprocess.DEVNULL, stdout=subprocess.PIPE, stderr=subprocess.PIPE, text=True)
    ps_proc = psutil.Process(proc.pid)
    # Warm-up cpu_percent
    ps_proc.cpu_percent(None)
    peak_rss = 0
    cpu_samples = []

    while proc.poll() is None:
        try:
            cpu_samples.append(ps_proc.cpu_percent(0.1))
            peak_rss = max(peak_rss, ps_proc.memory_info().rss)
        except (psutil.NoSuchProcess, psutil.AccessDenied):
            break
    stdout, stderr = proc.communicate()
    duration = time.time() - start
    try:
        peak_rss = max(peak_rss, ps_proc.memory_info().rss)
    except (psutil.NoSuchProcess, psutil.AccessDenied):
        pass
    avg_cpu = sum(cpu_samples) / len(cpu_samples) if cpu_samples else ps_proc.cpu_percent(None)
    stderr_clean = stderr.strip().replace("\n", " | ")
    status = "success" if proc.returncode == 0 else f"fail:{proc.returncode}"
    
    # Parse metrics from output file if successful
    metrics = parse_callgraph_metrics(out_path) if status == "success" else {}
    
    return (
        status,
        duration,
        stderr_clean,
        sha256,
        size_bytes,
        out_path,
        peak_rss,
        avg_cpu,
        metrics.get('total_methods', 0),
        metrics.get('library_methods', 0),
        metrics.get('app_methods', 0),
        metrics.get('total_edges', 0),
        metrics.get('library_edges', 0),
        metrics.get('app_edges', 0),
    )


def main():
    parser = argparse.ArgumentParser(description="Run Androguard call graph over an APK folder")
    parser.add_argument("apk_dir", type=Path, help="Root directory containing APK files")
    parser.add_argument("--output-dir", type=Path, default=Path("cg_txt"), help="Output directory for normalized graphs")
    parser.add_argument("--log", type=Path, default=Path("run_log.csv"), help="CSV log file path")
    parser.add_argument("--extra-args", type=str, default="", help="Additional flags to append to androguard cg")
    parser.add_argument("--tool", type=str, default="androguard", help="Label used in the log for the tool name")
    parser.add_argument("--verbose", action="store_true", help="Run androguard in verbose mode")
    args = parser.parse_args()

    args.output_dir.mkdir(parents=True, exist_ok=True)

    with args.log.open("w", newline="", encoding="utf-8") as csvfile:
        writer = csv.writer(csvfile)
        writer.writerow(
            [
                "apk",
                "sha256",
                "size_bytes",
                "tool",
                "runtime_s",
                "status",
                "stderr",
                "output_file",
                "peak_rss_kb",
                "avg_cpu_percent",
                "total_methods",
                "library_methods",
                "app_methods",
                "total_edges",
                "library_edges",
                "app_edges",
            ]
        )
        
        # Find both .apk and .xapk files
        apk_files = list(args.apk_dir.rglob("*.apk"))
        xapk_files = list(args.apk_dir.rglob("*.xapk"))
        all_files = sorted(apk_files + xapk_files)
        
        if not all_files:
            print(f"[WARNING] No .apk or .xapk files found in {args.apk_dir}", file=sys.stderr)
            return
        
        print(f"[INFO] Found {len(apk_files)} APK file(s) and {len(xapk_files)} XAPK file(s)", file=sys.stderr)
        print(f"[INFO] Starting analysis of {len(all_files)} file(s)...", file=sys.stderr)
        print("", file=sys.stderr)  # Blank line for readability
        
        # Create a temporary directory for XAPK extraction (reused for all XAPKs)
        temp_extract_dir = None
        
        for idx, file_path in enumerate(all_files, 1):
            original_path = file_path
            is_xapk = file_path.suffix.lower() == '.xapk'
            temp_apk_path = None
            cleanup_needed = False
            
            try:
                # Show progress
                file_type = "XAPK" if is_xapk else "APK"
                print(f"[{idx}/{len(all_files)}] Processing {file_type}: {original_path.name}", file=sys.stderr, flush=True)
                
                # If it's a XAPK, extract the base APK first
                if is_xapk:
                    if temp_extract_dir is None:
                        temp_extract_dir = Path(tempfile.mkdtemp(prefix="androguard_xapk_"))
                    
                    print(f"  -> Extracting base APK from XAPK...", file=sys.stderr, flush=True)
                    temp_apk_path = extract_base_apk_from_xapk(file_path, temp_extract_dir)
                    if temp_apk_path is None:
                        print(f"  [ERROR] Failed to extract base APK from XAPK", file=sys.stderr)
                        writer.writerow(
                            [
                                file_path.name,
                                "",
                                file_path.stat().st_size,
                                args.tool,
                                "0.00",
                                "fail:extraction_error",
                                "Failed to extract base APK from XAPK",
                                "",
                                "0",
                                "0.0",
                                "0",
                                "0",
                                "0",
                                "0",
                                "0",
                                "0",
                            ]
                        )
                        continue
                    
                    # Use the extracted base APK for analysis
                    file_path = temp_apk_path
                    cleanup_needed = True
                    print(f"  -> Extracted base APK: {temp_apk_path.name}", file=sys.stderr, flush=True)
                
                # Run analysis on the APK (either original or extracted from XAPK)
                print(f"  -> Running androguard call graph analysis...", file=sys.stderr, flush=True)
                (
                    status,
                    duration,
                    stderr,
                    sha256,
                    size_bytes,
                    out_path,
                    peak_rss,
                    avg_cpu,
                    total_methods,
                    library_methods,
                    app_methods,
                    total_edges,
                    library_edges,
                    app_edges,
                ) = run_callgraph(file_path, args.output_dir, args.extra_args, args.verbose, original_path.name if is_xapk else None)
                
                # Use original file path info for logging
                original_size = original_path.stat().st_size
                
                # Show completion status
                if status == "success":
                    print(f"  [SUCCESS] Completed in {duration:.2f}s | Methods: {total_methods} (App: {app_methods}, Lib: {library_methods}) | Edges: {total_edges}", file=sys.stderr)
                    print(f"  -> Output saved to: {out_path.name}", file=sys.stderr)
                else:
                    print(f"  [FAILED] Error: {stderr[:100]}", file=sys.stderr)
                
                writer.writerow(
                    [
                        original_path.name,
                        sha256,
                        original_size,  # Use original XAPK size, not extracted APK size
                        args.tool,
                        f"{duration:.2f}",
                        status,
                        stderr,
                        out_path.name,
                        f"{peak_rss // 1024}",
                        f"{avg_cpu:.1f}",
                        str(total_methods),
                        str(library_methods),
                        str(app_methods),
                        str(total_edges),
                        str(library_edges),
                        str(app_edges),
                    ]
                )
                print("", file=sys.stderr)  # Blank line between files
            
            finally:
                # Clean up extracted APK file if it was from XAPK
                if cleanup_needed and temp_apk_path and temp_apk_path.exists():
                    try:
                        temp_apk_path.unlink()
                    except OSError:
                        pass
        
        # Clean up temporary extraction directory
        if temp_extract_dir and temp_extract_dir.exists():
            try:
                shutil.rmtree(temp_extract_dir)
            except OSError:
                pass


if __name__ == "__main__":
    main()

