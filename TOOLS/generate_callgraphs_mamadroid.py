#!/usr/bin/env python3
"""
Script to generate callgraphs for APKs using MamaDroid tool.
Supports both DroidBench benchmark APKs and APKPure APKs.
Logs runtime duration, CPU usage, and memory usage for each APK processed.
"""

import os
import sys
import subprocess
import time
import psutil
import json
import threading
import argparse
import shutil
import shlex
from pathlib import Path
from datetime import datetime

# Default paths
_DEFAULT_ROOT = "/local-storage/RESEARCH"
DEFAULT_JAR_PATH = (
    f"{_DEFAULT_ROOT}/TOOLS/MAMADROID/target/"
    "experiments-callgraphsoundness-1.0-jar-with-dependencies.jar"
)
DEFAULT_PLATFORMS = f"{_DEFAULT_ROOT}/Android-platforms/jars/stubs"

# Configuration for different datasets
DATASETS = {
    'apkpure': {
        'input_folder': f"{_DEFAULT_ROOT}/APK/communication",
        'output_folder': f"{_DEFAULT_ROOT}/RESULTS/MAMADROID/ALL_APKS/communication",
        'log_file': f"{_DEFAULT_ROOT}/RESULTS/MAMADROID/all_apks_log.json",
        'recursive': False,  # APKs are in flat folder
    },
    'droidbench': {
        'input_folder': f"{_DEFAULT_ROOT}/DroidBench/apk",
        'output_folder': f"{_DEFAULT_ROOT}/RESULTS/MAMADROID/DROIDBENCH",
        'log_file': f"{_DEFAULT_ROOT}/RESULTS/MAMADROID/droidbench_processing_log.json",
        'recursive': True,  # APKs are in category subfolders
    }
}

def get_resource_usage(process):
    """CPU and RSS memory for the Java process (raw psutil CPU %, same as FlowDroid/Gator)."""
    try:
        cpu_percent = process.cpu_percent(interval=0.1)
        memory_info = process.memory_info()
        memory_mb = memory_info.rss / (1024 * 1024)  # Convert to MB
        return cpu_percent, memory_mb
    except (psutil.NoSuchProcess, psutil.AccessDenied):
        return 0.0, 0.0

def analyze_callgraph(output_file):
    """Analyze the callgraph file to count edges and unique methods."""
    edges_count = 0
    methods_set = set()
    
    if not os.path.exists(output_file):
        return {'edges': 0, 'methods': 0}
    
    try:
        with open(output_file, 'r', encoding='utf-8', errors='ignore') as f:
            in_callgraph_section = False
            for line in f:
                line = line.strip()
                if not line:
                    continue
                
                if line.startswith('Call Graph:'):
                    in_callgraph_section = True
                    continue
                
                if in_callgraph_section and '->' in line:
                    edges_count += 1
                    parts = line.split('->', 1)
                    if len(parts) == 2:
                        source_method = parts[0].strip()
                        target_method = parts[1].strip()
                        if source_method:
                            methods_set.add(source_method)
                        if target_method:
                            methods_set.add(target_method)
    
    except Exception as e:
        print(f"Warning: Could not analyze callgraph file: {e}")
        return {'edges': 0, 'methods': 0}
    
    return {
        'edges': edges_count,
        'methods': len(methods_set)
    }

def monitor_process_thread(psutil_process, subprocess_popen, cpu_samples, memory_samples, log_interval=1.0):
    """Monitor a process in a background thread and collect resource usage metrics."""
    while subprocess_popen.poll() is None:
        try:
            if psutil_process.is_running():
                cpu, memory = get_resource_usage(psutil_process)
                cpu_samples.append(cpu)
                memory_samples.append(memory)
        except (psutil.NoSuchProcess, psutil.AccessDenied):
            break
        time.sleep(log_interval)
    
    # Get final metrics if process still exists
    try:
        if psutil_process.is_running():
            final_cpu, final_memory = get_resource_usage(psutil_process)
            if final_cpu > 0 or final_memory > 0:
                cpu_samples.append(final_cpu)
                memory_samples.append(final_memory)
    except (psutil.NoSuchProcess, psutil.AccessDenied):
        pass

def process_apk(apk_path, output_file, jar_path, platforms_path, java_opts="-Xmx32g", category=None):
    """Process a single APK file and generate callgraph using MamaDroid."""
    apk_name = os.path.basename(apk_path)
    apk_base_name = os.path.splitext(apk_name)[0]
    output_folder = os.path.dirname(output_file)
    apk_abs = os.path.abspath(apk_path)
    jar_abs = os.path.abspath(jar_path)
    plat_abs = os.path.abspath(platforms_path)
    stderr_log_path = os.path.join(output_folder, f"{apk_base_name}-stderr.log")
    
    print(f"\n{'='*80}")
    if category:
        print(f"Category: {category}")
    print(f"Processing: {apk_name}")
    print(f"Output: {output_file}")
    print(f"{'='*80}")
    
    # Create output directory if needed
    os.makedirs(output_folder, exist_ok=True)
    
    # Build java command for MamaDroid
    # `java_opts` may contain multiple args (e.g., "-Xmx32g -XX:+UseG1GC").
    java_opts_list = shlex.split(java_opts) if java_opts else []
    cmd = [
        "java",
        *java_opts_list,
        "-jar", jar_abs,
        "-a", apk_abs,
        "-p", plat_abs,
        "-j", plat_abs,
        "-t", "mamadroid"
    ]
    
    # Record start time
    start_time = time.time()
    start_datetime = datetime.now().isoformat()
    
    try:
        # Run mamadroid command with cwd set to output folder so the tool writes there
        mamadroid_process = subprocess.Popen(
            cmd,
            stdout=subprocess.PIPE,
            stderr=subprocess.PIPE,
            text=True,
            cwd=output_folder
        )
        
        # Get psutil Process object for monitoring
        resource_metrics = {}
        cpu_samples = []
        memory_samples = []
        
        try:
            psutil_process = psutil.Process(mamadroid_process.pid)
            # Start monitoring thread
            monitor_thread = threading.Thread(
                target=monitor_process_thread,
                args=(psutil_process, mamadroid_process, cpu_samples, memory_samples),
                daemon=True
            )
            monitor_thread.start()
        except (psutil.NoSuchProcess, psutil.AccessDenied) as e:
            print(f"Warning: Could not monitor process resources: {e}")
        
        # Wait for completion
        stdout, stderr = mamadroid_process.communicate()
        try:
            with open(stderr_log_path, "w", encoding="utf-8", errors="replace") as sf:
                sf.write(stderr or "")
        except OSError as e:
            print(f"Warning: could not write stderr log {stderr_log_path}: {e}")
        
        # Wait for monitoring thread to finish
        if 'monitor_thread' in locals():
            monitor_thread.join(timeout=2.0)
        
        # Calculate resource metrics
        if cpu_samples or memory_samples:
            avg_cpu = sum(cpu_samples) / len(cpu_samples) if cpu_samples else 0.0
            max_cpu = max(cpu_samples) if cpu_samples else 0.0
            avg_memory = sum(memory_samples) / len(memory_samples) if memory_samples else 0.0
            max_memory = max(memory_samples) if memory_samples else 0.0
            
            resource_metrics = {
                'avg_cpu_percent': round(avg_cpu, 2),
                'max_cpu_percent': round(max_cpu, 2),
                'avg_memory_mb': round(avg_memory, 2),
                'max_memory_mb': round(max_memory, 2)
            }
        
        # Calculate duration
        end_time = time.time()
        duration_seconds = end_time - start_time
        duration_minutes = duration_seconds / 60
        
        # DataCollector may write (1) "<basename>.apk-SPARK-callgraph.txt" in cwd (output_folder), or
        # (2) legacy "<fullApkPath>-SPARK-callgraph.txt" next to the APK.
        spark_in_cwd = os.path.join(output_folder, f"{apk_name}-SPARK-callgraph.txt")
        spark_next_apk = f"{apk_abs}-SPARK-callgraph.txt"
        for src in (spark_in_cwd, spark_next_apk):
            if os.path.exists(src) and os.path.normpath(src) != os.path.normpath(output_file):
                try:
                    shutil.move(src, output_file)
                    break
                except OSError as e:
                    try:
                        shutil.copy2(src, output_file)
                        os.remove(src)
                        break
                    except OSError:
                        print(f"Warning: could not move/copy callgraph to output path: {e}")

        # Check if successful
        success = mamadroid_process.returncode == 0 and os.path.exists(output_file)
        
        if success:
            print(f"✓ Successfully processed {apk_name}")
        else:
            print(f"✗ Failed to process {apk_name}")
            if stderr:
                print(f"Error: {stderr[:500]}")
        
        # Analyze callgraph if successful
        callgraph_stats = {'edges': 0, 'methods': 0}
        output_size_mb = 0
        if success and os.path.exists(output_file):
            callgraph_stats = analyze_callgraph(output_file)
            output_size_mb = os.path.getsize(output_file) / (1024 * 1024)
        
        result = {
            'tool_name': 'MamaDroid',
            'apk_name': apk_name,
            'apk_path': apk_path,
            'category': category,
            'output_file': output_file,
            'stderr_log_path': stderr_log_path,
            'start_time': start_datetime,
            'end_time': datetime.now().isoformat(),
            'duration_seconds': round(duration_seconds, 2),
            'duration_minutes': round(duration_minutes, 2),
            'success': success,
            'return_code': mamadroid_process.returncode,
            'resource_usage': resource_metrics,
            'output_file_size_mb': round(output_size_mb, 2),
            'callgraph_stats': callgraph_stats
        }
        
        return result
        
    except Exception as e:
        end_time = time.time()
        duration_seconds = end_time - start_time
        
        print(f"✗ Exception while processing {apk_name}: {str(e)}")
        
        result = {
            'tool_name': 'MamaDroid',
            'apk_name': apk_name,
            'apk_path': apk_path,
            'category': category,
            'output_file': output_file,
            'stderr_log_path': os.path.join(output_folder, f"{apk_base_name}-stderr.log"),
            'start_time': start_datetime,
            'end_time': datetime.now().isoformat(),
            'duration_seconds': round(duration_seconds, 2),
            'duration_minutes': round(duration_seconds / 60, 2),
            'success': False,
            'error': str(e),
            'resource_usage': {},
            'callgraph_stats': {'edges': 0, 'methods': 0}
        }
        
        return result

def find_apks(input_folder, recursive=False):
    """Find all APK files in the input folder.
    
    Returns list of tuples: (apk_path, category)
    For non-recursive, category is None.
    For recursive, category is derived from the first path component under input_folder
    (useful for simple breakdown stats), but output structure is preserved separately.
    """
    apk_files = []
    input_folder = os.path.abspath(input_folder)
    
    if recursive:
        # Generic recursive walk (works for /local-storage/RESEARCH/APK/* trees)
        for root, _, files in os.walk(input_folder):
            files = sorted(files)
            for file in files:
                if not file.endswith(".apk"):
                    continue
                apk_path = os.path.abspath(os.path.join(root, file))
                rel_parent = os.path.relpath(os.path.dirname(apk_path), input_folder)
                if rel_parent == ".":
                    category = None
                else:
                    category = rel_parent.split(os.sep, 1)[0] or None
                apk_files.append((apk_path, category))
    else:
        # Flat folder with APKs
        for file in sorted(os.listdir(input_folder)):
            if file.endswith('.apk'):
                apk_path = os.path.abspath(os.path.join(input_folder, file))
                apk_files.append((apk_path, None))
    
    return apk_files

def _check_java_version():
    """
    FlowDroid 2.15.x requires Java 17+. Fail fast with a clear error if the
    system default `java` is older.
    """
    try:
        p = subprocess.run(["java", "-version"], capture_output=True, text=True)
    except FileNotFoundError:
        print("Error: `java` not found on PATH")
        sys.exit(1)

    out = (p.stderr or "") + (p.stdout or "")
    major = None

    # Common formats:
    # - openjdk version "17.0.15" ...
    # - java version "1.8.0_..." ...
    for token in out.split():
        if token.startswith('"') and token.endswith('"') and len(token) >= 3:
            ver = token.strip('"')
            try:
                if ver.startswith("1."):
                    major = int(ver.split(".", 2)[1])
                else:
                    major = int(ver.split(".", 1)[0])
            except Exception:
                major = None
            if major is not None:
                break

    if major is None:
        print("Warning: could not parse `java -version` output; continuing.")
        return

    if major < 17:
        print(f"Error: Java {major} detected, but FlowDroid 2.15.x requires Java 17+. Please use Java 17 and retry.")
        sys.exit(1)

def main():
    parser = argparse.ArgumentParser(
        description='Generate callgraphs for APKs using MamaDroid tool',
        formatter_class=argparse.RawDescriptionHelpFormatter,
        epilog="""
Examples:
  # Run on DroidBench APKs
  python3 generate_callgraphs_mamadroid.py --dataset droidbench
  
  # Run on APKPure APKs
  python3 generate_callgraphs_mamadroid.py --dataset apkpure
  
  # Run only a specific DroidBench category
  python3 generate_callgraphs_mamadroid.py --dataset droidbench --category Callbacks
  
  # Run on custom folder
  python3 generate_callgraphs_mamadroid.py --input-dir /path/to/apks --output-dir /path/to/output
"""
    )
    parser.add_argument('--dataset', '-d', choices=['apkpure', 'droidbench'],
                        help='Dataset to process (apkpure or droidbench)')
    parser.add_argument('--input-dir', '-i', help='Custom input directory with APKs')
    parser.add_argument('--output-dir', '-o', help='Custom output directory for callgraphs')
    parser.add_argument('--log-file', '-l', help='Custom log file path')
    parser.add_argument('--jar', default=DEFAULT_JAR_PATH, help='Path to MamaDroid jar')
    parser.add_argument('--platforms', default=DEFAULT_PLATFORMS, help='Android platforms path')
    parser.add_argument('--java-opts', default="-Xmx32g", help='Java options (e.g., -Xmx32g)')
    parser.add_argument('--recursive', '-r', action='store_true',
                        help='Scan input directory recursively (for categorized APKs like DroidBench)')
    parser.add_argument('--category', '-c', help='Process only specific category (for DroidBench)')
    
    args = parser.parse_args()

    _check_java_version()
    
    # Determine configuration
    if args.dataset:
        config = DATASETS[args.dataset].copy()
        # Override with custom paths if provided
        if args.input_dir:
            config['input_folder'] = args.input_dir
        if args.output_dir:
            config['output_folder'] = args.output_dir
        if args.log_file:
            config['log_file'] = args.log_file
        if args.recursive:
            config['recursive'] = True
    elif args.input_dir and args.output_dir:
        # Custom configuration
        config = {
            'input_folder': args.input_dir,
            'output_folder': args.output_dir,
            'log_file': args.log_file or os.path.join(args.output_dir, 'processing_log.json'),
            'recursive': args.recursive,
        }
    else:
        parser.print_help()
        print("\nError: Please specify --dataset or both --input-dir and --output-dir")
        sys.exit(1)
    
    input_folder = os.path.abspath(config['input_folder'])
    output_folder = os.path.abspath(config['output_folder'])
    log_file = os.path.abspath(config['log_file'])
    recursive = config['recursive']
    jar_path = os.path.abspath(args.jar)
    platforms_path = os.path.abspath(args.platforms)
    java_opts = args.java_opts
    
    # Create output folder if it doesn't exist
    os.makedirs(output_folder, exist_ok=True)
    log_dir = os.path.dirname(log_file)
    if log_dir:
        os.makedirs(log_dir, exist_ok=True)
    
    # Check if input folder exists
    if not os.path.exists(input_folder):
        print(f"Error: Input folder not found: {input_folder}")
        sys.exit(1)
    
    # Check if jar exists
    if not os.path.exists(jar_path):
        print(f"Error: MamaDroid jar not found: {jar_path}")
        sys.exit(1)
    
    # Find all APK files
    apk_files = find_apks(input_folder, recursive)
    
    # Filter by category if specified
    if args.category:
        apk_files = [(path, cat) for path, cat in apk_files if cat == args.category]
    
    if not apk_files:
        print(f"No APK files found in {input_folder}")
        sys.exit(1)
    
    # Count categories
    categories = set(cat for _, cat in apk_files if cat)
    
    print(f"Tool: MamaDroid")
    print(f"Dataset: {args.dataset or 'custom'}")
    print(f"Found {len(apk_files)} APK files to process")
    if categories:
        print(f"Categories: {len(categories)} ({', '.join(sorted(categories))})")
    print(f"Output folder: {output_folder}")
    print(f"Log file: {log_file}")
    print(f"JAR: {jar_path}")
    print(f"Platforms: {platforms_path}")
    print(f"Java opts: {java_opts}")
    
    # Load existing log if it exists
    results = []
    if os.path.exists(log_file):
        try:
            with open(log_file, 'r') as f:
                results = json.load(f)
            print(f"Loaded {len(results)} previous results from log file")
        except:
            results = []
    
    # Skip if an APK already has any log entry (success or failure),
    # or if a non-empty expected output already exists.
    processed_apks = set()
    for r in results:
        p = r.get('apk_path')
        if p:
            processed_apks.add(os.path.abspath(p))
    
    # Process each APK
    total_start_time = time.time()
    
    for idx, (apk_path, category) in enumerate(apk_files, 1):
        # Determine output file path
        # - flat mode: output_folder/<apkBase>.txt
        # - recursive mode: preserve tree: output_folder/<relative_parent>/<apkBase>.txt
        apk_base_name = os.path.splitext(os.path.basename(apk_path))[0]
        if recursive:
            rel_parent = os.path.relpath(os.path.dirname(os.path.abspath(apk_path)), input_folder)
            rel_parent = "" if rel_parent == "." else rel_parent
            output_file = os.path.join(output_folder, rel_parent, f"{apk_base_name}.txt")
        else:
            output_file = os.path.join(output_folder, f"{apk_base_name}.txt")

        file_exists = os.path.exists(output_file)
        file_size = os.path.getsize(output_file) if file_exists else 0
        if apk_path in processed_apks or (file_exists and file_size > 0):
            reason = "already processed (log)" if apk_path in processed_apks else f"output exists ({file_size} bytes), skipping re-run"
            print(f"\n[{idx}/{len(apk_files)}] Skipping ({reason}): {os.path.basename(apk_path)}")
            continue

        print(f"\n[{idx}/{len(apk_files)}] Processing APK...")
        
        result = process_apk(apk_path, output_file, jar_path, platforms_path, java_opts, category)
        results.append(result)
        processed_apks.add(apk_path)
        
        # Save progress after each APK
        with open(log_file, 'w') as f:
            json.dump(results, f, indent=2)
        
        # Print summary
        if result['success']:
            callgraph_stats = result.get('callgraph_stats', {})
            edges_count = callgraph_stats.get('edges', 0)
            methods_count = callgraph_stats.get('methods', 0)
            
            print(f"\nSummary for {result['apk_name']}:")
            print(f"  Duration: {result['duration_minutes']:.2f} minutes ({result['duration_seconds']:.2f} seconds)")
            print(f"  Avg CPU: {result['resource_usage'].get('avg_cpu_percent', 0):.2f}%")
            print(f"  Max CPU: {result['resource_usage'].get('max_cpu_percent', 0):.2f}%")
            print(f"  Avg Memory: {result['resource_usage'].get('avg_memory_mb', 0):.2f} MB")
            print(f"  Max Memory: {result['resource_usage'].get('max_memory_mb', 0):.2f} MB")
            print(f"  Output size: {result.get('output_file_size_mb', 0):.2f} MB")
            print(f"  Edges: {edges_count:,}")
            print(f"  Methods: {methods_count:,}")
    
    # Category breakdown for DroidBench
    if categories:
        print(f"\n{'='*80}")
        print("CATEGORY BREAKDOWN")
        print(f"{'='*80}")
        for cat in sorted(categories):
            cat_results = [r for r in results if r.get('category') == cat]
            cat_success = sum(1 for r in cat_results if r.get('success', False))
            print(f"  {cat}: {cat_success}/{len(cat_results)} successful")
    
    # Final summary
    total_duration = time.time() - total_start_time
    successful = sum(1 for r in results if r.get('success', False))
    failed = len(results) - successful
    
    print(f"\n{'='*80}")
    print("FINAL SUMMARY")
    print(f"{'='*80}")
    print(f"Total APKs processed: {len(results)}")
    print(f"Successful: {successful}")
    print(f"Failed: {failed}")
    print(f"Total time: {total_duration/60:.2f} minutes ({total_duration:.2f} seconds)")
    print(f"Results saved to: {log_file}")
    print(f"{'='*80}")

if __name__ == "__main__":
    main()
