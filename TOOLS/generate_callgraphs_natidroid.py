#!/usr/bin/env python3
"""
Script to generate callgraphs for APKs using NatiDroid.

The JAR is experiments-callgraphsoundness (MethodsExtractorMain). NatiDroid mode is
selected with: -t natidroid  → MethodsExtractorNatiDroid + CHA call graph.

Supports DroidBench-style categories and flat APKPure folders.
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
from datetime import datetime

# Default paths on evihunter /local-storage (NatiDroid_Modification copy + Android stubs)
_DEFAULT_ROOT = "/local-storage/RESEARCH"
DEFAULT_JAR_PATH = (
    f"{_DEFAULT_ROOT}/TOOLS/NatiDroid_Modification/"
    "Call-Graph-Soundness-in-Android-Static-Analysis-main (1)/"
    "Call-Graph-Soundness-in-Android-Static-Analysis-main/target/"
    "experiments-callgraphsoundness-1.0-jar-with-dependencies.jar"
)
DEFAULT_PLATFORMS = f"{_DEFAULT_ROOT}/Android-platforms/jars/stubs"

# Configuration for different datasets
DATASETS = {
    'apkpure': {
        'input_folder': f"{_DEFAULT_ROOT}/APK/communication",
        'output_folder': f"{_DEFAULT_ROOT}/RESULTS/NATIDROID/ALL_APKS/communication",
        'log_file': f"{_DEFAULT_ROOT}/RESULTS/NATIDROID/all_apks_log.json",
        'recursive': False,
    },
    'droidbench': {
        'input_folder': f"{_DEFAULT_ROOT}/DroidBench/apk",
        'output_folder': f"{_DEFAULT_ROOT}/RESULTS/NATIDROID/DROIDBENCH",
        'log_file': f"{_DEFAULT_ROOT}/RESULTS/NATIDROID/droidbench_processing_log.json",
        'recursive': True,
    },
}


def get_resource_usage(process):
    """CPU and RSS memory for the Java process (aligned with FlowDroid wrapper: raw psutil %)."""
    try:
        cpu_percent = process.cpu_percent(interval=0.1)
        memory_info = process.memory_info()
        memory_mb = memory_info.rss / (1024 * 1024)
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

    try:
        if psutil_process.is_running():
            final_cpu, final_memory = get_resource_usage(psutil_process)
            if final_cpu > 0 or final_memory > 0:
                cpu_samples.append(final_cpu)
                memory_samples.append(final_memory)
    except (psutil.NoSuchProcess, psutil.AccessDenied):
        pass


def process_apk(apk_path, output_file, jar_path, platforms_path, java_opts="-Xmx32g", category=None):
    """Process a single APK file and generate callgraph using NatiDroid (-t natidroid)."""
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

    os.makedirs(output_folder, exist_ok=True)

    cmd = [
        "java",
        java_opts,
        "-jar", jar_abs,
        "-a", apk_abs,
        "-p", plat_abs,
        "-j", plat_abs,
        "-t", "natidroid",
    ]

    start_time = time.time()
    start_datetime = datetime.now().isoformat()

    try:
        natidroid_process = subprocess.Popen(
            cmd,
            stdout=subprocess.PIPE,
            stderr=subprocess.PIPE,
            text=True,
            cwd=output_folder,
        )

        resource_metrics = {}
        cpu_samples = []
        memory_samples = []

        try:
            psutil_process = psutil.Process(natidroid_process.pid)
            monitor_thread = threading.Thread(
                target=monitor_process_thread,
                args=(psutil_process, natidroid_process, cpu_samples, memory_samples),
                daemon=True,
            )
            monitor_thread.start()
        except (psutil.NoSuchProcess, psutil.AccessDenied) as e:
            print(f"Warning: Could not monitor process resources: {e}")

        stdout, stderr = natidroid_process.communicate()
        try:
            with open(stderr_log_path, "w", encoding="utf-8", errors="replace") as sf:
                sf.write(stderr or "")
        except OSError as e:
            print(f"Warning: could not write stderr log {stderr_log_path}: {e}")

        if 'monitor_thread' in locals():
            monitor_thread.join(timeout=2.0)

        if cpu_samples or memory_samples:
            avg_cpu = sum(cpu_samples) / len(cpu_samples) if cpu_samples else 0.0
            max_cpu = max(cpu_samples) if cpu_samples else 0.0
            avg_memory = sum(memory_samples) / len(memory_samples) if memory_samples else 0.0
            max_memory = max(memory_samples) if memory_samples else 0.0

            resource_metrics = {
                'avg_cpu_percent': round(avg_cpu, 2),
                'max_cpu_percent': round(max_cpu, 2),
                'avg_memory_mb': round(avg_memory, 2),
                'max_memory_mb': round(max_memory, 2),
            }

        end_time = time.time()
        duration_seconds = end_time - start_time
        duration_minutes = duration_seconds / 60

        # DataCollector: fileName = "%s-%s-callgraph.txt" % (apkPath, algo)  →  <apkPath>-CHA-callgraph.txt
        expected_natidroid_output = f"{apk_abs}-CHA-callgraph.txt"
        if os.path.exists(expected_natidroid_output) and os.path.normpath(
                expected_natidroid_output) != os.path.normpath(output_file):
            try:
                shutil.move(expected_natidroid_output, output_file)
            except OSError as e:
                print(f"Warning: could not move callgraph to output path: {e}")

        success = natidroid_process.returncode == 0 and os.path.exists(output_file)

        if success:
            print(f"✓ Successfully processed {apk_name}")
        else:
            print(f"✗ Failed to process {apk_name}")
            if stderr:
                print(f"Error: {stderr[:500]}")

        callgraph_stats = {'edges': 0, 'methods': 0}
        output_size_mb = 0
        if success and os.path.exists(output_file):
            callgraph_stats = analyze_callgraph(output_file)
            output_size_mb = os.path.getsize(output_file) / (1024 * 1024)

        result = {
            'tool_name': 'NatiDroid',
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
            'return_code': natidroid_process.returncode,
            'resource_usage': resource_metrics,
            'output_file_size_mb': round(output_size_mb, 2),
            'callgraph_stats': callgraph_stats,
        }

        return result

    except Exception as e:
        end_time = time.time()
        duration_seconds = end_time - start_time

        print(f"✗ Exception while processing {apk_name}: {str(e)}")

        return {
            'tool_name': 'NatiDroid',
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
            'callgraph_stats': {'edges': 0, 'methods': 0},
        }


def find_apks(input_folder, recursive=False):
    """Return list of (apk_path, category); paths are absolute."""
    apk_files = []
    input_folder = os.path.abspath(input_folder)

    if recursive:
        for category in sorted(os.listdir(input_folder)):
            category_path = os.path.join(input_folder, category)
            if os.path.isdir(category_path):
                for file in sorted(os.listdir(category_path)):
                    if file.endswith('.apk'):
                        apk_path = os.path.abspath(os.path.join(category_path, file))
                        apk_files.append((apk_path, category))
    else:
        for file in sorted(os.listdir(input_folder)):
            if file.endswith('.apk'):
                apk_path = os.path.abspath(os.path.join(input_folder, file))
                apk_files.append((apk_path, None))

    return apk_files


def main():
    parser = argparse.ArgumentParser(
        description='Generate callgraphs for APKs using NatiDroid (-t natidroid)',
        formatter_class=argparse.RawDescriptionHelpFormatter,
        epilog="""
Examples:
  python3 generate_callgraphs_natidroid.py --dataset droidbench
  python3 generate_callgraphs_natidroid.py --dataset apkpure
  python3 generate_callgraphs_natidroid.py --dataset droidbench --category Callbacks
  python3 generate_callgraphs_natidroid.py -i /local-storage/RESEARCH/APK -o ... --recursive
""",
    )
    parser.add_argument('--dataset', '-d', choices=['apkpure', 'droidbench'],
                        help='Dataset to process (apkpure or droidbench)')
    parser.add_argument('--input-dir', '-i', help='Custom input directory with APKs')
    parser.add_argument('--output-dir', '-o', help='Custom output directory for callgraphs')
    parser.add_argument('--log-file', '-l', help='Custom log file path')
    parser.add_argument('--jar', default=DEFAULT_JAR_PATH, help='Path to experiments-callgraphsoundness JAR')
    parser.add_argument('--platforms', default=DEFAULT_PLATFORMS, help='Android platforms (stubs) path')
    parser.add_argument('--java-opts', default="-Xmx32g", help='Java options (e.g., -Xmx32g)')
    parser.add_argument('--recursive', '-r', action='store_true',
                        help='Scan input directory recursively (category subfolders)')
    parser.add_argument('--category', '-c', help='Process only this category (recursive mode)')

    args = parser.parse_args()

    if args.dataset:
        config = DATASETS[args.dataset].copy()
        if args.input_dir:
            config['input_folder'] = args.input_dir
        if args.output_dir:
            config['output_folder'] = args.output_dir
        if args.log_file:
            config['log_file'] = args.log_file
        if args.recursive:
            config['recursive'] = True
    elif args.input_dir and args.output_dir:
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

    os.makedirs(output_folder, exist_ok=True)
    log_dir = os.path.dirname(log_file)
    if log_dir:
        os.makedirs(log_dir, exist_ok=True)

    if not os.path.exists(input_folder):
        print(f"Error: Input folder not found: {input_folder}")
        sys.exit(1)

    if not os.path.exists(jar_path):
        print(f"Error: NatiDroid JAR not found: {jar_path}")
        sys.exit(1)

    apk_files = find_apks(input_folder, recursive)

    if args.category:
        apk_files = [(path, cat) for path, cat in apk_files if cat == args.category]

    if not apk_files:
        print(f"No APK files found in {input_folder}")
        sys.exit(1)

    categories = set(cat for _, cat in apk_files if cat)

    print("Tool: NatiDroid (MethodsExtractorNatiDroid, -t natidroid)")
    print(f"Dataset: {args.dataset or 'custom'}")
    print(f"Found {len(apk_files)} APK files to process")
    if categories:
        print(f"Categories: {len(categories)} ({', '.join(sorted(categories))})")
    print(f"Output folder: {output_folder}")
    print(f"Log file: {log_file}")
    print(f"JAR: {jar_path}")
    print(f"Platforms: {platforms_path}")

    results = []
    if os.path.exists(log_file):
        try:
            with open(log_file, 'r') as f:
                results = json.load(f)
            print(f"Loaded {len(results)} previous results from log file")
        except Exception:
            results = []

    # Any prior log entry for this apk_path → skip (matches FlowDroid/Androguard wrappers)
    processed_apks = set()
    for r in results:
        p = r.get('apk_path')
        if p:
            processed_apks.add(os.path.abspath(p))

    total_start_time = time.time()

    for idx, (apk_path, category) in enumerate(apk_files, 1):
        apk_base_name = os.path.splitext(os.path.basename(apk_path))[0]
        if category:
            output_file = os.path.join(output_folder, category, f"{apk_base_name}.txt")
        else:
            output_file = os.path.join(output_folder, f"{apk_base_name}.txt")

        file_exists = os.path.exists(output_file)
        file_size = os.path.getsize(output_file) if file_exists else 0

        if apk_path in processed_apks or (file_exists and file_size > 0):
            reason = "already in log" if apk_path in processed_apks else f"output exists ({file_size} bytes)"
            print(f"\n[{idx}/{len(apk_files)}] Skipping ({reason}): {os.path.basename(apk_path)}")
            continue

        print(f"\n[{idx}/{len(apk_files)}] Processing APK...")

        result = process_apk(apk_path, output_file, jar_path, platforms_path, java_opts, category)
        results.append(result)
        processed_apks.add(apk_path)

        try:
            with open(log_file, 'w') as f:
                json.dump(results, f, indent=2)
        except OSError as e:
            print(f"Warning: could not write log file: {e}")

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

    if categories:
        print(f"\n{'='*80}")
        print("CATEGORY BREAKDOWN")
        print(f"{'='*80}")
        for cat in sorted(categories):
            cat_results = [r for r in results if r.get('category') == cat]
            cat_success = sum(1 for r in cat_results if r.get('success', False))
            print(f"  {cat}: {cat_success}/{len(cat_results)} successful")

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
