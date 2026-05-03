#!/usr/bin/env python3
"""
Script to generate callgraphs for APKs using FlowDroid tool.
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
from pathlib import Path
from datetime import datetime

# Default paths
DEFAULT_JAR_PATH = "/home/shafiqul/RESEARCH/Tools/FlowDroid/soot-infoflow-cmd/target/soot-infoflow-cmd-jar-with-dependencies.jar"
DEFAULT_PLATFORMS = "/home/shafiqul/RESEARCH/Tools/static analysis/iccta/Android-platforms/jars/stubs"

# FlowDroid supported algorithms
ALGORITHMS = ["CHA", "VTA", "RTA", "SPARK", "GEOM"]

# Configuration for different datasets
DATASETS = {
    'apkpure': {
        'input_folder': "/home/shafiqul/MY_APPCRAWLER/apkpure_apks_final_2/communication",
        'output_folder': "/home/shafiqul/RESEARCH/RESULTS/FLOWDROID/APKPURE_APKS",
        'log_file': "/home/shafiqul/RESEARCH/RESULTS/FLOWDROID/apkpure_processing_log.json",
        'recursive': False,  # APKs are in flat folder
    },
    'droidbench': {
        'input_folder': "/home/shafiqul/RESEARCH/DroidBench/apk",
        'output_folder': "/home/shafiqul/RESEARCH/RESULTS/FLOWDROID/DROIDBENCH",
        'log_file': "/home/shafiqul/RESEARCH/RESULTS/FLOWDROID/droidbench_processing_log.json",
        'recursive': True,  # APKs are in category subfolders
    }
}

def get_resource_usage(process):
    """Get CPU and memory usage of a process.
    
    CPU usage is the actual percentage (can exceed 100% on multi-core systems).
    e.g., 400% means 4 cores are fully utilized.
    """
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
            for line in f:
                line = line.strip()
                if not line:
                    continue
                
                if '->' in line:
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

def process_apk(apk_path, output_folder, jar_path, platforms_path, algorithm, java_opts="-Xmx32g", category=None, timeout_seconds=3600):
    """Process a single APK file and generate callgraph using FlowDroid."""
    apk_name = os.path.basename(apk_path)
    apk_base_name = os.path.splitext(apk_name)[0]
    output_file = os.path.join(output_folder, f"{apk_base_name}-{algorithm}-callgraph.txt")
    
    print(f"\n{'='*80}")
    if category:
        print(f"Category: {category}")
    print(f"Processing: {apk_name}")
    print(f"Algorithm: {algorithm}")
    print(f"Output: {output_file}")
    print(f"{'='*80}")
    
    # Create output directory if needed
    os.makedirs(output_folder, exist_ok=True)
    
    # Ensure apk_path is absolute (FlowDroid needs absolute paths)
    # Convert to absolute path - this is critical for FlowDroid
    if not os.path.isabs(apk_path):
        apk_path_abs = os.path.abspath(apk_path)
    else:
        apk_path_abs = apk_path
    
    # Verify the file exists
    if not os.path.exists(apk_path_abs):
        return {
            'apk_name': apk_name,
            'apk_path': apk_path,
            'algorithm': algorithm,
            'category': category,
            'success': False,
            'status': 'error',
            'error': f"APK file does not exist: {apk_path_abs}",
            'error_tag': 'no_file',
            'duration_seconds': 0,
            'start_time': datetime.now().isoformat(),
            'end_time': datetime.now().isoformat()
        }
    
    # Build java command for FlowDroid
    # Use absolute paths for both APK and output file
    output_file_abs = os.path.abspath(output_file)
    # Ensure platforms_path is absolute
    platforms_path_abs = os.path.abspath(platforms_path) if platforms_path else platforms_path
    cmd = [
        "java",
        java_opts,
        "-jar", jar_path,
        "-a", apk_path_abs,
        "-p", platforms_path_abs,
        "-cg", algorithm,
        "-o", output_file_abs
    ]
    
    # Record start time
    start_time = time.time()
    start_datetime = datetime.now().isoformat()
    
    try:
        # Run FlowDroid command
        # Don't set cwd - use absolute paths for all arguments to avoid path resolution issues
        flowdroid_process = subprocess.Popen(
            cmd,
            stdout=subprocess.PIPE,
            stderr=subprocess.PIPE,
            text=True
        )
        
        # Get psutil Process object for monitoring
        resource_metrics = {}
        cpu_samples = []
        memory_samples = []
        psutil_process = None
        
        try:
            psutil_process = psutil.Process(flowdroid_process.pid)
            # Start monitoring thread
            monitor_thread = threading.Thread(
                target=monitor_process_thread,
                args=(psutil_process, flowdroid_process, cpu_samples, memory_samples),
                daemon=True
            )
            monitor_thread.start()
        except (psutil.NoSuchProcess, psutil.AccessDenied) as e:
            print(f"Warning: Could not monitor process resources: {e}")
        
        # Wait for completion with timeout
        try:
            stdout, stderr = flowdroid_process.communicate(timeout=timeout_seconds)
            timed_out = False
        except subprocess.TimeoutExpired:
            timed_out = True
            print(f"⚠ Timeout after {timeout_seconds/60:.1f} minutes. Terminating process...")
            # Kill the process and its children
            try:
                if psutil_process is None:
                    psutil_process = psutil.Process(flowdroid_process.pid)
                for child in psutil_process.children(recursive=True):
                    try:
                        child.kill()
                    except psutil.NoSuchProcess:
                        pass
                psutil_process.kill()
            except (psutil.NoSuchProcess, psutil.AccessDenied):
                flowdroid_process.kill()
            # Get any remaining output
            try:
                stdout, stderr = flowdroid_process.communicate(timeout=5)
            except subprocess.TimeoutExpired:
                stdout = b''
                stderr = b'Timeout: Process killed after exceeding time limit'
        
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
        
        # Prepare stderr log path and write stderr to file
        stderr_log_path = ""
        try:
            out_path = Path(output_file)
            stderr_log_file = out_path.with_name(f"{out_path.stem}-stderr.log")
            stderr_log_path = str(stderr_log_file)
            with open(stderr_log_file, "w", encoding="utf-8", errors="ignore") as f:
                if stderr:
                    f.write(stderr if isinstance(stderr, str) else stderr.decode('utf-8', errors='ignore'))
        except Exception as e:
            print(f"Warning: Could not write stderr log file: {e}")
            stderr_log_path = ""
        
        # Check if successful
        error_msg = None
        if timed_out:
            success = False
            print(f"✗ Timeout: {apk_name} with {algorithm} exceeded {timeout_seconds/60:.1f} minute limit")
            error_msg = f"Timeout after {timeout_seconds/60:.1f} minutes"
        else:
            success = flowdroid_process.returncode == 0 and os.path.exists(output_file)
            if success:
                print(f"✓ Successfully processed {apk_name} with {algorithm}")
            else:
                print(f"✗ Failed to process {apk_name} with {algorithm}")
                if stderr:
                    if isinstance(stderr, bytes):
                        error_msg = stderr.decode('utf-8', errors='ignore')[:500]
                    else:
                        error_msg = str(stderr)[:500]
                    print(f"Error: {error_msg}")
                if not error_msg:
                    error_msg = "Unknown error"
        
        # Derive status and error_tag
        # status: success | timeout | failure
        # error_tag: java_heap_oom | parse_error | no_output | timeout | other | ""
        if timed_out:
            status = "timeout"
            error_tag = "timeout"
        elif success:
            status = "success"
            error_tag = ""
        else:
            status = "failure"
            err_text = (error_msg or "").lower()
            if "outofmemoryerror" in err_text or "java heap space" in err_text:
                error_tag = "java_heap_oom"
            elif "file format violation" in err_text or "badzipfile" in err_text or "not a zip file" in err_text:
                error_tag = "parse_error"
            elif flowdroid_process.returncode == 0 and not os.path.exists(output_file):
                error_tag = "no_output"
            else:
                error_tag = "other"
        
        # Analyze callgraph if successful
        callgraph_stats = {'edges': 0, 'methods': 0}
        if success and os.path.exists(output_file):
            callgraph_stats = analyze_callgraph(output_file)
        
        result = {
            'tool_name': 'FlowDroid',
            'apk_name': apk_name,
            'apk_path': apk_path,
            'category': category,
            'algorithm': algorithm,
            'output_file': output_file,
            'start_time': start_datetime,
            'end_time': datetime.now().isoformat(),
            'duration_seconds': round(duration_seconds, 2),
            'duration_minutes': round(duration_minutes, 2),
            'success': success,
            'status': status,
            'error_tag': error_tag,
            'stderr_log_path': stderr_log_path,
            'return_code': flowdroid_process.returncode if not timed_out else -1,
            'timed_out': timed_out,
            'resource_usage': resource_metrics,
            'callgraph_stats': callgraph_stats
        }
        if timed_out or not success:
            result['error'] = error_msg if error_msg else "Process failed or timed out"
        
        return result
        
    except Exception as e:
        end_time = time.time()
        duration_seconds = end_time - start_time
        
        print(f"✗ Exception while processing {apk_name}: {str(e)}")
        
        result = {
            'tool_name': 'FlowDroid',
            'apk_name': apk_name,
            'apk_path': apk_path,
            'category': category,
            'algorithm': algorithm,
            'output_file': output_file,
            'start_time': start_datetime,
            'end_time': datetime.now().isoformat(),
            'duration_seconds': round(duration_seconds, 2),
            'duration_minutes': round(duration_seconds / 60, 2),
            'success': False,
            'status': 'failure',
            'error_tag': 'exception',
            'stderr_log_path': '',
            'error': str(e),
            'resource_usage': {},
            'callgraph_stats': {'edges': 0, 'methods': 0}
        }
        
        return result

def find_apks(input_folder, recursive=False):
    """Find all APK files in the input folder.
    
    Returns list of tuples: (apk_path, category)
    For non-recursive (APKPure), category is None.
    For recursive (DroidBench), category is the subfolder name.
    """
    apk_files = []
    
    # Ensure input_folder is absolute
    input_folder = os.path.abspath(input_folder)
    
    if recursive:
        # DroidBench structure: apk/Category/file.apk
        for category in sorted(os.listdir(input_folder)):
            category_path = os.path.join(input_folder, category)
            if os.path.isdir(category_path):
                for file in sorted(os.listdir(category_path)):
                    if file.endswith('.apk'):
                        apk_path = os.path.abspath(os.path.join(category_path, file))
                        apk_files.append((apk_path, category))
    else:
        # APKPure structure: flat folder with APKs
        for file in sorted(os.listdir(input_folder)):
            if file.endswith('.apk'):
                apk_path = os.path.abspath(os.path.join(input_folder, file))
                apk_files.append((apk_path, None))
    
    return apk_files

def main():
    parser = argparse.ArgumentParser(
        description='Generate callgraphs for APKs using FlowDroid tool',
        formatter_class=argparse.RawDescriptionHelpFormatter,
        epilog="""
Examples:
  # Run on DroidBench APKs with all algorithms
  python3 generate_callgraphs_flowdroid.py --dataset droidbench
  
  # Run on APKPure APKs
  python3 generate_callgraphs_flowdroid.py --dataset apkpure
  
  # Run only a specific DroidBench category
  python3 generate_callgraphs_flowdroid.py --dataset droidbench --category Callbacks
  
  # Run with specific algorithms
  python3 generate_callgraphs_flowdroid.py --dataset droidbench --algorithms SPARK CHA
  
  # Run on custom folder
  python3 generate_callgraphs_flowdroid.py --input-dir /path/to/apks --output-dir /path/to/output
"""
    )
    parser.add_argument('--dataset', '-d', choices=['apkpure', 'droidbench'],
                        help='Dataset to process (apkpure or droidbench)')
    parser.add_argument('--input-dir', '-i', help='Custom input directory with APKs')
    parser.add_argument('--output-dir', '-o', help='Custom output directory for callgraphs')
    parser.add_argument('--log-file', '-l', help='Custom log file path')
    parser.add_argument('--jar', default=DEFAULT_JAR_PATH, help='Path to FlowDroid jar')
    parser.add_argument('--platforms', default=DEFAULT_PLATFORMS, help='Android platforms path')
    parser.add_argument('--java-opts', default="-Xmx32g", help='Java options (e.g., -Xmx32g)')
    parser.add_argument('--recursive', '-r', action='store_true',
                        help='Scan input directory recursively (for categorized APKs like DroidBench)')
    parser.add_argument('--category', '-c', help='Process only specific category (for DroidBench)')
    parser.add_argument('--algorithms', '-a', nargs='+', choices=ALGORITHMS, default=ALGORITHMS,
                        help=f'Algorithms to run (default: all - {", ".join(ALGORITHMS)})')
    parser.add_argument('--timeout', '-t', type=int, default=3600,
                        help='Timeout in seconds for each APK analysis (default: 3600 = 60 minutes)')
    
    args = parser.parse_args()
    
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
    
    input_folder = config['input_folder']
    output_folder = config['output_folder']
    log_file = config['log_file']
    recursive = config['recursive']
    jar_path = args.jar
    platforms_path = args.platforms
    java_opts = args.java_opts
    algorithms = args.algorithms
    
    # Create output folder if it doesn't exist
    os.makedirs(output_folder, exist_ok=True)
    os.makedirs(os.path.dirname(log_file), exist_ok=True)
    
    # Check if input folder exists
    if not os.path.exists(input_folder):
        print(f"Error: Input folder not found: {input_folder}")
        sys.exit(1)
    
    # Check if jar exists
    if not os.path.exists(jar_path):
        print(f"Error: FlowDroid jar not found: {jar_path}")
        sys.exit(1)
    
    # Find all APK files
    apk_files = find_apks(input_folder, recursive)
    
    # Filter by category if specified
    if args.category:
        apk_files = [(path, cat) for path, cat in apk_files if cat == args.category]
    
    if not apk_files:
        print(f"No APK files found in {input_folder}")
        sys.exit(1)
    
    # Count categories and total APKs
    categories = set(cat for _, cat in apk_files if cat)
    total_apks = len(apk_files)
    
    print(f"Dataset: {args.dataset or 'custom'}")
    print(f"Found {total_apks} APK files to process")
    print(f"Algorithms: {', '.join(algorithms)}")
    print(f"Total runs: {total_apks * len(algorithms)}")
    if categories:
        print(f"Categories: {len(categories)} ({', '.join(sorted(categories))})")
    print(f"Output folder: {output_folder}")
    print(f"Log file: {log_file}")
    print(f"JAR: {jar_path}")
    print(f"Platforms: {platforms_path}")
    print(f"Timeout: {args.timeout} seconds ({args.timeout/60:.1f} minutes) per APK")
    
    # Load existing log if it exists
    results = []
    if os.path.exists(log_file):
        try:
            with open(log_file, 'r') as f:
                results = json.load(f)
            print(f"Loaded {len(results)} previous results from log file")
        except:
            results = []
    
    # Get list of already attempted APKs (apk_path + algorithm), regardless of success.
    # This ensures we skip APKs that previously failed or timed out as well.
    processed_keys = set((r.get('apk_path'), r.get('algorithm')) for r in results)
    
    # Process each APK
    total_start_time = time.time()
    
    # Group counts per category (for progress reporting)
    from collections import Counter
    cat_counts = Counter(cat for _, cat in apk_files)
    
    # Sort by category then by path for cleaner output
    apk_files_sorted = sorted(apk_files, key=lambda t: ((t[1] or ''), t[0]))
    
    current_category = None
    cat_idx = 0
    global_idx = 0
    
    for apk_path, category in apk_files_sorted:
        apk_name = os.path.basename(apk_path)
        
        # Category header when we enter a new category
        if category != current_category:
            current_category = category
            cat_idx = 0
            cat_name = current_category or os.path.basename(input_folder)
            cat_total = cat_counts[current_category]
            
            print(f"\n{'='*80}")
            print(f"[CATEGORY] {cat_name} ({cat_total} APKs)")
            print(f"{'='*80}")
        
        for algorithm in algorithms:
            # Determine output folder path for this (apk, algorithm) pair
            if category:
                # DroidBench: preserve category structure
                apk_output_folder = os.path.join(output_folder, category)
            else:
                # APKPure or custom: flat structure
                apk_output_folder = output_folder

            # Expected output file path (must match process_apk)
            apk_base_name = os.path.splitext(apk_name)[0]
            expected_output_file = os.path.join(
                apk_output_folder,
                f"{apk_base_name}-{algorithm}-callgraph.txt"
            )

            # Use per-category and global indices
            # Only increment counters when we actually consider a (apk, algorithm) pair
            cat_idx += 1
            global_idx += 1
            
            # Skip if already processed successfully (from log)
            # OR if the expected output file already exists and is non-empty.
            if ((apk_path, algorithm) in processed_keys or
                (os.path.exists(expected_output_file) and os.path.getsize(expected_output_file) > 0)):
                
                reason = "already processed (log)" if (apk_path, algorithm) in processed_keys else "output exists, skipping re-run"
                print(f"\n[{cat_idx}/{cat_counts[current_category]} in {current_category or os.path.basename(input_folder)}] "
                      f"[{global_idx}/{total_apks} total] [{algorithm}] Skipping: {apk_name} ({reason})")
                continue
            
            print(f"\n[{cat_idx}/{cat_counts[current_category]} in {current_category or os.path.basename(input_folder)}] "
                  f"[{global_idx}/{total_apks} total] [{algorithm}] Processing APK...")
            
            result = process_apk(apk_path, apk_output_folder, jar_path, platforms_path, algorithm, java_opts, category, args.timeout)
            results.append(result)
            
            # Save progress after each APK
            with open(log_file, 'w') as f:
                json.dump(results, f, indent=2)
            
            # Print summary
            if result.get('timed_out'):
                print(f"\nSummary for {result['apk_name']} ({algorithm}):")
                print(f"  Tool: {result.get('tool_name', 'FlowDroid')}")
                print(f"  Status: {result.get('status', 'timeout')}")
                if result.get('error_tag'):
                    print(f"  Error tag: {result.get('error_tag')}")
                if result.get('stderr_log_path'):
                    print(f"  Stderr log: {result.get('stderr_log_path')}")
                print(f"  Duration: {result['duration_minutes']:.2f} minutes ({result['duration_seconds']:.2f} seconds)")
                if result.get('resource_usage'):
                    print(f"  Avg CPU: {result['resource_usage'].get('avg_cpu_percent', 0):.2f}%")
                    print(f"  Max CPU: {result['resource_usage'].get('max_cpu_percent', 0):.2f}%")
                    print(f"  Avg Memory: {result['resource_usage'].get('avg_memory_mb', 0):.2f} MB")
                    print(f"  Max Memory: {result['resource_usage'].get('max_memory_mb', 0):.2f} MB")
            elif result['success']:
                callgraph_stats = result.get('callgraph_stats', {})
                edges_count = callgraph_stats.get('edges', 0)
                methods_count = callgraph_stats.get('methods', 0)
                
                print(f"\nSummary for {result['apk_name']} ({algorithm}):")
                print(f"  Tool: {result.get('tool_name', 'FlowDroid')}")
                print(f"  Status: {result.get('status', 'success')}")
                if result.get('error_tag'):
                    print(f"  Error tag: {result.get('error_tag')}")
                if result.get('stderr_log_path'):
                    print(f"  Stderr log: {result.get('stderr_log_path')}")
                print(f"  Duration: {result['duration_minutes']:.2f} minutes ({result['duration_seconds']:.2f} seconds)")
                print(f"  Avg CPU: {result['resource_usage'].get('avg_cpu_percent', 0):.2f}%")
                print(f"  Max CPU: {result['resource_usage'].get('max_cpu_percent', 0):.2f}%")
                print(f"  Avg Memory: {result['resource_usage'].get('avg_memory_mb', 0):.2f} MB")
                print(f"  Max Memory: {result['resource_usage'].get('max_memory_mb', 0):.2f} MB")
                print(f"  Edges: {edges_count:,}")
                print(f"  Methods: {methods_count:,}")
    
    # Algorithm breakdown
    print(f"\n{'='*80}")
    print("ALGORITHM BREAKDOWN")
    print(f"{'='*80}")
    for algo in algorithms:
        algo_results = [r for r in results if r.get('algorithm') == algo]
        algo_success = sum(1 for r in algo_results if r.get('success', False))
        avg_edges = sum(r.get('callgraph_stats', {}).get('edges', 0) for r in algo_results) / len(algo_results) if algo_results else 0
        print(f"  {algo}: {algo_success}/{len(algo_results)} successful, avg {avg_edges:.0f} edges")
    
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
    print(f"Total runs processed: {len(results)}")
    print(f"Successful: {successful}")
    print(f"Failed: {failed}")
    print(f"Total time: {total_duration/60:.2f} minutes ({total_duration:.2f} seconds)")
    print(f"Results saved to: {log_file}")
    print(f"{'='*80}")

if __name__ == "__main__":
    main()
