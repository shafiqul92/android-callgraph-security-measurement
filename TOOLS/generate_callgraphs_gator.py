#!/usr/bin/env python3
"""
Script to generate callgraphs for APKs using Gator tool.
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

# Default paths (updated for /local-storage layout on evihunter-main)
DEFAULT_JAR_PATH = "/local-storage/RESEARCH/TOOLS/GATOR/target/experiments-callgraphsoundness-1.0-jar-with-dependencies.jar"
DEFAULT_PLATFORMS = "/local-storage/RESEARCH/Android-platforms/jars/stubs"

# Configuration for different datasets
DATASETS = {
    'apkpure': {
        'input_folder': "/local-storage/RESEARCH/APK",
        'output_folder': "/local-storage/RESEARCH/RESULTS/GATOR/APKPURE_APKS",
        'log_file': "/local-storage/RESEARCH/RESULTS/GATOR/apkpure_processing_log.json",
        'recursive': False,  # APKs are in flat folder
    },
    'droidbench': {
        'input_folder': "/local-storage/RESEARCH/DroidBench/apk",
        'output_folder': "/local-storage/RESEARCH/RESULTS/GATOR/DROIDBENCH",
        'log_file': "/local-storage/RESEARCH/RESULTS/GATOR/droidbench_processing_log.json",
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

def process_apk(apk_path, output_file, jar_path, platforms_path, java_opts="-Xmx32g", category=None, timeout_seconds=3600):
    """Process a single APK file and generate callgraph using Gator."""
    apk_name = os.path.basename(apk_path)
    apk_base_name = os.path.splitext(apk_name)[0]
    output_folder = os.path.dirname(output_file)
    
    print(f"\n{'='*80}")
    if category:
        print(f"Category: {category}")
    print(f"Processing: {apk_name}")
    print(f"Output: {output_file}")
    print(f"{'='*80}")
    
    # Create output directory if needed
    os.makedirs(output_folder, exist_ok=True)
    
    # Convert all paths to absolute (critical: Java runs with cwd=output_folder)
    apk_path_abs = os.path.abspath(apk_path)
    jar_path_abs = os.path.abspath(jar_path)
    platforms_path_abs = os.path.abspath(platforms_path)
    output_file_abs = os.path.abspath(output_file)
    output_folder_abs = os.path.abspath(output_folder)
    
    # Verify the APK file exists
    if not os.path.exists(apk_path_abs):
        return {
            'tool_name': 'Gator',
            'apk_name': apk_name,
            'apk_path': apk_path,
            'category': category,
            'success': False,
            'status': 'error',
            'error': f"APK file does not exist: {apk_path_abs}",
            'error_tag': 'no_file',
            'duration_seconds': 0,
            'start_time': datetime.now().isoformat(),
            'end_time': datetime.now().isoformat()
        }
    
    # Build java command for Gator using absolute paths
    cmd = [
        "java",
        java_opts,
        "-jar", jar_path_abs,
        "-a", apk_path_abs,
        "-p", platforms_path_abs,
        "-j", platforms_path_abs,
        "-t", "gator"
    ]
    
    # Record start time
    start_time = time.time()
    start_datetime = datetime.now().isoformat()
    
    try:
        # Run gator command with cwd set to output folder so the tool writes there
        gator_process = subprocess.Popen(
            cmd,
            stdout=subprocess.PIPE,
            stderr=subprocess.PIPE,
            text=True,
            cwd=output_folder_abs
        )
        
        # Get psutil Process object for monitoring
        resource_metrics = {}
        cpu_samples = []
        memory_samples = []
        psutil_process = None
        
        try:
            psutil_process = psutil.Process(gator_process.pid)
            # Start monitoring thread
            monitor_thread = threading.Thread(
                target=monitor_process_thread,
                args=(psutil_process, gator_process, cpu_samples, memory_samples),
                daemon=True
            )
            monitor_thread.start()
        except (psutil.NoSuchProcess, psutil.AccessDenied) as e:
            print(f"Warning: Could not monitor process resources: {e}")
        
        # Wait for completion with timeout
        try:
            stdout, stderr = gator_process.communicate(timeout=timeout_seconds)
            timed_out = False
        except subprocess.TimeoutExpired:
            timed_out = True
            print(f"⚠ Timeout after {timeout_seconds/60:.1f} minutes. Terminating process...")
            try:
                if psutil_process is None:
                    psutil_process = psutil.Process(gator_process.pid)
                for child in psutil_process.children(recursive=True):
                    try:
                        child.kill()
                    except psutil.NoSuchProcess:
                        pass
                psutil_process.kill()
            except (psutil.NoSuchProcess, psutil.AccessDenied):
                gator_process.kill()
            try:
                stdout, stderr = gator_process.communicate(timeout=5)
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
            out_path = Path(output_file_abs)
            stderr_log_file = out_path.with_name(f"{out_path.stem}-stderr.log")
            stderr_log_path = str(stderr_log_file)
            with open(stderr_log_file, "w", encoding="utf-8", errors="ignore") as f:
                if stderr:
                    f.write(stderr if isinstance(stderr, str) else stderr.decode('utf-8', errors='ignore'))
        except Exception as e:
            print(f"Warning: Could not write stderr log file: {e}")
            stderr_log_path = ""
        
        # Find the actual output file (Gator names it differently)
        expected_gator_output = os.path.join(output_folder_abs, f"{apk_base_name}-CHA-callgraph.txt")
        if os.path.exists(expected_gator_output):
            if expected_gator_output != output_file_abs:
                os.rename(expected_gator_output, output_file_abs)
        
        # Check if successful
        error_msg = None
        if timed_out:
            success = False
            print(f"✗ Timeout: {apk_name} exceeded {timeout_seconds/60:.1f} minute limit")
            error_msg = f"Timeout after {timeout_seconds/60:.1f} minutes"
        else:
            success = gator_process.returncode == 0 and os.path.exists(output_file_abs)
            if success:
                print(f"✓ Successfully processed {apk_name}")
            else:
                print(f"✗ Failed to process {apk_name}")
                if stderr:
                    if isinstance(stderr, bytes):
                        error_msg = stderr.decode('utf-8', errors='ignore')[:500]
                    else:
                        error_msg = str(stderr)[:500]
                    print(f"Error: {error_msg}")
                if not error_msg:
                    error_msg = "Unknown error"
        
        # Derive status and error_tag (same as FlowDroid)
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
            elif gator_process.returncode == 0 and not os.path.exists(output_file_abs):
                error_tag = "no_output"
            else:
                error_tag = "other"
        
        # Analyze callgraph if successful
        callgraph_stats = {'edges': 0, 'methods': 0}
        output_size_mb = 0
        if success and os.path.exists(output_file_abs):
            callgraph_stats = analyze_callgraph(output_file_abs)
            output_size_mb = os.path.getsize(output_file_abs) / (1024 * 1024)
        
        result = {
            'tool_name': 'Gator',
            'apk_name': apk_name,
            'apk_path': apk_path,
            'category': category,
            'output_file': output_file,
            'start_time': start_datetime,
            'end_time': datetime.now().isoformat(),
            'duration_seconds': round(duration_seconds, 2),
            'duration_minutes': round(duration_minutes, 2),
            'success': success,
            'status': status,
            'error_tag': error_tag,
            'stderr_log_path': stderr_log_path,
            'return_code': gator_process.returncode if not timed_out else -1,
            'timed_out': timed_out,
            'resource_usage': resource_metrics,
            'output_file_size_mb': round(output_size_mb, 2),
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
            'tool_name': 'Gator',
            'apk_name': apk_name,
            'apk_path': apk_path,
            'category': category,
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
    
    if recursive:
        # DroidBench structure: apk/Category/file.apk
        for category in sorted(os.listdir(input_folder)):
            category_path = os.path.join(input_folder, category)
            if os.path.isdir(category_path):
                for file in sorted(os.listdir(category_path)):
                    if file.endswith('.apk'):
                        apk_path = os.path.join(category_path, file)
                        apk_files.append((apk_path, category))
    else:
        # APKPure structure: flat folder with APKs
        for file in sorted(os.listdir(input_folder)):
            if file.endswith('.apk'):
                apk_path = os.path.join(input_folder, file)
                apk_files.append((apk_path, None))
    
    return apk_files

def main():
    parser = argparse.ArgumentParser(
        description='Generate callgraphs for APKs using Gator tool',
        formatter_class=argparse.RawDescriptionHelpFormatter,
        epilog="""
Examples:
  # Run on DroidBench APKs
  python3 generate_callgraphs_gator.py --dataset droidbench
  
  # Run on APKPure APKs
  python3 generate_callgraphs_gator.py --dataset apkpure
  
  # Run only a specific DroidBench category
  python3 generate_callgraphs_gator.py --dataset droidbench --category Callbacks
  
  # Run on custom folder
  python3 generate_callgraphs_gator.py --input-dir /path/to/apks --output-dir /path/to/output
"""
    )
    parser.add_argument('--dataset', '-d', choices=['apkpure', 'droidbench'],
                        help='Dataset to process (apkpure or droidbench)')
    parser.add_argument('--input-dir', '-i', help='Custom input directory with APKs')
    parser.add_argument('--output-dir', '-o', help='Custom output directory for callgraphs')
    parser.add_argument('--log-file', '-l', help='Custom log file path')
    parser.add_argument('--jar', default=DEFAULT_JAR_PATH, help='Path to Gator jar')
    parser.add_argument('--platforms', default=DEFAULT_PLATFORMS, help='Android platforms path')
    parser.add_argument('--java-opts', default="-Xmx32g", help='Java options (e.g., -Xmx32g)')
    parser.add_argument('--recursive', '-r', action='store_true',
                        help='Scan input directory recursively (for categorized APKs like DroidBench)')
    parser.add_argument('--category', '-c', help='Process only specific category (for DroidBench)')
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
    
    # Create output folder if it doesn't exist
    os.makedirs(output_folder, exist_ok=True)
    os.makedirs(os.path.dirname(log_file), exist_ok=True)
    
    # Check if input folder exists
    if not os.path.exists(input_folder):
        print(f"Error: Input folder not found: {input_folder}")
        sys.exit(1)
    
    # Check if jar exists
    if not os.path.exists(jar_path):
        print(f"Error: Gator jar not found: {jar_path}")
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
    
    print(f"Dataset: {args.dataset or 'custom'}")
    print(f"Found {len(apk_files)} APK files to process")
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
    
    # Get list of already attempted APKs (any log entry), same as FlowDroid.
    # Also skip when output file exists and is non-empty.
    processed_apks = set(r.get('apk_path') for r in results)
    
    # Process each APK
    total_start_time = time.time()
    
    for idx, (apk_path, category) in enumerate(apk_files, 1):
        # Determine output file path (for skip check and process_apk)
        apk_base_name = os.path.splitext(os.path.basename(apk_path))[0]
        if category:
            output_file = os.path.join(output_folder, category, f"{apk_base_name}.txt")
        else:
            output_file = os.path.join(output_folder, f"{apk_base_name}.txt")
        
        # Skip if already attempted (log) or output exists and non-empty, same as FlowDroid
        if apk_path in processed_apks or (os.path.exists(output_file) and os.path.getsize(output_file) > 0):
            reason = "already processed (log)" if apk_path in processed_apks else "output exists, skipping re-run"
            print(f"\n[{idx}/{len(apk_files)}] Skipping ({reason}): {os.path.basename(apk_path)}")
            continue
        
        print(f"\n[{idx}/{len(apk_files)}] Processing APK...")
        
        result = process_apk(apk_path, output_file, jar_path, platforms_path, java_opts, category, args.timeout)
        results.append(result)
        
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
