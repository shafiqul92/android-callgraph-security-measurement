#!/usr/bin/env python3
"""
Script to generate callgraphs for APKs using androguard.
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

# Configuration for different datasets
DATASETS = {
    'apkpure': {
        'input_folder': "/home/shafiqul/MY_APPCRAWLER/apkpure_apks_final_2/communication",
        'output_folder': "/home/shafiqul/RESEARCH/RESULTS/ANDROGUARD/APKPURE_APKS",
        'log_file': "/home/shafiqul/RESEARCH/RESULTS/ANDROGUARD/apkpure_processing_log.json",
        'recursive': False,  # APKs are in flat folder
    },
    'droidbench': {
        'input_folder': "/home/shafiqul/RESEARCH/DroidBench/apk",
        'output_folder': "/home/shafiqul/RESEARCH/RESULTS/ANDROGUARD/DROIDBENCH",
        'log_file': "/home/shafiqul/RESEARCH/RESULTS/ANDROGUARD/droidbench_processing_log.json",
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
                if not line or line.startswith('#'):
                    continue
                
                # Check if line contains an edge (has ==> separator)
                if ' ==> ' in line:
                    edges_count += 1
                    
                    # Extract source and target methods
                    parts = line.split(' ==> ', 1)
                    if len(parts) == 2:
                        source_method = parts[0].strip()
                        target_method = parts[1].strip()
                        
                        # Add both methods to the set
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

def process_apk(apk_path, output_file, category=None):
    """Process a single APK file and generate callgraph."""
    apk_name = os.path.basename(apk_path)
    apk_base_name = os.path.splitext(apk_name)[0]
    
    print(f"\n{'='*80}")
    if category:
        print(f"Category: {category}")
    print(f"Processing: {apk_name}")
    print(f"Output: {output_file}")
    print(f"{'='*80}")
    
    # Create output directory if needed
    os.makedirs(os.path.dirname(output_file), exist_ok=True)
    
    # Absolute paths (Androguard/Click need reliable paths; cwd may vary)
    apk_path_abs = os.path.abspath(apk_path)
    output_file_abs = os.path.abspath(output_file)
    
    # Modified Androguard fork (Modification-Androguard) exposes CLI via
    # androguard.cli.cli (Click entry_point + "cg" subcommand), not androguard.cli.main.
    # After: pip install -e /path/to/Modification-Androguard/androguard
    #   use the same Python: python3 -m androguard.cli.cli --verbose cg ...
    cmd = [
        sys.executable,
        "-m",
        "androguard.cli.cli",
        "--verbose",
        "cg",
        "--output-type", "txt",
        "-o", output_file_abs,
        apk_path_abs,
    ]
    
    # Record start time
    start_time = time.time()
    start_datetime = datetime.now().isoformat()
    
    try:
        # Run androguard command
        androguard_process = subprocess.Popen(
            cmd,
            stdout=subprocess.PIPE,
            stderr=subprocess.PIPE,
            text=True
        )
        
        # Get psutil Process object for monitoring
        resource_metrics = {}
        cpu_samples = []
        memory_samples = []
        
        try:
            psutil_process = psutil.Process(androguard_process.pid)
            # Start monitoring thread
            monitor_thread = threading.Thread(
                target=monitor_process_thread,
                args=(psutil_process, androguard_process, cpu_samples, memory_samples),
                daemon=True
            )
            monitor_thread.start()
        except (psutil.NoSuchProcess, psutil.AccessDenied) as e:
            print(f"Warning: Could not monitor process resources: {e}")
        
        # Wait for completion
        stdout, stderr = androguard_process.communicate()
        
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
            # Always write stderr (may be empty)
            with open(stderr_log_file, "w", encoding="utf-8", errors="ignore") as f:
                if stderr:
                    f.write(stderr)
        except Exception as e:
            print(f"Warning: Could not write stderr log file: {e}")
            stderr_log_path = ""
        
        # Check if successful - both return code and output file must exist with content
        output_file_exists = os.path.exists(output_file)
        output_file_has_content = output_file_exists and os.path.getsize(output_file) > 0
        success = androguard_process.returncode == 0 and output_file_has_content
        
        if success:
            print(f"✓ Successfully processed {apk_name}")
        else:
            if androguard_process.returncode == 0 and not output_file_has_content:
                print(f"⚠ Processed {apk_name} but output file is empty (no call graph generated)")
                if stderr:
                    print(f"Warning: {stderr[:500]}")
            else:
                print(f"✗ Failed to process {apk_name}")
                print(f"Error: {stderr[:500] if stderr else 'Unknown error'}")
        
        # Derive status and error_tag
        # status: success | timeout | failure
        # error_tag: java_heap_oom | parse_error | no_output | timeout | other | ""
        status = "success" if success else "failure"
        error_tag = ""
        if not success:
            err_text = (stderr or "").lower()
            if "timeout" in err_text:
                status = "timeout"
                error_tag = "timeout"
            elif "outofmemoryerror" in err_text or "memoryerror" in err_text:
                error_tag = "oom"
            elif "file format violation" in err_text or "badzipfile" in err_text or "not a zip file" in err_text:
                error_tag = "parse_error"
            elif androguard_process.returncode == 0 and not output_file_has_content:
                error_tag = "no_output"
            else:
                error_tag = "other"
        
        # Analyze callgraph if successful
        callgraph_stats = {}
        if success and output_file_has_content:
            callgraph_stats = analyze_callgraph(output_file)
        elif output_file_exists and not output_file_has_content:
            # Even if empty, return empty stats
            callgraph_stats = {'edges': 0, 'methods': 0}
        
        result = {
            'tool_name': 'Androguard',
            'apk_name': apk_name,
            'apk_path': apk_path,
            'category': category,
            'algorithm': '',
            'output_file': output_file,
            'start_time': start_datetime,
            'end_time': datetime.now().isoformat(),
            'duration_seconds': round(duration_seconds, 2),
            'duration_minutes': round(duration_minutes, 2),
            'success': success,
            'status': status,
            'error_tag': error_tag,
            'stderr_log_path': stderr_log_path,
            # return_code kept for debugging but not part of primary RQ
            'return_code': androguard_process.returncode,
            'resource_usage': resource_metrics,
            'callgraph_stats': callgraph_stats
        }
        
        return result
        
    except Exception as e:
        end_time = time.time()
        duration_seconds = end_time - start_time
        
        print(f"✗ Exception while processing {apk_name}: {str(e)}")
        
        # For unexpected exceptions, mark as failure with generic error_tag
        result = {
            'tool_name': 'Androguard',
            'apk_name': apk_name,
            'apk_path': apk_path,
            'category': category,
            'algorithm': '',
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
    """Main function to process all APKs."""
    parser = argparse.ArgumentParser(
        description='Generate callgraphs for APKs using androguard',
        formatter_class=argparse.RawDescriptionHelpFormatter,
        epilog="""
Examples:
  # Run on DroidBench APKs
  python3 generate_callgraphs_androguard.py --dataset droidbench
  
  # Run on APKPure APKs
  python3 generate_callgraphs_androguard.py --dataset apkpure
  
  # Run on custom folder
  python3 generate_callgraphs_androguard.py --input-dir /path/to/apks --output-dir /path/to/output
"""
    )
    parser.add_argument('--dataset', '-d', choices=['apkpure', 'droidbench'],
                        help='Dataset to process (apkpure or droidbench)')
    parser.add_argument('--input-dir', '-i', help='Custom input directory with APKs')
    parser.add_argument('--output-dir', '-o', help='Custom output directory for callgraphs')
    parser.add_argument('--log-file', '-l', help='Custom log file path')
    parser.add_argument('--recursive', '-r', action='store_true',
                        help='Scan input directory recursively (for categorized APKs like DroidBench)')
    parser.add_argument('--category', '-c', help='Process only specific category (for DroidBench)')
    
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
    
    # Create output folder if it doesn't exist
    os.makedirs(output_folder, exist_ok=True)
    os.makedirs(os.path.dirname(log_file), exist_ok=True)
    
    # Check if input folder exists
    if not os.path.exists(input_folder):
        print(f"Error: Input folder not found: {input_folder}")
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
    if categories:
        print(f"Categories: {len(categories)} ({', '.join(sorted(categories))})")
    print(f"Root output folder: {output_folder}")
    print(f"Global log file: {log_file}")
    
    # Load existing log if it exists
    results = []
    if os.path.exists(log_file):
        try:
            with open(log_file, 'r') as f:
                results = json.load(f)
            print(f"Loaded {len(results)} previous results from log file")
        except:
            results = []
    
    # Get list of already attempted APKs (apk_path), regardless of success.
    # This mirrors FlowDroid behavior: once an APK has an entry in the log,
    # it will be skipped on subsequent runs (unless you remove/edit its log entry).
    processed_apks = set(r.get('apk_path') for r in results)
    
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
        global_idx += 1
        
        # Category header when we enter a new category
        if category != current_category:
            current_category = category
            cat_idx = 0
            cat_name = current_category or os.path.basename(input_folder)
            cat_total = cat_counts[current_category]
            cat_output_folder = os.path.join(output_folder, cat_name) if current_category else output_folder
            cat_log_file = os.path.join(cat_output_folder, "processing_log.json")
            
            print(f"\n{'='*79}")
            print(f"[CATEGORY] {cat_name} ({cat_total} APKs)")
            print(f"Output folder: {cat_output_folder}")
            print(f"Category log: {cat_log_file}")
            print(f"{'='*79}")
        
        cat_idx += 1
        
        # Determine output file path (needed for skip check)
        apk_base_name = os.path.splitext(os.path.basename(apk_path))[0]
        if current_category:
            # Categorized: preserve category structure
            output_file = os.path.join(output_folder, current_category, f"{apk_base_name}.txt")
        else:
            # Flat structure or single folder
            output_file = os.path.join(output_folder, f"{apk_base_name}.txt")
        
        # Skip if already processed successfully (from log)
        # OR if the expected output file already exists and is non-empty.
        file_exists = os.path.exists(output_file)
        file_size = os.path.getsize(output_file) if file_exists else 0
        
        if (apk_path in processed_apks or
            (file_exists and file_size > 0)):
            
            reason = "already processed (log)" if apk_path in processed_apks else f"output exists ({file_size} bytes), skipping re-run"
            print(f"\n[{cat_idx}/{cat_counts[current_category]} in {current_category or os.path.basename(input_folder)}] "
                  f"[{global_idx}/{total_apks} total] Skipping ({reason}): {os.path.basename(apk_path)}")
            continue
        
        print(f"\n[{cat_idx}/{cat_counts[current_category]} in {current_category or os.path.basename(input_folder)}] "
              f"[{global_idx}/{total_apks} total] Processing APK...")
        
        result = process_apk(apk_path, output_file, current_category)
        results.append(result)
        
        # Save global progress after each APK
        try:
            with open(log_file, 'w') as f:
                json.dump(results, f, indent=2)
        except OSError as e:
            if e.errno == 122:  # Disk quota exceeded
                print(f"⚠ Warning: Could not save log file due to disk quota: {e}")
                print(f"   Results are still being processed, but log won't be updated until quota is resolved.")
            else:
                raise
        
        # Also maintain per-category log
        try:
            os.makedirs(os.path.dirname(output_file), exist_ok=True)
            cat_log_file = os.path.join(os.path.dirname(output_file), "processing_log.json")
            cat_results = []
            if os.path.exists(cat_log_file):
                try:
                    with open(cat_log_file, 'r') as cf:
                        cat_results = json.load(cf)
                except Exception:
                    cat_results = []
            cat_results.append(result)
            try:
                with open(cat_log_file, 'w') as cf:
                    json.dump(cat_results, cf, indent=2)
            except OSError as e:
                if e.errno == 122:  # Disk quota exceeded
                    print(f"⚠ Warning: Could not save category log file due to disk quota: {e}")
                else:
                    raise
        except Exception as e:
            print(f"Warning: Could not update category log for {current_category}: {e}")
        
        # Print summary
        if result['success']:
            callgraph_stats = result.get('callgraph_stats', {})
            edges_count = callgraph_stats.get('edges', 0)
            methods_count = callgraph_stats.get('methods', 0)
            
            print(f"\nSummary for {result['apk_name']}:")
            print(f"  Tool: {result.get('tool_name', 'Androguard')}")
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
    
    # Final summary
    total_duration = time.time() - total_start_time
    successful = sum(1 for r in results if r.get('success', False))
    failed = len(results) - successful
    failed_results = [r for r in results if not r.get('success', False)]
    
    # Category breakdown for DroidBench
    if categories:
        print(f"\n{'='*80}")
        print("CATEGORY BREAKDOWN")
        print(f"{'='*80}")
        for cat in sorted(categories):
            cat_results = [r for r in results if r.get('category') == cat]
            cat_success = sum(1 for r in cat_results if r.get('success', False))
            print(f"  {cat}: {cat_success}/{len(cat_results)} successful")
    
    print(f"\n{'='*80}")
    print("FINAL SUMMARY")
    print(f"{'='*80}")
    print(f"Total APKs processed: {len(results)}")
    print(f"Successful: {successful}")
    print(f"Failed: {failed}")
    if failed_results:
        print("\nFailed APKs so far:")
        for r in failed_results:
            apk_name = r.get('apk_name')
            status = r.get('status', 'failure')
            error_tag = r.get('error_tag', '')
            if error_tag:
                print(f"  - {apk_name} (status={status}, error_tag={error_tag})")
            else:
                print(f"  - {apk_name} (status={status})")
    print(f"Total time: {total_duration/60:.2f} minutes ({total_duration:.2f} seconds)")
    print(f"Results saved to: {log_file}")
    print(f"{'='*80}")

if __name__ == "__main__":
    main()
