import pandas as pd
import json
import os
import glob
import yaml
from collections import defaultdict
import numpy as np

# Load scenario-based ground truth labels
SCENARIO_LABELS_PATH = '../samples/scenario_labels.yaml'

def load_scenario_labels():
    """
    Load ground truth labels from YAML.
    
    CRITICAL: Labels are from scenario identity, NOT feature thresholds.
    This ensures valid supervised learning.
    """
    try:
        with open(SCENARIO_LABELS_PATH) as f:
            data = yaml.safe_load(f)
            return data.get('scenarios', {})
    except FileNotFoundError:
        print(f"[WARNING] Scenario labels not found at {SCENARIO_LABELS_PATH}")
        return {}

SCENARIO_LABELS = load_scenario_labels()

def get_ground_truth_label(program_name):
    """
    Get label from scenario identity, NOT from metrics.
    
    Critical for ML validity:
    - No circular logic (features → labels → features)
    - True supervised learning
    - Reproducible evaluation
    
    Args:
        program_name: str, e.g. "cpu_hog", "/bin/ls", "samples/fork_bomb"
    
    Returns:
        str: 'malicious_sim', 'benign', or 'unknown'
    """
    # Extract base name
    base_name = os.path.basename(program_name)
    
    # Check scenario mapping
    for scenario, config in SCENARIO_LABELS.items():
        if scenario in base_name.lower() or scenario in program_name.lower():
            return config['label']
    
    # Default for unknown programs
    return 'unknown'

def identify_scenario(program_name):
    """Get scenario name from program"""
    base_name = os.path.basename(program_name).lower()
    
    for scenario in SCENARIO_LABELS.keys():
        if scenario in base_name:
            return scenario
    
    return 'unknown'

def load_all_logs(log_dir="../logs"):
    """Load all JSON telemetry logs"""
    files = glob.glob(os.path.join(log_dir, "*.json"))
    logs = []
    for f in files:
        try:
            with open(f, 'r') as fh:
                log = json.load(fh)
                log['_file'] = f
                logs.append(log)
        except Exception as e:
            print(f"[Analytics] Error reading {f}: {e}")
    return logs

def extract_features(logs):
    """
    FEATURE EXTRACTION LAYER (Critical for research correctness)
    
    Converts raw telemetry logs into structured feature DataFrame.
    This is the ONLY input to ML and analytics.
    
    LABELS: From scenario identity (YAML), NOT feature thresholds!
    
    Returns: pandas DataFrame with flat structure
    """
    features_list = []
    
    for log in logs:
        # Get ground truth label from scenario identity
        # CRITICAL: This is NOT derived from features!
        program = log.get('program', '')
        true_label = get_ground_truth_label(program)
        scenario = identify_scenario(program)
        
        # Extract features (5 original + 3 eBPF)
        features = {
            'program': program,
            'scenario': scenario,
            'runtime_ms': log.get('runtime_ms', 0),
            'peak_cpu': log.get('peak_cpu_percent', 0),
            'peak_memory_kb': log.get('peak_memory_kb', 0),
            'page_faults_minor': 0,
            'page_faults_major': 0,
            'exit_reason': log.get('exit_reason', ''),
            
            # Syscall features from eBPF (Phase 2)
            'syscall_rate': 0,
            'syscall_diversity': 0,
            'syscall_network_count': 0,
            'total_syscalls': 0,
            
            # Ground truth label (from scenario, NOT thresholds)
            'true_label': true_label
        }
        
        # Extract syscall features if eBPF data exists
        if 'syscall_events' in log:
            events = log['syscall_events']
            features['syscall_rate'] = events.get('syscall_rate_per_sec', 0)
            features['syscall_diversity'] = events.get('unique_syscalls', 0)
            features['syscall_network_count'] = events.get('network_syscalls', 0)
            features['total_syscalls'] = events.get('total_syscalls', 0)
        
        # Extract page faults from summary or telemetry
        summary = log.get('summary', {})
        features['page_faults_minor'] = summary.get('page_faults_minor', 0)
        features['page_faults_major'] = summary.get('page_faults_major', 0)
        
        features_list.append(features)
    
    return pd.DataFrame(features_list)
    
    return pd.DataFrame(features_list)


def compute_statistics(df):
    """Compute comprehensive statistics from feature DataFrame"""
    if df.empty:
        return {
            "total_runs": 0,
            "by_profile": {},
            "by_exit_reason": {},
            "syscall_violations": 0
        }
    
    stats = {
        "total_runs": len(df),
        "by_profile": {},
        "by_exit_reason": {},
        "syscall_violations": int(df['exit_reason'].str.contains('VIOLATION', na=False).sum()),
        "avg_runtime_ms": int(df['runtime_ms'].mean()),
        "avg_cpu_percent": int(df['peak_cpu'].mean()),
        "avg_memory_kb": int(df['peak_memory_kb'].mean())
    }
    
    # By-profile breakdown (optional - field may not exist)
    by_profile = {}
    if 'profile' in df.columns:
        for profile in df['profile'].unique():
            subset = df[df['profile'] == profile]
            by_profile[profile] = {
                'count': len(subset),
                'avg_cpu': float(subset['peak_cpu'].mean()) if 'peak_cpu' in subset.columns else 0,
                'avg_mem': float(subset['peak_memory_kb'].mean()) if 'peak_memory_kb' in subset.columns else 0,
                'avg_runtime': float(subset['runtime_ms'].mean()) if 'runtime_ms' in subset.columns else 0
            }
    else:
        # No profile field, use defaults
        by_profile = {'default': {
            'count': len(df),
            'avg_cpu': float(df['peak_cpu'].mean()) if 'peak_cpu' in df.columns and len(df) > 0 else 0,
            'avg_mem': float(df['peak_memory_kb'].mean()) if 'peak_memory_kb' in df.columns and len(df) > 0 else 0,
            'avg_runtime': float(df['runtime_ms'].mean()) if 'runtime_ms' in df.columns and len(df) > 0 else 0
        }}
    stats["by_profile"] = by_profile
    
    # By exit reason
    exit_counts = df['exit_reason'].value_counts().to_dict()
    stats["by_exit_reason"] = exit_counts
    
    return stats

def get_syscall_frequency(df):
    """Count blocked syscalls"""
    if df.empty:
        return {}
    
    # Filter non-empty syscalls
    syscalls = df[df['blocked_syscall'] != '']['blocked_syscall']
    return syscalls.value_counts().to_dict()

def get_syscall_stats(logs):
    """Extract eBPF syscall statistics from logs"""
    syscall_data = []
    
    for log in logs:
        syscall_events = log.get('syscall_events', {})
        if syscall_events:
            top_syscalls = syscall_events.get('top_syscalls', [])
            for sc in top_syscalls:
                syscall_data.append({
                    'program': log.get('program', 'unknown'),
                    'syscall_name': sc['name'],
                    'count': sc['count']
                })
    
    if not syscall_data:
        return None
    
    return pd.DataFrame(syscall_data)
