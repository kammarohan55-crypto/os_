import os
import json
import glob
import pandas as pd
import numpy as np

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
    
    Returns: pandas DataFrame with flat structure
    """
    features = []
    
    for log in logs:
        summary = log.get('summary', {})
        timeline = log.get('timeline', {})
        
        # Extract summary features (guaranteed fields)
        feature_row = {
            'program': log.get('program', 'unknown'),
            'profile': log.get('profile', 'UNKNOWN'),
            'pid': log.get('pid', 0),
            
            # Core metrics from summary
            'runtime_ms': summary.get('runtime_ms', 0),
            'peak_cpu': summary.get('peak_cpu', 0),
            'peak_memory_kb': summary.get('peak_memory_kb', 0),
            'page_faults_minor': summary.get('page_faults_minor', 0),
            'page_faults_major': summary.get('page_faults_major', 0),
            
            # Exit information
            'exit_reason': summary.get('exit_reason', 'UNKNOWN'),
            'termination': summary.get('termination', ''),
            'blocked_syscall': summary.get('blocked_syscall', ''),
            
            # Timeline-derived features
            'sample_count': len(timeline.get('time_ms', [])),
        }
        
        # Compute timeline statistics (safe)
        cpu_samples = timeline.get('cpu_percent', [])
        mem_samples = timeline.get('memory_kb', [])
        
        if cpu_samples:
            feature_row['avg_cpu'] = int(np.mean(cpu_samples))
            feature_row['cpu_variance'] = float(np.var(cpu_samples))
        else:
            feature_row['avg_cpu'] = 0
            feature_row['cpu_variance'] = 0.0
        
        if mem_samples and len(mem_samples) >= 2:
            # Memory growth rate (KB per sample)
            feature_row['memory_growth_rate'] = float((mem_samples[-1] - mem_samples[0]) / len(mem_samples))
            feature_row['avg_memory_kb'] = int(np.mean(mem_samples))
        else:
            feature_row['memory_growth_rate'] = 0.0
            feature_row['avg_memory_kb'] = feature_row['peak_memory_kb']
        
        features.append(feature_row)
    
    return pd.DataFrame(features)

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
    
    # By profile
    for profile in df['profile'].unique():
        profile_df = df[df['profile'] == profile]
        stats["by_profile"][profile] = {
            "count": len(profile_df),
            "avg_cpu": int(profile_df['peak_cpu'].mean()),
            "avg_mem": int(profile_df['peak_memory_kb'].mean()),
            "avg_runtime": int(profile_df['runtime_ms'].mean())
        }
    
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
