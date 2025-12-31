import os
import json
import glob
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
            print(f"Error reading {f}: {e}")
    return logs

def compute_statistics(logs):
    """Compute comprehensive statistics from all logs"""
    if not logs:
        return {}
    
    stats = {
        "total_runs": len(logs),
        "by_profile": {},
        "by_exit_reason": {},
        "syscall_violations": 0,
        "avg_runtime_ms": 0,
        "avg_cpu_percent": 0,
        "avg_memory_kb": 0
    }
    
    runtimes = []
    cpus = []
    mems = []
    
    for log in logs:
        summary = log.get("summary", {})
        profile = log.get("profile", "UNKNOWN")
        exit_reason = summary.get("exit_reason", "UNKNOWN")
        
        # By profile
        if profile not in stats["by_profile"]:
            stats["by_profile"][profile] = {"count": 0, "avg_cpu": 0, "avg_mem": 0}
        stats["by_profile"][profile]["count"] += 1
        
        # By exit reason
        if exit_reason not in stats["by_exit_reason"]:
            stats["by_exit_reason"][exit_reason] = 0
        stats["by_exit_reason"][exit_reason] += 1
        
        # Syscall violations
        if "VIOLATION" in exit_reason:
            stats["syscall_violations"] += 1
        
        # Accumulate for averages
        runtimes.append(summary.get("runtime_ms", 0))
        cpus.append(summary.get("peak_cpu", 0))
        mems.append(summary.get("peak_memory_kb", 0))
    
    # Compute averages
    if runtimes:
        stats["avg_runtime_ms"] = int(np.mean(runtimes))
        stats["avg_cpu_percent"] = int(np.mean(cpus))
        stats["avg_memory_kb"] = int(np.mean(mems))
    
    # Profile-specific averages
    for profile in stats["by_profile"]:
        profile_logs = [l for l in logs if l.get("profile") == profile]
        if profile_logs:
            profile_cpus = [l.get("summary", {}).get("peak_cpu", 0) for l in profile_logs]
            profile_mems = [l.get("summary", {}).get("peak_memory_kb", 0) for l in profile_logs]
            stats["by_profile"][profile]["avg_cpu"] = int(np.mean(profile_cpus))
            stats["by_profile"][profile]["avg_mem"] = int(np.mean(profile_mems))
    
    return stats

def get_memory_growth_rate(log):
    """Calculate memory growth rate from timeline"""
    timeline = log.get("timeline", {})
    mem_samples = timeline.get("memory_kb", [])
    
    if len(mem_samples) < 2:
        return 0.0
    
    x = np.arange(len(mem_samples))
    y = np.array(mem_samples)
    
    if np.std(y) == 0:
        return 0.0
    
    slope = np.polyfit(x, y, 1)[0]
    return float(slope)

def get_syscall_frequency(logs):
    """Count blocked syscalls"""
    syscall_counts = {}
    
    for log in logs:
        syscall = log.get("summary", {}).get("blocked_syscall", "")
        if syscall and syscall != "":
            if syscall not in syscall_counts:
                syscall_counts[syscall] = 0
            syscall_counts[syscall] += 1
    
    return syscall_counts
