"""
Per-Process CPU Attribution (Phase 4 - Critical Fix)

Explicit per-PID CPU metrics using /proc/[pid]/stat parsing.
This ensures reviewers understand metrics are NOT system-wide.

Key fields from /proc/[pid]/stat:
- utime (field 14): CPU time in user mode (jiffies)
- stime (field 15): CPU time in kernel mode (jiffies)
- cutime (field 16): Children user time
- cstime (field 17): Children kernel time
- starttime (field 22): Process start time since boot

Conversion: jiffies → seconds using sysconf(_SC_CLK_TCK)
"""

import os
import time

def get_clock_ticks_per_second():
    """
    Get system clock ticks per second (usually 100 on Linux)
    """
    return os.sysconf(os.sysconf_names['SC_CLK_TCK'])

def parse_proc_stat(pid):
    """
    Parse /proc/[pid]/stat for explicit per-process CPU metrics
    
    Returns dict with:
    - utime_jiffies: CPU time in user mode
    - stime_jiffies: CPU time in kernel mode
    - utime_seconds: Converted to seconds
    - stime_seconds: Converted to seconds
    - total_cpu_seconds: Total CPU time
    - clock_ticks_per_sec: For reproducibility
    
    Critical for publication: Explicitly shows per-PID attribution
    """
    try:
        with open(f'/proc/{pid}/stat', 'r') as f:
            stat_line = f.read()
        
        # Parse the stat line
        # Format: pid (comm) state ppid ... utime stime cutime cstime ...
        # Need to handle process name with spaces/parens
        
        # Find last ')' to skip process name
        paren_end = stat_line.rfind(')')
        fields = stat_line[paren_end+2:].split()
        
        # Fields after ')' and state:
        # 0=ppid, 1=pgrp, 2=session, 3=tty_nr, 4=tpgid, 5=flags,
        # 6=minflt, 7=cminflt, 8=majflt, 9=cmajflt,
        # 10=utime, 11=stime, 12=cutime, 13=cstime
        
        utime_jiffies = int(fields[11])  # Field 14 in full stat
        stime_jiffies = int(fields[12])  # Field 15 in full stat
        
        # Convert jiffies to seconds
        clk_tck = get_clock_ticks_per_second()
        utime_seconds = utime_jiffies / clk_tck
        stime_seconds = stime_jiffies / clk_tck
        total_cpu_seconds = utime_seconds + stime_seconds
        
        return {
            'utime_jiffies': utime_jiffies,
            'stime_jiffies': stime_jiffies,
            'utime_seconds': round(utime_seconds, 3),
            'stime_seconds': round(stime_seconds, 3),
            'total_cpu_seconds': round(total_cpu_seconds, 3),
            'clock_ticks_per_sec': clk_tck
        }
    
    except (FileNotFoundError, ValueError, IndexError) as e:
        return None

def calculate_cpu_percent(pid, sample_interval=0.1):
    """
    Calculate per-process CPU percentage over sample interval
    
    This is explicitly per-PID, not system-wide!
    
    CPU% = (delta_cpu_time / delta_wall_time) * 100
    """
    # First sample
    stat1 = parse_proc_stat(pid)
    if not stat1:
        return None
    
    time1 = time.time()
    
    # Wait
    time.sleep(sample_interval)
    
    # Second sample
    stat2 = parse_proc_stat(pid)
    if not stat2:
        return None
    
    time2 = time.time()
    
    # Calculate delta
    delta_cpu = stat2['total_cpu_seconds'] - stat1['total_cpu_seconds']
    delta_wall = time2 - time1
    
    cpu_percent = (delta_cpu / delta_wall) * 100
    
    return {
        'cpu_percent': round(cpu_percent, 2),
        'delta_cpu_seconds': round(delta_cpu, 3),
        'delta_wall_seconds': round(delta_wall, 3),
        'sample_interval': sample_interval
    }

def get_comprehensive_cpu_metrics(pid):
    """
    Get comprehensive per-process CPU metrics for telemetry
    
    This function provides everything needed to prove:
    "All CPU metrics are derived from kernel-maintained per-process 
    accounting structures (/proc/[pid]/stat)"
    """
    raw_stat = parse_proc_stat(pid)
    if not raw_stat:
        return None
    
    cpu_usage = calculate_cpu_percent(pid)
    if not cpu_usage:
        return None
    
    return {
        'raw_proc_stat': raw_stat,
        'cpu_usage': cpu_usage,
        'attribution': 'per-process',  # NOT system-wide!
        'source': f'/proc/{pid}/stat'
    }

# Example for telemetry JSON:
"""
{
  "cpu_metrics": {
    "raw_proc_stat": {
      "utime_jiffies": 1234,
      "stime_jiffies": 567,
      "utime_seconds": 12.34,
      "stime_seconds": 5.67,
      "total_cpu_seconds": 18.01,
      "clock_ticks_per_sec": 100
    },
    "cpu_usage": {
      "cpu_percent": 95.2,
      "delta_cpu_seconds": 0.095,
      "delta_wall_seconds": 0.100,
      "sample_interval": 0.1
    },
    "attribution": "per-process",
    "source": "/proc/1234/stat"
  }
}

Now we can confidently say:
"CPU metrics are explicitly derived from kernel-maintained per-process 
accounting in /proc/[pid]/stat, with jiffies converted to seconds using 
sysconf(_SC_CLK_TCK)."
"""
