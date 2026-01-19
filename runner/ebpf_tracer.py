#!/usr/bin/env python3
"""
eBPF-based Syscall Tracer for OS Sandbox
Uses BCC to capture syscalls from sandboxed process with <1% overhead
"""

import sys
import json
import time
from collections import defaultdict
from bcc import BPF

# BPF program (C code embedded in Python)
BPF_PROGRAM = """
#include <uapi/linux/ptrace.h>

// Data structures
struct syscall_event_t {
    u32 pid;
    u32 syscall_id;
    u64 timestamp_ns;
};

// Hash map: syscall_id -> count
BPF_HASH(syscall_counts, u32, u64);

// Perf event output for real-time streaming (optional)
BPF_PERF_OUTPUT(events);

// Tracepoint for syscall entry
TRACEPOINT_PROBE(raw_syscalls, sys_enter) {
    u64 pid_tgid = bpf_get_current_pid_tgid();
    u32 pid = pid_tgid >> 32;
    
    // Filter: only track TARGET_PID
    if (pid != TARGET_PID) {
        return 0;
    }
    
    // Get syscall ID from tracepoint args
    u32 syscall_id = args->id;
    
    // Increment syscall count
    u64 zero = 0;
    u64 *count = syscall_counts.lookup_or_try_init(&syscall_id, &zero);
    if (count) {
        (*count)++;
    }
    
    // Optional: send event for real-time monitoring
    struct syscall_event_t evt = {};
    evt.pid = pid;
    evt.syscall_id = syscall_id;
    evt.timestamp_ns = bpf_ktime_get_ns();
    events.perf_submit(args, &evt, sizeof(evt));
    
    return 0;
}
"""

# Syscall ID to name mapping (x86_64 Linux)
SYSCALL_NAMES = {
    0: "read", 1: "write", 2: "open", 3: "close", 4: "stat",
    5: "fstat", 6: "lstat", 7: "poll", 8: "lseek", 9: "mmap",
    10: "mprotect", 11: "munmap", 12: "brk", 13: "rt_sigaction",
    14: "rt_sigprocmask", 15: "rt_sigreturn", 16: "ioctl", 17: "pread64",
    18: "pwrite64", 19: "readv", 20: "writev", 21: "access",
    22: "pipe", 23: "select", 24: "sched_yield", 25: "mremap",
    26: "msync", 27: "mincore", 28: "madvise", 29: "shmget",
    30: "shmat", 31: "shmctl", 32: "dup", 33: "dup2",
    34: "pause", 35: "nanosleep", 36: "getitimer", 37: "alarm",
    38: "setitimer", 39: "getpid", 40: "sendfile", 41: "socket",
    42: "connect", 43: "accept", 44: "sendto", 45: "recvfrom",
    46: "sendmsg", 47: "recvmsg", 48: "shutdown", 49: "bind",
    50: "listen", 51: "getsockname", 52: "getpeername", 53: "socketpair",
    54: "setsockopt", 55: "getsockopt", 56: "clone", 57: "fork",
    58: "vfork", 59: "execve", 60: "exit", 61: "wait4",
    62: "kill", 63: "uname", 257: "openat", 318: "getrandom"
}

def get_syscall_name(syscall_id):
    """Convert syscall ID to human-readable name"""
    return SYSCALL_NAMES.get(syscall_id, f"syscall_{syscall_id}")

def is_network_syscall(syscall_id):
    """Check if syscall is network-related"""
    network_syscalls = {41, 42, 43, 44, 45, 46, 47, 48, 49, 50}  # socket-related
    return syscall_id in network_syscalls

class eBPFTracer:
    def __init__(self, target_pid):
        self.target_pid = target_pid
        self.bpf = None
        self.start_time = time.time()
        self.event_count = 0
        
    def load(self):
        """Load and attach BPF program"""
        try:
            # Replace TARGET_PID placeholder
            bpf_code = BPF_PROGRAM.replace("TARGET_PID", str(self.target_pid))
            
            # Compile and load BPF program
            self.bpf = BPF(text=bpf_code)
            
            print(f"[eBPF] Attached to PID {self.target_pid}", file=sys.stderr)
            return True
        except Exception as e:
            print(f"[eBPF] Failed to load BPF program: {e}", file=sys.stderr)
            return False
    
    def process_event(self, cpu, data, size):
        """Callback for perf events (real-time monitoring)"""
        self.event_count += 1
    
    def collect_stats(self):
        """Collect syscall statistics from BPF hash map"""
        syscall_counts = defaultdict(int)
        
        if self.bpf is None:
            return {}
        
        # Read syscall_counts hash map
        counts_map = self.bpf["syscall_counts"]
        for k, v in counts_map.items():
            syscall_id = k.value
            count = v.value
            syscall_counts[syscall_id] = count
        
        return syscall_counts
    
    def export_json(self):
        """Export syscall statistics as JSON"""
        syscall_counts = self.collect_stats()
        
        if not syscall_counts:
            return {
                "syscall_events": {
                    "total_syscalls": 0,
                    "unique_syscalls": 0,
                    "syscall_rate_per_sec": 0,
                    "top_syscalls": [],
                    "network_syscalls": 0
                }
            }
        
        # Calculate metrics
        total_syscalls = sum(syscall_counts.values())
        unique_syscalls = len(syscall_counts)
        elapsed_time = time.time() - self.start_time
        syscall_rate = total_syscalls / elapsed_time if elapsed_time > 0 else 0
        
        # Count network syscalls
        network_count = sum(
            count for syscall_id, count in syscall_counts.items()
            if is_network_syscall(syscall_id)
        )
        
        # Get top syscalls
        top_syscalls = sorted(
            [
                {
                    "name": get_syscall_name(syscall_id),
                    "id": syscall_id,
                    "count": count
                }
                for syscall_id, count in syscall_counts.items()
            ],
            key=lambda x: x["count"],
            reverse=True
        )[:10]  # Top 10
        
        return {
            "syscall_events": {
                "total_syscalls": total_syscalls,
                "unique_syscalls": unique_syscalls,
                "syscall_rate_per_sec": round(syscall_rate, 2),
                "top_syscalls": top_syscalls,
                "network_syscalls": network_count
            }
        }
    
    def cleanup(self):
        """Detach and cleanup BPF program"""
        if self.bpf:
            self.bpf.cleanup()
            print(f"[eBPF] Detached from PID {self.target_pid}", file=sys.stderr)

def main():
    if len(sys.argv) < 2:
        print("Usage: ebpf_tracer.py <target_pid> [output_json]", file=sys.stderr)
        sys.exit(1)
    
    target_pid = int(sys.argv[1])
    output_file = sys.argv[2] if len(sys.argv) > 2 else None
    
    tracer = eBPFTracer(target_pid)
    
    # Load BPF program
    if not tracer.load():
        sys.exit(1)
    
    # Open perf buffer for real-time events (optional)
    tracer.bpf["events"].open_perf_buffer(tracer.process_event)
    
    try:
        print(f"[eBPF] Tracing PID {target_pid}... Press Ctrl+C to stop", file=sys.stderr)
        
        # Poll for events until process exits
        while True:
            try:
                tracer.bpf.perf_buffer_poll(timeout=100)  # 100ms timeout
                
                # Check if process still exists
                try:
                    with open(f"/proc/{target_pid}/status", "r") as f:
                        pass  # Process exists
                except FileNotFoundError:
                    print(f"[eBPF] Process {target_pid} exited", file=sys.stderr)
                    break
                    
            except KeyboardInterrupt:
                break
    finally:
        # Export results
        stats = tracer.export_json()
        
        if output_file:
            with open(output_file, "w") as f:
                json.dump(stats, f, indent=2)
            print(f"[eBPF] Exported to {output_file}", file=sys.stderr)
        else:
            print(json.dumps(stats, indent=2))
        
        tracer.cleanup()

if __name__ == "__main__":
    main()
