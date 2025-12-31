
import os
import sys
import subprocess
import uuid
import shutil
import time
import argparse
import signal
from pathlib import Path

# -------------------------------------------------------------
# CONSTANTS & CONFIGURATION
# -------------------------------------------------------------
CGROUP_ROOT = "/sys/fs/cgroup"
SANDBOX_CGROUP_PARENT = "sandbox_project"
LAUNCHER_BIN = "./runner/launcher"
UID_MAP_OFFSET = 100000 
GID_MAP_OFFSET = 100000

class SandboxController:
    def __init__(self, cpus=0.5, memory="128M", pids=20, time_limit=5):
        self.run_id = str(uuid.uuid4())[:8]
        self.cgroup_path = os.path.join(CGROUP_ROOT, SANDBOX_CGROUP_PARENT, self.run_id)
        
        # Resource Limits
        self.cpu_quota = int(cpus * 100000) # CFS Quota (us) per 100ms period
        self.memory_limit = memory
        self.pids_limit = str(pids)
        self.time_limit = time_limit
        
        # Paths
        self.exec_path = None

    def setup_cgroups(self):
        """
        5. Mandatory OS Algorithms
        A. CPU SCHEDULING (CFS via Cgroups)
        B. MEMORY MANAGEMENT (OOM Killer via Cgroups)
        """
        print(f"[Controller] Creating Cgroup: {self.cgroup_path}")
        try:
            os.makedirs(self.cgroup_path, exist_ok=True)
            
            # Enforce CPU Quota (CFS)
            # cpu.max: "quota period"
            with open(os.path.join(self.cgroup_path, "cpu.max"), "w") as f:
                f.write(f"{self.cpu_quota} 100000")
                
            # Enforce Memory Limit
            with open(os.path.join(self.cgroup_path, "memory.max"), "w") as f:
                f.write(self.memory_limit)
                
            # Enforce PID Limit (Fork Bomb Protection)
            with open(os.path.join(self.cgroup_path, "pids.max"), "w") as f:
                f.write(self.pids_limit)
                
            # Enable Memory Swap accounting to prevent swap exhaustion (optional/if supported)
            # with open(os.path.join(self.cgroup_path, "memory.swap.max"), "w") as f: f.write("0")

        except PermissionError:
            print("WARNING: Not running as root. Cgroup resource limits will be SKIPPED (Demo Mode).")
            return
        except Exception as e:
            print(f"WARNING: Cgroup error: {e}. Proceeding in Demo Mode.")
            return

    def cleanup(self):
        """
        Destroys the isolated environment.
        """
        print(f"[Controller] Cleaning up environment...")
        if os.path.exists(self.cgroup_path):
            try:
                os.rmdir(self.cgroup_path)
            except OSError:
                # Often fails if processes are still zombie; wait logic handles this usually
                pass
        
        if self.exec_path and os.path.exists(self.exec_path):
            os.remove(self.exec_path)

    def compile(self, source_path):
        """
        Compiles untrusted code.
        """
        if not source_path.endswith(".c"):
            print("Only C files supported for this demo.")
            return

        print(f"[Controller] Compiling {source_path}...")
        self.exec_path = f"/tmp/sandbox_exec_{self.run_id}"
        
        cmd = ["gcc", source_path, "-o", self.exec_path]
        result = subprocess.run(cmd, capture_output=True)
        
        if result.returncode != 0:
            print(f"Compilation Failed:\n{result.stderr.decode()}")
            sys.exit(1)
        
        print("[Controller] Compilation Successful.")

    def run(self):
        """
        Executes the sandbox.
        """
        print(f"[Controller] Launching Process Isolation Wrapper...")
        
        # We start the wrapper using subprocess
        # Pre-execution hook to attach to Cgroup
        
        def preexec_fn():
            # Add this process to Cgroup
            pid = os.getpid()
            try:
                # In Demo Mode (Non-Root), this path won't exist or be writable.
                if os.path.exists(os.path.join(self.cgroup_path, "cgroup.procs")):
                    with open(os.path.join(self.cgroup_path, "cgroup.procs"), "w") as f:
                        f.write(str(pid))
            except Exception as e:
                # Just warn in demo mode
                pass
                
        start_time = time.time()
        
        cmd = [LAUNCHER_BIN, self.exec_path]
        
        try:
            # Running the C wrapper
            process = subprocess.Popen(
                cmd,
                preexec_fn=preexec_fn,
                stdout=subprocess.PIPE,
                stderr=subprocess.PIPE
            )
            
            try:
                stdout, stderr = process.communicate(timeout=self.time_limit)
                print("\n--- SANDBOX OUTPUT ---")
                print(stdout.decode(errors='replace'))
                print("--- SANDBOX ERRORS ---")
                print(stderr.decode(errors='replace'))
                
                if process.returncode != 0:
                    print(f"Process exited with code {process.returncode}")
                else:
                    print("Execution completed successfully.")

            except subprocess.TimeoutExpired:
                print(f"\n[Controller] TIMEOUT ({self.time_limit}s) EXCEEDED! Killing process...")
                process.kill()
                print("Process terminated.")
                
        except Exception as e:
            print(f"Execution Error: {e}")

if __name__ == "__main__":
    if os.getuid() != 0:
        print("CRITICAL: Sandbox Controller must act as Root to configure Cgroups/Namespaces.")
        # Proceeding for code check, but execution will fail without sudo
        
    parser = argparse.ArgumentParser(description='OS Sandbox Controller')
    parser.add_argument('source', help='Path to source code')
    parser.add_argument('--cpu', type=float, default=0.2, help='CPU Quota (Cores)')
    parser.add_argument('--mem', type=str, default='64M', help='Memory Limit')
    parser.add_argument('--pids', type=int, default=20, help='PID Limit')
    parser.add_argument('--time_limit', type=int, default=5, help='Time Limit (seconds)')
    args = parser.parse_args()

    sandbox = SandboxController(cpus=args.cpu, memory=args.mem, pids=args.pids, time_limit=args.time_limit)
    
    try:
        sandbox.setup_cgroups()
        sandbox.compile(args.source)
        sandbox.run()
    finally:
        sandbox.cleanup()
