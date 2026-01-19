#!/usr/bin/env python3
"""
eBPF Installation and Functionality Test
Verifies BCC is installed and can load basic BPF programs
"""

import sys
import os
import subprocess
import time

def test_bcc_import():
    """Test 1: Check if BCC is installed"""
    print("[1/5] Testing BCC import...")
    try:
        from bcc import BPF
        print("  ✅ BCC installed and importable")
        return True
    except ImportError as e:
        print(f"  ❌ BCC not installed: {e}")
        print()
        print("  Install with:")
        print("    sudo apt update")
        print("    sudo apt install bpfcc-tools python3-bpfcc linux-headers-$(uname -r)")
        return False

def test_root_privileges():
    """Test 2: Check if running as root (required for BPF)"""
    print("\n[2/5] Checking root privileges...")
    if os.geteuid() == 0:
        print("  ✅ Running as root")
        return True
    else:
        print("  ⚠️  Not running as root")
        print("     BPF programs require root. Run with: sudo python3 test_ebpf.py")
        return False

def test_kernel_config():
    """Test 3: Check kernel BPF support"""
    print("\n[3/5] Checking kernel BPF support...")
    try:
        # Check if /sys/kernel/debug/tracing exists
        if os.path.exists("/sys/kernel/debug/tracing"):
            print("  ✅ Tracing filesystem available")
        else:
            print("  ⚠️  /sys/kernel/debug/tracing not found")
            print("     Mount with: sudo mount -t debugfs none /sys/kernel/debug")
        
        # Check kernel version
        kernel_version = subprocess.check_output(["uname", "-r"], text=True).strip()
        print(f"  ✅ Kernel version: {kernel_version}")
        
        return True
    except Exception as e:
        print(f"  ❌ Kernel check failed: {e}")
        return False

def test_minimal_bpf_program():
    """Test 4: Load a minimal BPF program"""
    print("\n[4/5] Loading minimal BPF program...")
    
    if os.geteuid() != 0:
        print("  ⚠️  Skipped (requires root)")
        return False
    
    try:
        from bcc import BPF
        
        # Minimal BPF program that does nothing
        minimal_program = """
        int hello(void *ctx) {
            return 0;
        }
        """
        
        bpf = BPF(text=minimal_program)
        print("  ✅ BPF program compiled successfully")
        
        bpf.cleanup()
        print("  ✅ BPF program cleaned up")
        
        return True
    except Exception as e:
        print(f"  ❌ Failed to load BPF program: {e}")
        return False

def test_syscall_tracepoint():
    """Test 5: Attach to syscall tracepoint"""
    print("\n[5/5] Testing syscall tracepoint attachment...")
    
    if os.geteuid() != 0:
        print("  ⚠️  Skipped (requires root)")
        return False
    
    try:
        from bcc import BPF
        
        # BPF program that attaches to getpid syscall
        test_program = """
        #include <uapi/linux/ptrace.h>
        
        BPF_HASH(counter, u32, u64);
        
        TRACEPOINT_PROBE(raw_syscalls, sys_enter) {
            u32 key = 0;
            u64 zero = 0;
            u64 *count = counter.lookup_or_try_init(&key, &zero);
            if (count) {
                (*count)++;
            }
            return 0;
        }
        """
        
        bpf = BPF(text=test_program)
        print("  ✅ Attached to tracepoint:raw_syscalls:sys_enter")
        
        # Trigger some syscalls
        time.sleep(0.1)
        os.getpid()  # Trigger syscall
        
        # Read counter
        counter_map = bpf["counter"]
        key = counter_map.Key(0)
        try:
            count = counter_map[key].value
            print(f"  ✅ Captured {count} syscall events")
        except KeyError:
            print("  ⚠️  No events captured (this is normal for short duration)")
        
        bpf.cleanup()
        print("  ✅ Detached successfully")
        
        return True
    except Exception as e:
        print(f"  ❌ Failed to attach tracepoint: {e}")
        import traceback
        traceback.print_exc()
        return False

def main():
    print("=" * 70)
    print("eBPF INSTALLATION TEST")
    print("=" * 70)
    print()
    
    results = []
    
    # Run tests
    results.append(("BCC Import", test_bcc_import()))
    results.append(("Root Privileges", test_root_privileges()))
    results.append(("Kernel Config", test_kernel_config()))
    results.append(("Minimal BPF Program", test_minimal_bpf_program()))
    results.append(("Syscall Tracepoint", test_syscall_tracepoint()))
    
    # Summary
    print()
    print("=" * 70)
    print("TEST SUMMARY")
    print("=" * 70)
    print()
    
    for test_name, passed in results:
        status = "✅ PASS" if passed else "❌ FAIL"
        print(f"  {status:10} - {test_name}")
    
    print()
    
    passed_count = sum(1 for _, passed in results if passed)
    total_count = len(results)
    
    if passed_count == total_count:
        print(f"✅ All tests passed ({passed_count}/{total_count})")
        print()
        print("Next steps:")
        print("  1. Run eBPF tracer: sudo python3 runner/ebpf_tracer.py <pid>")
        print("  2. Test with sandbox: ./runner/launcher --enable-ebpf samples/cpu_hog")
        return 0
    else:
        print(f"⚠️  {total_count - passed_count} test(s) failed")
        print()
        print("Fix issues above before using eBPF telemetry")
        return 1

if __name__ == "__main__":
    sys.exit(main())
