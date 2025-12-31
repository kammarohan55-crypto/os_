# Testing Instructions (WSL2)

Since this sandbox uses **Linux Control Groups (cgroups v2)** and **Namespaces**, it **MUST** be run inside a Linux environment like WSL2 (Ubuntu). It will **NOT** work directly in Windows PowerShell.

## 1. Open WSL Terminal
Open your terminal and type:
```bash
wsl
```
Navigate to your project directory. If it is on your desktop, it is likely at:
```bash
cd /mnt/c/Users/Rohan/Desktop/os_el/sandbox-project
```

## 2. Compile the Launcher
We need to compile the C wrapper that handles namespaces. I have added a `Makefile` for you.
```bash
make
```
*If `make` is not installed, run: `sudo apt update && sudo apt install build-essential`*

## 3. Run the Tests (Root Required)
The sandbox requires `sudo` to set up cgroups and namespaces.

### Test 1: CPU Hog (Should be throttled)
This program tries to use 100% CPU. The sandbox limits it to 20% (0.2 cores).
```bash
sudo python3 runner/sandbox.py samples/cpu_hog.c --cpu 0.2 --time_limit 10
```
**Expected Output:** The process runs, but if you check `top` in another window, it should not exceed ~20% CPU. It limits execution time to 10s.

### Test 2: Memory Eater (Should OOM Kill)
This program tries to eat 512MB RAM. The sandbox limits it to 64MB.
```bash
sudo python3 runner/sandbox.py samples/mem_eater.c --mem 64M
```
**Expected Output:**
```
Sandbox created.
...
Process killed by signal: 9 (SIGKILL)
```
*(Signal 9 usually indicates OOM Killer intervention).*

### Test 3: Fork Bomb (Should be contained)
This program tries to spawn infinite processes. The sandbox limits PIDs to 20.
```bash
sudo python3 runner/sandbox.py samples/fork_bomb.c --pids 20
```
**Expected Output:**
```
[Sandbox-Child] PID: ...
...
fork failed: Resource temporarily unavailable
```
*(It stops spawning after ~20 processes).*

### Test 4: File System Attack (Should fail)
This program tries to read `/etc/shadow` or write to `/bin`.
```bash
sudo python3 runner/sandbox.py samples/fs_attack.c
```
**Expected Output:**
```
fopen /etc/shadow: EACCES (Permission Denied)
or
Child exited with status: ...
```
*(The read-only filesystem mount prevents writing, and permissions prevent reading sensitive root files).*

## Troubleshooting
- **cgroup2 not mounted?**
  WSL2 usually mounts cgroups v2 by default at `/sys/fs/cgroup`. run `mount | grep cgroup` to verify.
- **Permission Denied?**
  Ensure you are using `sudo`.
