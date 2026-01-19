# Log Directory

This directory stores telemetry logs from sandbox executions.

## Files Generated

- `run_<pid>_<timestamp>.json` - Main telemetry from /proc polling
- `ebpf_<pid>_<timestamp>.json` - eBPF syscall data (when --enable-ebpf used)

## Structure

Each log contains:
- Program metadata (name, profile, PID)
- Resource usage timeline (CPU, memory)
- Exit reason and status
- Syscall events (if eBPF enabled)

## Usage

Logs are automatically loaded by the dashboard for ML analysis and visualization.
