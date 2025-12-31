#define _GNU_SOURCE
#include <stdio.h>
#include <stdlib.h>
#include <unistd.h>
#include <sched.h>
#include <sys/wait.h>
#include <sys/resource.h>
#include <sys/mount.h>
#include <string.h>
#include <errno.h>
#include <fcntl.h>
#include <time.h>
#include "../policies/seccomp_rules.h"
#include "telemetry.h"

// Stack size for cloned child
#define STACK_SIZE (1024 * 1024)

/**
 * STRUCTURE:
 * 1. Parse Arguments (Binary to run)
 * 2. Setup Resources (RLIMIT)
 * 3. Isolate (Namespaces) - handled via 'unshare' or 'clone' logic
 * 4. Apply Seccomp
 * 5. Execve
 */

struct container_config {
    char *binary_path;
    char **args;
    sandbox_profile_t profile;
};

// Child process function
int child_fn(void *arg) {
    struct container_config *config = (struct container_config *)arg;

    printf("[Sandbox-Child] PID: %d inside new namespace\n", getpid());

    // -------------------------------------------------------------
    // F. INTERPROCESS COMMUNICATION (IPC)
    // Mechanism: IPC Isolation via Namespace
    // The child is in a new IPC namespace, so it cannot see host semaphores/shm.
    // -------------------------------------------------------------
    
    // -------------------------------------------------------------
    // E. FILE SYSTEM MANAGEMENT
    // Mechanism: Mount Namespace + Read-Only Root
    // -------------------------------------------------------------
    // 1. make mount setting private
    if (mount(NULL, "/", NULL, MS_PRIVATE | MS_REC, NULL) != 0) {
        perror("mount / private");
    }
    
    // 2. Remount / as Read-Only
    // This prevents the untrusted process from modifying ANY file in the system
    // unless we explicitly mount a writable tmpfs (which we skip for strict sandbox).
    if (mount(NULL, "/", NULL, MS_REMOUNT | MS_BIND | MS_RDONLY, NULL) != 0) {
       perror("mount / read-only");
       // Non-fatal for demo if unprivileged, but critical for security.
    } else {
       printf("[Sandbox-Child] Filesystem locked (Read-Only Root Enforced).\n");
    }
    
    // -------------------------------------------------------------
    // B. MEMORY MANAGEMENT (Soft Limits)
    // Mechanism: setrlimit() for Stack and Data
    // Hard limits are enforced by Cgroups v2 in the Python runner (or here if Resource Aware).
    // -------------------------------------------------------------
    if (config->profile == PROFILE_RESOURCE_AWARE) {
         // Tighter limits or specific ones for Resource Aware
         printf("[Sandbox-Child] Applying RESOURCE-AWARE limits...\n");
    }

    struct rlimit rl;
    // Limit stack to 8MB
    rl.rlim_cur = 8 * 1024 * 1024;
    rl.rlim_max = 8 * 1024 * 1024;
    setrlimit(RLIMIT_STACK, &rl);

    // Limit File Descriptors
    rl.rlim_cur = 64;
    rl.rlim_max = 64;
    setrlimit(RLIMIT_NOFILE, &rl);

    // B. MEMORY MANAGEMENT (Fallback if Cgroups fail)
    // Limit Address Space to 128MB
    rl.rlim_cur = 128 * 1024 * 1024;
    rl.rlim_max = 128 * 1024 * 1024;
    setrlimit(RLIMIT_AS, &rl);
    
    // C. PROCESS MANAGEMENT (Fallback)
    // Limit number of processes (Fork Bomb protection)
    // Note: In unprivileged UserNS, this limits processes in this namespace.
    rl.rlim_cur = 20;
    rl.rlim_max = 20;
    setrlimit(RLIMIT_NPROC, &rl);

    // -------------------------------------------------------------
    // D. SYSTEM CALL HANDLING
    // Mechanism: Seccomp BPF
    // -------------------------------------------------------------
    install_syscall_filter(config->profile);

    // -------------------------------------------------------------
    // C. PROCESS MANAGEMENT
    // Mechanism: execv()
    // Replaces the current process image with the untrusted code.
    // -------------------------------------------------------------
    printf("[Sandbox-Child] Executing untrusted binary: %s\n", config->binary_path);
    execv(config->binary_path, config->args);

    // If execv returns, it failed
    perror("execv failed");
    return 1;
}

void print_usage(const char *prog) {
    fprintf(stderr, "Usage: %s [--profile=STRICT|RESOURCE-AWARE|LEARNING] <executable> [args...]\n", prog);
}

int main(int argc, char *argv[]) {
    if (argc < 2) {
        print_usage(argv[0]);
        return 1;
    }

    // Default profile
    sandbox_profile_t profile = PROFILE_STRICT;
    char *profile_str = "STRICT";
    
    int bin_index = 1;
    if (strncmp(argv[1], "--profile=", 10) == 0) {
        char *pinfo = argv[1] + 10;
        if (strcmp(pinfo, "STRICT") == 0) {
            profile = PROFILE_STRICT;
            profile_str = "STRICT";
        } else if (strcmp(pinfo, "RESOURCE-AWARE") == 0) {
            profile = PROFILE_RESOURCE_AWARE;
            profile_str = "RESOURCE-AWARE";
        } else if (strcmp(pinfo, "LEARNING") == 0) {
            profile = PROFILE_LEARNING;
            profile_str = "LEARNING";
        } else {
             fprintf(stderr, "Unknown profile: %s. Using STRICT.\n", pinfo);
        }
        bin_index++;
    }

    if (bin_index >= argc) {
        print_usage(argv[0]);
        return 1;
    }

    printf("[Sandbox-Parent] Preparing execution environment (Profile: %s)...\n", profile_str);

    // Prepare child stack
    char *stack = malloc(STACK_SIZE);
    if (!stack) {
        perror("malloc stack");
        exit(1);
    }
    
    // Setup config
    struct container_config config;
    config.binary_path = argv[bin_index];
    config.args = &argv[bin_index]; // Pass the executable + its args
    config.profile = profile;

    // -------------------------------------------------------------
    // C. PROCESS MANAGEMENT & E. FILESYSTEM
    // Mechanism: clone() with CLONE_NEW* flags
    // Creating a new process in new namespaces (PID, IPC, UTS, MOUNT).
    // SIGCHLD tells the kernel to notify us when child dies.
    // -------------------------------------------------------------
    // Note: Creating User Namespaces (CLONE_NEWUSER) allows unprivileged users 
    // to usage other namespaces. Required for WSL2 often.
    
    int flags = CLONE_NEWNS | CLONE_NEWPID | CLONE_NEWIPC | CLONE_NEWUTS | CLONE_NEWUSER | SIGCHLD;
    
    long start_time = get_current_time_ms();
    
    pid_t child_pid = clone(child_fn, stack + STACK_SIZE, flags, &config);

    
    if (child_pid == -1) {
        perror("clone failed (Trying fallback to simple fork without namespaces if unprivileged)");
        exit(1);
    }

    printf("[Sandbox-Parent] Child launched with PID: %d\n", child_pid);

    // -------------------------------------------------------------
    // H. TIME MANAGEMENT & TELEMETRY
    // Mechanism: waitpid(WNOHANG) + Polling
    // -------------------------------------------------------------
    int status;
    int child_running = 1;
    
    telemetry_log_t log_data = {0};
    log_data.program_name = config.binary_path;
    log_data.profile_name = profile_str;
    log_data.cpu_usage_percent = 0;
    log_data.memory_peak_kb = 0;
    log_data.minflt = 0;
    log_data.majflt = 0;
    
    unsigned long long total_ticks = 0;


    // Monitoring Loop
    while (child_running) {
        pid_t result = waitpid(child_pid, &status, WNOHANG);
        
        if (result == 0) {
            // Child still running, collect metrics
            long current_mem = get_memory_peak(child_pid);
            if (current_mem > log_data.memory_peak_kb) {
                log_data.memory_peak_kb = current_mem;
            }
            
            // Capture CPU ticks and Faults
            unsigned long minflt = 0, majflt = 0;
            unsigned long long current_ticks = get_process_metrics(child_pid, &minflt, &majflt);
            if (current_ticks > total_ticks) {
                total_ticks = current_ticks;
            }
            // Update faults (they are cumulative in stat, so just take latest)
            log_data.minflt = minflt;
            log_data.majflt = majflt;

            
            usleep(100000); // 100ms sample rate
        } else if (result == -1) {
            perror("waitpid");
            child_running = 0;
        } else {
            // Child exited
            child_running = 0;
        }
    }
    
    long end_time = get_current_time_ms();
    log_data.runtime_ms = end_time - start_time;

    // Calculate CPU Usage %
    // total_ticks / CLK_TCK = CPU seconds
    // runtime_ms / 1000 = Wall seconds
    if (log_data.runtime_ms > 0) {
        double cpu_seconds = (double)total_ticks / sysconf(_SC_CLK_TCK);
        double wall_seconds = (double)log_data.runtime_ms / 1000.0;
        if (wall_seconds > 0) {
            log_data.cpu_usage_percent = (int)((cpu_seconds / wall_seconds) * 100.0);
        }
    }


    if (WIFEXITED(status)) {
        printf("[Sandbox-Parent] Child exited with status: %d\n", WEXITSTATUS(status));
        snprintf(log_data.exit_reason, sizeof(log_data.exit_reason), "EXITED(%d)", WEXITSTATUS(status));
    } else if (WIFSIGNALED(status)) {
        int sig = WTERMSIG(status);
        printf("[Sandbox-Parent] Child killed by signal: %d\n", sig);
        snprintf(log_data.termination_signal, sizeof(log_data.termination_signal), "SIG%d", sig);
        
        if (sig == SIGSYS) {
             printf("[Sandbox-Parent] DETECTED ILLEGAL SYSCALL (Seccomp Blocked)\n");
             snprintf(log_data.exit_reason, sizeof(log_data.exit_reason), "SECURITY_VIOLATION");
             // In a real audit setup, we'd read audit log to find WHICH syscall. 
             // Here we assume based on context or store "Unknown"
             snprintf(log_data.blocked_syscall, sizeof(log_data.blocked_syscall), "Unknown(SIGSYS)");
        } else if (sig == SIGKILL) {
             snprintf(log_data.exit_reason, sizeof(log_data.exit_reason), "KILLED_BY_OS");
        } else {
             snprintf(log_data.exit_reason, sizeof(log_data.exit_reason), "SIGNALED");
        }
    }
    
    // Generate Log Filename
    char filename[128];
    snprintf(filename, sizeof(filename), "logs/run_%ld.json", time(NULL));
    log_telemetry(filename, &log_data);

    free(stack);
    return 0;
}

