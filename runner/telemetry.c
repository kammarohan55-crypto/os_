#define _GNU_SOURCE
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <time.h>
#include <unistd.h>
#include <sys/time.h>
#include "telemetry.h"

// Get current time in milliseconds
long get_current_time_ms() {
    struct timeval tv;
    gettimeofday(&tv, NULL);
    return (tv.tv_sec * 1000) + (tv.tv_usec / 1000);
}

// Write telemetry to JSON file
void log_telemetry(const char *filename, telemetry_log_t *log) {
    FILE *fp = fopen(filename, "w");
    if (!fp) {
        perror("fopen telemetry log");
        return;
    }

    fprintf(fp, "{\n");
    fprintf(fp, "  \"program\": \"%s\",\n", log->program_name);
    fprintf(fp, "  \"profile\": \"%s\",\n", log->profile_name);
    fprintf(fp, "  \"runtime_ms\": %ld,\n", log->runtime_ms);
    fprintf(fp, "  \"cpu_usage_percent\": %d,\n", log->cpu_usage_percent);
    fprintf(fp, "  \"memory_peak_kb\": %ld,\n", log->memory_peak_kb);
    fprintf(fp, "  \"page_faults_minor\": %lu,\n", log->minflt);
    fprintf(fp, "  \"page_faults_major\": %lu,\n", log->majflt);
    fprintf(fp, "  \"termination_signal\": \"%s\",\n", log->termination_signal);

    fprintf(fp, "  \"blocked_syscall\": \"%s\",\n", log->blocked_syscall);
    fprintf(fp, "  \"exit_reason\": \"%s\"\n", log->exit_reason);
    fprintf(fp, "}\n");

    fclose(fp);
    printf("[Telemetry] Log written to %s\n", filename);
}

// Parse /proc/[pid]/stat for CPU usage (Simplified for this project)
// In a real OS project, we'd sample this over time. 
// Here we just grab utime+stime at the end (or near end).
// Helper to get process metrics (ticks, faults)
// Returns cpu ticks, and updating fault pointers if not null
unsigned long long get_process_metrics(pid_t pid, unsigned long *minflt_out, unsigned long *majflt_out) {
    char path[64];
    snprintf(path, sizeof(path), "/proc/%d/stat", pid);
    
    FILE *fp = fopen(path, "r");
    if (!fp) return 0;

    char buf[1024];
    if (!fgets(buf, sizeof(buf), fp)) {
        fclose(fp);
        return 0;
    }
    fclose(fp);

    char *last_paren = strrchr(buf, ')');
    if (!last_paren) return 0;

    char state;
    int ppid, pgrp, session, tty_nr, tpgid;
    unsigned int flags;
    unsigned long minflt, cminflt, majflt, cmajflt, utime_val, stime_val;

    sscanf(last_paren + 2, "%c %d %d %d %d %d %u %lu %lu %lu %lu %lu %lu",
           &state, &ppid, &pgrp, &session, &tty_nr, &tpgid, &flags,
           &minflt, &cminflt, &majflt, &cmajflt, &utime_val, &stime_val);
           
    if (minflt_out) *minflt_out = minflt + cminflt;
    if (majflt_out) *majflt_out = majflt + cmajflt;
    
    return utime_val + stime_val;
}

// Legacy wrapper if needed, or we just update header
unsigned long long get_cpu_ticks(pid_t pid) {
    return get_process_metrics(pid, NULL, NULL);
}


int get_cpu_usage(pid_t pid) {
    (void)pid;
    return 0;
}


// Parse /proc/[pid]/status for VmPeak
long get_memory_peak(pid_t pid) {
    char path[64];
    snprintf(path, sizeof(path), "/proc/%d/status", pid);
    
    FILE *fp = fopen(path, "r");
    if (!fp) return 0;
    
    char line[128];
    long peak_kb = 0;
    
    while (fgets(line, sizeof(line), fp)) {
        if (strncmp(line, "VmPeak:", 7) == 0) {
            sscanf(line + 7, "%ld", &peak_kb);
            break;
        }
    }
    
    fclose(fp);
    return peak_kb;
}
