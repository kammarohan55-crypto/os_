#ifndef TELEMETRY_H
#define TELEMETRY_H

#include <sys/types.h>

#define MAX_SAMPLES 1000  // Max 100 seconds at 100ms intervals

typedef enum {
    PROFILE_STRICT,
    PROFILE_RESOURCE_AWARE,
    PROFILE_LEARNING
} sandbox_profile_t;

// Time-series sample
typedef struct {
    long time_ms;
    int cpu_percent;
    long memory_kb;
} telemetry_sample_t;

// Structure to hold telemetry data with timeline
typedef struct {
    char *program_name;
    const char *profile_name;
    long runtime_ms;
    int cpu_usage_percent;
    long memory_peak_kb;
    unsigned long minflt;
    unsigned long majflt;
    char termination_signal[32];
    char blocked_syscall[32];
    char exit_reason[32];
    
    // Time-series data
    telemetry_sample_t *samples;
    int sample_count;
} telemetry_log_t;

// Function prototypes
void ensure_logs_directory();
void log_telemetry(const char *filename, telemetry_log_t *log, pid_t child_pid);
void add_sample(telemetry_log_t *log, long elapsed_ms, int cpu_percent, long mem_kb);
long get_current_time_ms();
int get_cpu_usage(pid_t pid);
unsigned long long get_cpu_ticks(pid_t pid);
unsigned long long get_process_metrics(pid_t pid, unsigned long *minflt_out, unsigned long *majflt_out);
long get_memory_peak(pid_t pid);

#endif
