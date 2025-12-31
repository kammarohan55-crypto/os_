#ifndef TELEMETRY_H
#define TELEMETRY_H

#include <sys/types.h>

typedef enum {
    PROFILE_STRICT,
    PROFILE_RESOURCE_AWARE,
    PROFILE_LEARNING
} sandbox_profile_t;

// Structure to hold telemetry data
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
} telemetry_log_t;

// Function prototypes
void log_telemetry(const char *filename, telemetry_log_t *log);
long get_current_time_ms();
int get_cpu_usage(pid_t pid);
unsigned long long get_cpu_ticks(pid_t pid);
unsigned long long get_process_metrics(pid_t pid, unsigned long *minflt_out, unsigned long *majflt_out);
long get_memory_peak(pid_t pid);



#endif
