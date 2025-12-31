#ifndef SECCOMP_RULES_H
#define SECCOMP_RULES_H

#include <seccomp.h>
#include <stdio.h>
#include <stdlib.h>
#include <errno.h>

/**
 * 5. Mandatory OS Algorithms & Kernel Mechanisms
 * D. SYSTEM CALL HANDLING
 *
 * This function loads the seccomp filter into the kernel.
 * It uses a WHITELIST approach: Default action is KILL.
 */
void install_syscall_filter() {
    scmp_filter_ctx ctx;

    // 1. Initialize the filter.
    // SCMP_ACT_KILL: Immediate process termination if a rule is violated.
    // This enforces the "Security by Default" principle.
    ctx = seccomp_init(SCMP_ACT_KILL); 
    if (ctx == NULL) {
        perror("seccomp_init");
        exit(1);
    }

    // 2. Allow essential System Calls for a basic C/Python program.
    // Without these, the program cannot start or print output.
    
    // Process management
    seccomp_rule_add(ctx, SCMP_ACT_ALLOW, SCMP_SYS(execve), 0);
    seccomp_rule_add(ctx, SCMP_ACT_ALLOW, SCMP_SYS(brk), 0);
    seccomp_rule_add(ctx, SCMP_ACT_ALLOW, SCMP_SYS(mmap), 0);
    seccomp_rule_add(ctx, SCMP_ACT_ALLOW, SCMP_SYS(munmap), 0);
    seccomp_rule_add(ctx, SCMP_ACT_ALLOW, SCMP_SYS(mprotect), 0);
    seccomp_rule_add(ctx, SCMP_ACT_ALLOW, SCMP_SYS(exit_group), 0);
    seccomp_rule_add(ctx, SCMP_ACT_ALLOW, SCMP_SYS(exit), 0);
    seccomp_rule_add(ctx, SCMP_ACT_ALLOW, SCMP_SYS(arch_prctl), 0); // Needed for Libc init

    // File I/O (stdout/stderr)
    seccomp_rule_add(ctx, SCMP_ACT_ALLOW, SCMP_SYS(write), 0);
    seccomp_rule_add(ctx, SCMP_ACT_ALLOW, SCMP_SYS(writev), 0);
    seccomp_rule_add(ctx, SCMP_ACT_ALLOW, SCMP_SYS(read), 0);
    seccomp_rule_add(ctx, SCMP_ACT_ALLOW, SCMP_SYS(fstat), 0);
    seccomp_rule_add(ctx, SCMP_ACT_ALLOW, SCMP_SYS(lseek), 0);
    seccomp_rule_add(ctx, SCMP_ACT_ALLOW, SCMP_SYS(close), 0);
    seccomp_rule_add(ctx, SCMP_ACT_ALLOW, SCMP_SYS(openat), 0); // Needed for dynamic linker
    seccomp_rule_add(ctx, SCMP_ACT_ALLOW, SCMP_SYS(readlink), 0);
    seccomp_rule_add(ctx, SCMP_ACT_ALLOW, SCMP_SYS(getrandom), 0); // Python needs this

    // 3. Explicitly DENY dangerous calls (Redundant due to default KILL, but for demonstration)
    // DANGER: fork() / clone() -> Prevent simple fork bombs inside the sandbox (defense in depth)
    // Note: Python or standard libs might try to clone threads, which will fail here.
    // For this strict sandbox, we essentially allow single-threaded execution only.
    
    // 4. Load the filter
    printf("[Sandbox] Loading Seccomp-BPF Profile...\n");
    if (seccomp_load(ctx) < 0) {
        perror("seccomp_load");
        seccomp_release(ctx);
        exit(1);
    }

    seccomp_release(ctx);
    printf("[Sandbox] Seccomp Enforced. System is locked down.\n");
}

#endif
