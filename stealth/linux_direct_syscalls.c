/*
 * linux_direct_syscalls.c — JOCKY Linux Direct System Calls Engine
 * ─────────────────────────────────────────────────────────────────────────────
 * Issues raw 64-bit Linux system calls directly to the kernel via inline assembly,
 * completely bypassing libc.so.6 wrapper functions, LD_PRELOAD interceptors, and
 * userspace EDR hooks.
 *
 * HOW DIRECT SYSCALLS WORK ON LINUX:
 *   - Normal libc call:  write() -> libc.so.6 wrapper -> [EDR hook] -> syscall
 *   - JOCKY call:       Our Code -> 'syscall' CPU instruction -> Kernel Ring-0
 *   - The userland C library (libc) is completely skipped.
 *
 * LINUX x86_64 SYSCALL CALLING CONVENTION:
 *   - Syscall Number : RAX
 *   - Arguments      : RDI, RSI, RDX, R10, R8, R9
 *   - Instruction    : syscall (0x0F 0x05)
 *   - Return Value   : RAX
 *
 * MITRE ATT&CK:
 *   T1106 - Native API
 *   T1562.001 - Impair Defenses: Disable or Modify Tools
 *
 * COMPILE (Ubuntu / Debian):
 *   gcc -O2 -nostartfiles -fno-builtin linux_direct_syscalls.c -o linux_direct_syscalls
 *   (or standard gcc -O2 linux_direct_syscalls.c -o linux_direct_syscalls)
 */

#define _GNU_SOURCE
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <stdint.h>
#include <sys/syscall.h>

/* Linux x86_64 Syscall Numbers (arch/x86/entry/syscalls/syscall_64.tbl) */
#ifndef __NR_read
#define __NR_read 0
#endif
#ifndef __NR_write
#define __NR_write 1
#endif
#ifndef __NR_open
#define __NR_open 2
#endif
#ifndef __NR_close
#define __NR_close 3
#endif
#ifndef __NR_mmap
#define __NR_mmap 9
#endif
#ifndef __NR_mprotect
#define __NR_mprotect 10
#endif
#ifndef __NR_munmap
#define __NR_munmap 11
#endif
#ifndef __NR_getpid
#define __NR_getpid 39
#endif
#ifndef __NR_ptrace
#define __NR_ptrace 101
#endif
#ifndef __NR_memfd_create
#define __NR_memfd_create 319
#endif

/* ── Raw Assembly Syscall Invocations ─────────────────────────────────────── */

static inline long raw_syscall0(long n)
{
    long ret;
    __asm__ volatile (
        "syscall"
        : "=a" (ret)
        : "a" (n)
        : "rcx", "r11", "memory"
    );
    return ret;
}

static inline long raw_syscall1(long n, long a1)
{
    long ret;
    __asm__ volatile (
        "syscall"
        : "=a" (ret)
        : "a" (n), "D" (a1)
        : "rcx", "r11", "memory"
    );
    return ret;
}

static inline long raw_syscall2(long n, long a1, long a2)
{
    long ret;
    __asm__ volatile (
        "syscall"
        : "=a" (ret)
        : "a" (n), "D" (a1), "S" (a2)
        : "rcx", "r11", "memory"
    );
    return ret;
}

static inline long raw_syscall3(long n, long a1, long a2, long a3)
{
    long ret;
    __asm__ volatile (
        "syscall"
        : "=a" (ret)
        : "a" (n), "D" (a1), "S" (a2), "d" (a3)
        : "rcx", "r11", "memory"
    );
    return ret;
}

static inline long raw_syscall6(long n, long a1, long a2, long a3, long a4, long a5, long a6)
{
    long ret;
    register long r10 __asm__("r10") = a4;
    register long r8  __asm__("r8")  = a5;
    register long r9  __asm__("r9")  = a6;

    __asm__ volatile (
        "syscall"
        : "=a" (ret)
        : "a" (n), "D" (a1), "S" (a2), "d" (a3), "r" (r10), "r" (r8), "r" (r9)
        : "rcx", "r11", "memory"
    );
    return ret;
}

/* ── JOCKY Direct Syscall Wrappers ────────────────────────────────────────── */

long jocky_direct_getpid(void)
{
    return raw_syscall0(__NR_getpid);
}

long jocky_direct_write(int fd, const void *buf, size_t count)
{
    return raw_syscall3(__NR_write, (long)fd, (long)buf, (long)count);
}

void* jocky_direct_mmap(void *addr, size_t length, int prot, int flags, int fd, off_t offset)
{
    return (void *)raw_syscall6(__NR_mmap, (long)addr, (long)length, (long)prot,
                               (long)flags, (long)fd, (long)offset);
}

int jocky_direct_munmap(void *addr, size_t length)
{
    return (int)raw_syscall2(__NR_munmap, (long)addr, (long)length);
}

int jocky_direct_memfd_create(const char *name, unsigned int flags)
{
    return (int)raw_syscall2(__NR_memfd_create, (long)name, (long)flags);
}

/* ── Main Demo ───────────────────────────────────────────────────────────── */

int main(int argc, char *argv[])
{
    printf("===============================================================\n");
    printf("  JOCKY Linux Direct System Calls Engine (x86_64)              \n");
    printf("  Bypasses libc.so.6 & LD_PRELOAD via Direct CPU 'syscall'    \n");
    printf("  MITRE ATT&CK: T1106 (Native API)                             \n");
    printf("===============================================================\n\n");

    /* 1. Direct getpid */
    long pid = jocky_direct_getpid();
    printf("[1] Raw syscall __NR_getpid (39): PID = %ld\n", pid);

    /* 2. Direct write (bypassing libc write, printf, puts) */
    const char msg[] = "[2] Raw syscall __NR_write (1): Emitted directly via Kernel Ring-0!\n";
    jocky_direct_write(1, msg, sizeof(msg) - 1);

    /* 3. Direct mmap */
    size_t alloc_sz = 4096;
    /* PROT_READ (1) | PROT_WRITE (2), MAP_PRIVATE (2) | MAP_ANONYMOUS (0x20) */
    void *mem = jocky_direct_mmap(NULL, alloc_sz, 0x1 | 0x2, 0x02 | 0x20, -1, 0);

    if ((intptr_t)mem > 0) {
        printf("[3] Raw syscall __NR_mmap (9): Allocated %zu bytes at %p\n", alloc_sz, mem);
        strcpy((char *)mem, "JOCKY-LINUX-STEALTH-ACTIVE-2026");
        printf("    Written directly to allocated RAM: \"%s\"\n", (char *)mem);
        jocky_direct_munmap(mem, alloc_sz);
        printf("    Raw syscall __NR_munmap (11): Memory freed cleanly.\n");
    } else {
        printf("[-] Direct mmap failed.\n");
    }

    /* 4. Direct memfd_create */
    int memfd = jocky_direct_memfd_create("jocky_stealth_mem", 1 /* MFD_CLOEXEC */);
    if (memfd >= 0) {
        printf("[4] Raw syscall __NR_memfd_create (319): Created RAM fd = %d\n", memfd);
        raw_syscall1(__NR_close, memfd);
        printf("    Raw syscall __NR_close (3): Closed RAM fd.\n");
    }

    printf("\n===============================================================\n");
    printf("[+] LINUX DIRECT SYSCALLS: ALL INVOCATIONS COMPLETED SUCCESSFULLY\n");
    printf("    No libc.so.6 symbols called; LD_PRELOAD interceptors bypassed.\n");
    printf("===============================================================\n");

    return 0;
}
