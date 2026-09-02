/*
 * syswhispers3.h — JOCKY Direct System Calls Header (SysWhispers3 / HalosGate)
 * ─────────────────────────────────────────────────────────────────────────────
 * Provides dynamic System Service Number (SSN) resolution and direct kernel
 * syscall stubs that completely bypass userland AV/EDR hooks in ntdll.dll.
 *
 * HOW DIRECT SYSCALLS WORK:
 *   1. Normal API Call:
 *      VirtualAlloc() -> kernel32 -> ntdll!NtAllocateVirtualMemory
 *      -> [EDR JMP Hook catches call] -> kernel syscall
 *
 *   2. JOCKY Direct Syscall:
 *      Our Code -> Dynamically resolve SSN via ntdll Export Sorting
 *      -> Execute direct 'syscall' CPU instruction from our own memory
 *      -> Kernel Ring-0 executes request
 *      -> EDR userland hook is completely bypassed (never triggered)
 *
 * MITRE ATT&CK:
 *   T1106 - Native API
 *   T1562.001 - Impair Defenses: Disable or Modify Tools
 */

#ifndef JOCKY_SYSWHISPERS3_H
#define JOCKY_SYSWHISPERS3_H

#ifndef __USE_MINGW_ANSI_STDIO
#define __USE_MINGW_ANSI_STDIO 1
#endif

#include <windows.h>
#include <stdio.h>
#include <stdlib.h>
#include <stdint.h>
#include <string.h>

#ifndef NT_SUCCESS
#define NT_SUCCESS(Status) (((NTSTATUS)(Status)) >= 0)
#endif

#ifndef STATUS_SUCCESS
#define STATUS_SUCCESS ((NTSTATUS)0x00000000L)
#endif

/* ── Basic NT Structures ─────────────────────────────────────────────────── */

typedef LONG NTSTATUS;

typedef struct _UNICODE_STRING {
    USHORT Length;
    USHORT MaximumLength;
    PWSTR  Buffer;
} UNICODE_STRING, *PUNICODE_STRING;

typedef struct _OBJECT_ATTRIBUTES {
    ULONG           Length;
    HANDLE          RootDirectory;
    PUNICODE_STRING ObjectName;
    ULONG           Attributes;
    PVOID           SecurityDescriptor;
    PVOID           SecurityQualityOfService;
} OBJECT_ATTRIBUTES, *POBJECT_ATTRIBUTES;

typedef struct _CLIENT_ID {
    HANDLE UniqueProcess;
    HANDLE UniqueThread;
} CLIENT_ID, *PCLIENT_ID;

/* ── Syscall Entry Structure ─────────────────────────────────────────────── */

typedef struct _SYSCALL_ENTRY {
    DWORD   Hash;
    DWORD   Rva;
    DWORD   Ssn;
    char    Name[64];
    PVOID   StubAddress;
} SYSCALL_ENTRY, *PSYSCALL_ENTRY;

#define MAX_SYSCALL_ENTRIES 1024

typedef struct _SYSCALL_TABLE {
    DWORD           Count;
    SYSCALL_ENTRY   Entries[MAX_SYSCALL_ENTRIES];
} SYSCALL_TABLE, *PSYSCALL_TABLE;

/* ── DJB2 Hash for stealth string hiding ─────────────────────────────────── */
static inline DWORD jocky_hash(const char *str)
{
    DWORD hash = 5381;
    int c;
    while ((c = *str++)) {
        hash = ((hash << 5) + hash) + (DWORD)c;
    }
    return hash;
}

/* ── Function Pointer Prototypes for Direct NT Invocation ─────────────────── */

typedef NTSTATUS (NTAPI *fnNtAllocateVirtualMemory)(
    HANDLE ProcessHandle,
    PVOID *BaseAddress,
    ULONG_PTR ZeroBits,
    PSIZE_T RegionSize,
    ULONG AllocationType,
    ULONG Protect
);

typedef NTSTATUS (NTAPI *fnNtWriteVirtualMemory)(
    HANDLE ProcessHandle,
    PVOID BaseAddress,
    PVOID Buffer,
    SIZE_T NumberOfBytesToWrite,
    PSIZE_T NumberOfBytesWritten
);

typedef NTSTATUS (NTAPI *fnNtProtectVirtualMemory)(
    HANDLE ProcessHandle,
    PVOID *BaseAddress,
    PSIZE_T RegionSize,
    ULONG NewProtect,
    PULONG OldProtect
);

typedef NTSTATUS (NTAPI *fnNtFreeVirtualMemory)(
    HANDLE ProcessHandle,
    PVOID *BaseAddress,
    PSIZE_T RegionSize,
    ULONG FreeType
);

typedef NTSTATUS (NTAPI *fnNtOpenProcess)(
    PHANDLE ProcessHandle,
    ACCESS_MASK DesiredAccess,
    POBJECT_ATTRIBUTES ObjectAttributes,
    PCLIENT_ID ClientId
);

#endif /* JOCKY_SYSWHISPERS3_H */
