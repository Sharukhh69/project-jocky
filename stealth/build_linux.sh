#!/usr/bin/env bash
# build_linux.sh — Build Linux / Ubuntu JOCKY Stealth Modules
set -e

echo "=========================================================="
echo "  JOCKY Linux / Ubuntu Stealth Engine -- Building Modules "
echo "=========================================================="

# Check gcc
if ! command -v gcc &>/dev/null; then
    echo "[ERROR] gcc is required but not installed. Run: sudo apt-get install build-essential"
    exit 1
fi

echo "[1/4] Building linux_unhook (libc .text restore & LD_PRELOAD bypass)..."
gcc -O2 linux_unhook.c -o linux_unhook -ldl
echo "  ✓ [OK] linux_unhook built successfully"

echo "[2/4] Building linux_process_hollow (ptrace + /proc/self/mem replacement)..."
gcc -O2 linux_process_hollow.c -o linux_process_hollow
echo "  ✓ [OK] linux_process_hollow built successfully"

echo "[3/4] Building linux_direct_syscalls (Raw inline x86_64 kernel syscalls)..."
gcc -O2 linux_direct_syscalls.c -o linux_direct_syscalls
echo "  ✓ [OK] linux_direct_syscalls built successfully"

echo "[4/4] Building linux_memfd_exec (In-memory fileless memfd_create execution)..."
gcc -O2 linux_memfd_exec.c -o linux_memfd_exec
echo "  ✓ [OK] linux_memfd_exec built successfully"

echo ""
echo "=========================================================="
echo "  [BUILD COMPLETE] All 4 Linux stealth modules compiled! "
echo "  • ./linux_unhook           (Unhooks libc.so.6 in memory)"
echo "  • ./linux_process_hollow   (Disguises inside host PID)"
echo "  • ./linux_direct_syscalls  (Direct kernel syscall stubs)"
echo "  • ./linux_memfd_exec       (Fileless RAM execution)"
echo "=========================================================="
