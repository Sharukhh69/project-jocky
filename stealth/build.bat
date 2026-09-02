@echo off
echo ========================================================
echo   JOCKY Stealth Engine -- Building C Modules
echo ========================================================

gcc -O2 api_unhook.c -o api_unhook.exe
if %ERRORLEVEL% EQU 0 (
    echo [OK] api_unhook.exe built successfully
) else (
    echo [FAIL] api_unhook.c failed to compile
)

gcc -O2 byovd_demo.c -o byovd_demo.exe
if %ERRORLEVEL% EQU 0 (
    echo [OK] byovd_demo.exe built successfully
) else (
    echo [FAIL] byovd_demo.c failed to compile
)

gcc -O2 process_hollow.c -o process_hollow.exe
if %ERRORLEVEL% EQU 0 (
    echo [OK] process_hollow.exe built successfully
) else (
    echo [FAIL] process_hollow.c failed to compile
)

gcc -O2 reflective_dll.c -o reflective_dll.exe
if %ERRORLEVEL% EQU 0 (
    echo [OK] reflective_dll.exe built successfully
) else (
    echo [FAIL] reflective_dll.c failed to compile
)

gcc -O2 thread_hijack.c -o thread_hijack.exe -lpsapi
if %ERRORLEVEL% EQU 0 (
    echo [OK] thread_hijack.exe built successfully
) else (
    echo [FAIL] thread_hijack.c failed to compile
)

echo.
echo Build complete.
