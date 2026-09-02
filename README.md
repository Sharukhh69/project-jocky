# JOCKY Framework — SIH 2026 Edition
## "Creation of scripts/functions with new programming language for Computer & Network Forensic Analysis"
### Problem Statement ID: 26148

---

## Project Overview

JOCKY is a proprietary forensic programming language and framework for digital forensic analysis of computers and networks. It bypasses antivirus solutions through a combination of:

1. **Custom Programming Language** — JOCKY (`.jky` files) with its own Lexer → Parser → AST → Executor pipeline
2. **LLVM Compiler Frontend** — Compiles JOCKY scripts to LLVM IR → unique native machine code per build
3. **Polymorphic Engine** — XOR encryption, junk injection, variable randomization → unique SHA-256 per build
4. **Stealth Engine** — Process hollowing, API unhooking, direct syscalls (SysWhispers3), BYOVD
5. **Cross-Platform Agent** — Flask-based agent supporting Windows and Linux forensic scans
6. **Central Management Interface** — Full dashboard UI with multi-target support
7. **Evidence + Reports** — SHA-256 chain of custody, court-admissible PDF reports

---

## Quick Start

### 1. Install Dependencies (Management Machine)
```bash
pip install -r requirements.txt
```

### 2. Start the Backend Server
```bash
cd backend
python server.py
# Starts on http://localhost:8000
```

### 3. Start the Agent (Target Machine)
```bash
cd agent
python agent.py
# Starts on http://0.0.0.0:5000
```

Or plug in the USB drive and run `usb_setup/START.bat` on the target.

### 4. Open Dashboard
Open `frontend/index.html` in any modern browser.

---

## Project Structure

```
JOCKY/
├── agent/
│   └── agent.py                ← Cross-platform forensic agent (Windows + Linux)
├── interpreter/
│   ├── jocky_interpreter.py    ← JOCKY language: Lexer → Parser → Executor
│   ├── polymorphic.py          ← Polymorphic transformation engine
│   └── llvm_compiler.py        ← LLVM IR compiler frontend (llvmlite)
├── stealth/
│   ├── process_hollow.c        ← Process hollowing (C, Windows)
│   ├── api_unhook.c            ← API unhooking / ntdll refresh (C, Windows)
│   └── byovd_demo.c            ← BYOVD kernel callback disabler (C, Windows)
├── backend/
│   └── server.py               ← Flask backend API (port 8000)
├── frontend/
│   ├── index.html              ← Dashboard UI
│   ├── styles.css              ← Dark cyberpunk CSS
│   └── app.js                  ← Dashboard logic
├── reports/
│   └── report_generator.py     ← Court-admissible PDF generator
├── usb_setup/
│   ├── agent.py                ← Agent copy for USB deployment
│   ├── START.bat               ← Auto-deploy script for target
│   └── requirements.txt        ← Minimal agent dependencies
├── requirements.txt            ← Full dependencies
└── README.md
```

---

## JOCKY Language Syntax

```jocky
# JOCKY Forensic Script

scan.processes()
scan.network.connections()
scan.usb.history()
scan.logins()
scan.system()
scan.files("/path")
scan.registry()
report.send("dashboard")
report.export("pdf")
```

---

## API Endpoints

| Endpoint | Method | Description |
|----------|--------|-------------|
| `/api/status` | GET | Server health check |
| `/api/cases` | GET | List all cases |
| `/api/case/create` | POST | Create new case |
| `/api/target/add` | POST | Add target machine |
| `/api/targets/<case_id>` | GET | List targets for case |
| `/api/run` | POST | Run JOCKY command on target |
| `/api/run/all` | POST | Run on ALL targets simultaneously |
| `/api/script/run` | POST | Execute JOCKY script |
| `/api/script/morph` | POST | Run polymorphic engine |
| `/api/script/validate` | POST | Validate JOCKY script |
| `/api/evidence/<case_id>` | GET | Get all evidence for case |
| `/api/report/<case_id>` | GET | Generate PDF report |

---

## Stealth Techniques

### 1. API Unhooking
Reloads ntdll.dll from disk (clean, no AV hooks) and overwrites the hooked in-memory copy's `.text` section.

### 2. Process Hollowing
Spawns notepad.exe in SUSPENDED state, writes JOCKY agent payload to allocated memory, redirects entry point, resumes. AV sees `notepad.exe` (trusted).

### 3. Direct System Calls (SysWhispers3)
Bypasses AV hooks by calling Windows kernel directly via dynamically-resolved syscall stubs — AV hooks in ntdll are completely skipped.

### 4. BYOVD (Bring Your Own Vulnerable Driver)
Loads signed but vulnerable RTCore64.sys (MSI Afterburner), exploits its arbitrary kernel read/write primitive to zero out EDR callback arrays (PsSetCreateProcessNotifyRoutine, ObRegisterCallbacks) at Ring-0 level.

### 5. Polymorphic Engine
XOR string encryption + junk code injection + variable name randomization + CFG obfuscation → different SHA-256 hash every build.

### 6. LLVM Compiler
Compiles JOCKY source to LLVM IR with randomized optimization passes → unique binary output per compilation. Signature-based AV cannot match it.

---

## Team Responsibilities

| Person | Component |
|--------|-----------|
| Person 1 | Stealth engine (API unhooking, process hollowing, syscalls, BYOVD) |
| Person 2 | Cross-platform agent (Windows + Linux scan routes) |
| Person 3 | LLVM compiler frontend + polymorphic engine |
| Person 4 | Backend server + multi-target support |
| Person 5 | Dashboard UI |
| Person 6 | PDF report generator + USB setup |

---

## Judge Talking Points

1. **"JOCKY is a complete programming language"** — Lexer tokenizes `.jky` files, Parser builds AST, Executor maps to agent API calls. Not just scripts — it's a full language with its own grammar.

2. **"Every binary is unique"** — LLVM + polymorphic engine = different SHA-256 hash on every build from the same source code. Demonstrated live with 3 builds.

3. **"AV is completely bypassed"** — (a) API unhooking removes hooks, (b) process hollowing hides in notepad.exe, (c) direct syscalls skip AV's monitoring layer entirely.

4. **"Multi-machine simultaneous scanning"** — `/api/run/all` uses ThreadPoolExecutor to scan all targets concurrently.

5. **"Court-admissible evidence"** — Every result is SHA-256 hashed immediately. PDF report includes a complete chain of custody with a master integrity hash.
