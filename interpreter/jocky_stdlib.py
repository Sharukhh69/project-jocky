# jocky_stdlib.py — JOCKY Standard Library Implementations
# All stdlib modules: sys, mem, proc, fs, reg, net, crypto, evasion, debug
# These run as Python implementations in interpreter mode.
# In compiler mode they are lowered to JOCKY-IR intrinsic instructions.

from __future__ import annotations
import os
import sys
import socket
import hashlib
import struct
import platform
import subprocess
import threading
import time
import random
import base64
from typing import Any, Dict, List, Optional, Tuple

# Optional platform-specific imports
try:
    import psutil
    _PSUTIL = True
except ImportError:
    _PSUTIL = False

try:
    from cryptography.hazmat.primitives.ciphers import Cipher, algorithms, modes
    from cryptography.hazmat.backends import default_backend
    _CRYPTO = True
except ImportError:
    _CRYPTO = False

_WINDOWS = sys.platform == 'win32'
if _WINDOWS:
    try:
        import winreg
        _WINREG = True
    except ImportError:
        _WINREG = False
else:
    _WINREG = False


# ─────────────────────────────────────────────────────────────────────────────
# ERROR TYPE
# ─────────────────────────────────────────────────────────────────────────────

class JockyError(Exception):
    pass


# ─────────────────────────────────────────────────────────────────────────────
# sys module
# ─────────────────────────────────────────────────────────────────────────────

class SysModule:
    """
    sys.getpid() → int
    sys.hostname() → string
    sys.os() → "windows" | "linux"
    sys.execute(cmd, ...args) → (output, error)
    sys.env(name) → string
    sys.username() → string
    """

    def getpid(self) -> int:
        return os.getpid()

    def hostname(self) -> str:
        return socket.gethostname()

    def os(self) -> str:
        return "windows" if _WINDOWS else "linux"

    def execute(self, cmd: str, *args: str) -> Tuple[str, Optional[str]]:
        try:
            result = subprocess.run(
                [cmd] + list(args),
                capture_output=True, text=True, timeout=30
            )
            return result.stdout, result.stderr or None
        except Exception as e:
            return "", str(e)

    def env(self, name: str) -> str:
        return os.environ.get(name, "")

    def username(self) -> str:
        return os.environ.get("USERNAME" if _WINDOWS else "USER", "unknown")

    def args(self) -> List[str]:
        return sys.argv[1:]


# ─────────────────────────────────────────────────────────────────────────────
# mem module
# ─────────────────────────────────────────────────────────────────────────────

class MemModule:
    """
    mem.alloc(size) → uintptr
    mem.read(addr, length) → []byte
    mem.write(addr, data) → error
    mem.protect(addr, size, prot) → error
    mem.scan(pattern, data) → []int  (offsets where pattern found)
    mem.regions(pid) → []MemRegion
    """

    def alloc(self, size: int) -> int:
        """Simulate memory allocation — returns a fake address in interpreter mode."""
        buf = bytearray(size)
        addr = id(buf)
        # Keep a ref so GC doesn't collect it
        _mem_registry[addr] = buf
        return addr

    def read(self, addr: int, length: int) -> bytes:
        buf = _mem_registry.get(addr)
        if buf is None:
            return bytes(length)
        return bytes(buf[:length])

    def write(self, addr: int, data: bytes) -> Optional[str]:
        buf = _mem_registry.get(addr)
        if buf is None:
            return "invalid address"
        buf[:len(data)] = data
        return None

    def protect(self, addr: int, size: int, prot: int) -> Optional[str]:
        # In interpreter mode, protection is a no-op
        return None

    def scan(self, pattern: str, data: Any) -> List[int]:
        """Search for pattern bytes/string in data, return list of offsets."""
        if isinstance(data, str):
            data = data.encode()
        if isinstance(pattern, str):
            needle = pattern.encode()
        else:
            needle = bytes(pattern)
        results = []
        start = 0
        while True:
            idx = data.find(needle, start)
            if idx == -1:
                break
            results.append(idx)
            start = idx + 1
        return results

    def regions(self, pid: int) -> List[Dict]:
        """List memory regions of a process."""
        if not _PSUTIL:
            return []
        try:
            proc = psutil.Process(pid)
            regions = []
            for m in proc.memory_maps(grouped=False):
                regions.append({
                    'base': 0,
                    'size': m.rss,
                    'path': m.path,
                    'perms': m.perms,
                })
            return regions
        except Exception:
            return []


_mem_registry: Dict[int, bytearray] = {}


# ─────────────────────────────────────────────────────────────────────────────
# proc module
# ─────────────────────────────────────────────────────────────────────────────

class ProcessInfo:
    def __init__(self, pid: int, name: str, ppid: int, status: str = ""):
        self.pid    = pid
        self.name   = name
        self.ppid   = ppid
        self.status = status

    def __repr__(self):
        return f"ProcessInfo(pid={self.pid}, name={self.name!r})"


class ProcessHandle:
    def __init__(self, pid: int):
        self.pid = pid
        self._closed = False

    def close(self):
        self._closed = True

    def __bool__(self):
        return not self._closed


class ProcModule:
    """
    proc.list() → []ProcessInfo
    proc.open(pid) → *ProcessHandle | nil
    proc.inject(targetPid, shellcode) → error
    proc.hollow(targetPid, path) → error
    proc.syscall(number, ...args) → (uintptr, error)
    proc.kill(pid) → error
    """

    def list(self) -> List[ProcessInfo]:
        if not _PSUTIL:
            return [ProcessInfo(os.getpid(), "self", 0)]
        procs = []
        for p in psutil.process_iter(['pid', 'name', 'ppid', 'status']):
            try:
                info = p.info
                procs.append(ProcessInfo(
                    pid=info['pid'],
                    name=info['name'] or "",
                    ppid=info.get('ppid', 0) or 0,
                    status=info.get('status', ""),
                ))
            except (psutil.NoSuchProcess, psutil.AccessDenied):
                pass
        return procs

    def open(self, pid: int) -> Optional[ProcessHandle]:
        if not _PSUTIL:
            return None
        try:
            p = psutil.Process(pid)
            _ = p.name()   # verify it's accessible
            return ProcessHandle(pid)
        except Exception:
            return None

    def inject(self, target_pid: int, shellcode: bytes) -> Optional[str]:
        # Interpreter mode: simulate, do not actually inject
        print(f"[JOCKY proc] inject({target_pid}, {len(shellcode)} bytes) — simulated")
        return None

    def hollow(self, target_pid: int, path: str) -> Optional[str]:
        print(f"[JOCKY proc] hollow({target_pid}, {path!r}) — simulated")
        return None

    def syscall(self, number: int, *args: int) -> Tuple[int, Optional[str]]:
        print(f"[JOCKY proc] syscall({number}, {args}) — simulated")
        return 0, None

    def kill(self, pid: int) -> Optional[str]:
        if not _PSUTIL:
            return "psutil not available"
        try:
            psutil.Process(pid).kill()
            return None
        except Exception as e:
            return str(e)


# ─────────────────────────────────────────────────────────────────────────────
# fs module
# ─────────────────────────────────────────────────────────────────────────────

class FsModule:
    """
    fs.readFile(path) → []byte
    fs.writeFile(path, data) → error
    fs.listDir(path) → []string
    fs.exists(path) → bool
    fs.stat(path) → {size, mtime, is_dir}
    fs.remove(path) → error
    """

    def readFile(self, path: str) -> bytes:
        try:
            with open(path, 'rb') as f:
                return f.read()
        except Exception as e:
            raise JockyError(str(e))

    def writeFile(self, path: str, data: bytes) -> Optional[str]:
        try:
            os.makedirs(os.path.dirname(os.path.abspath(path)), exist_ok=True)
            with open(path, 'wb') as f:
                f.write(data if isinstance(data, (bytes, bytearray)) else
                        data.encode())
            return None
        except Exception as e:
            return str(e)

    def listDir(self, path: str) -> List[str]:
        try:
            return os.listdir(path)
        except Exception:
            return []

    def exists(self, path: str) -> bool:
        return os.path.exists(path)

    def stat(self, path: str) -> Dict:
        try:
            st = os.stat(path)
            return {
                'size':   st.st_size,
                'mtime':  st.st_mtime,
                'is_dir': os.path.isdir(path),
            }
        except Exception:
            return {}

    def remove(self, path: str) -> Optional[str]:
        try:
            os.remove(path)
            return None
        except Exception as e:
            return str(e)


# ─────────────────────────────────────────────────────────────────────────────
# reg module  (Windows only)
# ─────────────────────────────────────────────────────────────────────────────

_REG_ROOTS = {}
if _WINREG:
    _REG_ROOTS = {
        'HKLM': winreg.HKEY_LOCAL_MACHINE,
        'HKCU': winreg.HKEY_CURRENT_USER,
        'HKCR': winreg.HKEY_CLASSES_ROOT,
        'HKU':  winreg.HKEY_USERS,
        'HKCC': winreg.HKEY_CURRENT_CONFIG,
    }


class RegModule:
    """
    reg.readKey(root, path, name) → (value, error)
    reg.writeKey(root, path, name, value) → error
    reg.enumerateKeys(root, path) → []string
    reg.enumerateValues(root, path) → []string
    """

    def _get_root(self, root: str):
        if not _WINREG:
            raise JockyError("reg module requires Windows")
        key = _REG_ROOTS.get(root.upper())
        if key is None:
            raise JockyError(f"Unknown registry root: {root!r}")
        return key

    def readKey(self, root: str, path: str, name: str) -> Tuple[Any, Optional[str]]:
        try:
            hive = self._get_root(root)
            with winreg.OpenKey(hive, path) as k:
                val, _ = winreg.QueryValueEx(k, name)
                return val, None
        except Exception as e:
            return None, str(e)

    def writeKey(self, root: str, path: str, name: str,
                 value: Any) -> Optional[str]:
        try:
            hive = self._get_root(root)
            with winreg.OpenKey(hive, path, 0, winreg.KEY_SET_VALUE) as k:
                if isinstance(value, int):
                    winreg.SetValueEx(k, name, 0, winreg.REG_DWORD, value)
                else:
                    winreg.SetValueEx(k, name, 0, winreg.REG_SZ, str(value))
            return None
        except Exception as e:
            return str(e)

    def enumerateKeys(self, root: str, path: str) -> List[str]:
        try:
            hive = self._get_root(root)
            with winreg.OpenKey(hive, path) as k:
                keys = []
                i = 0
                while True:
                    try:
                        keys.append(winreg.EnumKey(k, i))
                        i += 1
                    except OSError:
                        break
                return keys
        except Exception:
            return []

    def enumerateValues(self, root: str, path: str) -> List[str]:
        try:
            hive = self._get_root(root)
            with winreg.OpenKey(hive, path) as k:
                vals = []
                i = 0
                while True:
                    try:
                        name, _, _ = winreg.EnumValue(k, i)
                        vals.append(name)
                        i += 1
                    except OSError:
                        break
                return vals
        except Exception:
            return []


# ─────────────────────────────────────────────────────────────────────────────
# net module
# ─────────────────────────────────────────────────────────────────────────────

class NetModule:
    """
    net.socket(domain, type, proto) → fd
    net.connect(fd, addr, port) → error
    net.send(fd, data) → (n, error)
    net.recv(fd, size) → bytes
    net.close(fd) → error
    net.httpGet(url, headers) → (body, status, error)
    net.httpPost(url, data) → (body, status, error)
    net.domainFront(url, frontDomain) → (body, error)
    """

    def __init__(self):
        self._sockets: Dict[int, socket.socket] = {}

    def socket(self, domain: int, typ: int, proto: int) -> int:
        s = socket.socket(domain, typ, proto)
        fd = s.fileno()
        self._sockets[fd] = s
        return fd

    def connect(self, fd: int, addr: str, port: int) -> Optional[str]:
        s = self._sockets.get(fd)
        if s is None:
            return "invalid fd"
        try:
            s.connect((addr, port))
            return None
        except Exception as e:
            return str(e)

    def send(self, fd: int, data: bytes) -> Tuple[int, Optional[str]]:
        s = self._sockets.get(fd)
        if s is None:
            return 0, "invalid fd"
        try:
            n = s.send(data if isinstance(data, bytes) else data.encode())
            return n, None
        except Exception as e:
            return 0, str(e)

    def recv(self, fd: int, size: int = 4096) -> bytes:
        s = self._sockets.get(fd)
        if s is None:
            return b""
        try:
            return s.recv(size)
        except Exception:
            return b""

    def close(self, fd: int) -> Optional[str]:
        s = self._sockets.pop(fd, None)
        if s:
            try:
                s.close()
            except Exception:
                pass
        return None

    def httpGet(self, url: str,
                headers: Dict[str, str] = None) -> Tuple[bytes, int, Optional[str]]:
        try:
            import urllib.request
            req = urllib.request.Request(url, headers=headers or {})
            with urllib.request.urlopen(req, timeout=15) as resp:
                return resp.read(), resp.status, None
        except Exception as e:
            return b"", 0, str(e)

    def httpPost(self, url: str,
                 data: Any = None,
                 headers: Dict[str, str] = None) -> Tuple[bytes, int, Optional[str]]:
        try:
            import urllib.request
            import json as _json
            if isinstance(data, dict):
                body = _json.dumps(data).encode()
                hdrs = {"Content-Type": "application/json"}
            elif isinstance(data, str):
                body = data.encode()
                hdrs = {}
            else:
                body = data or b""
                hdrs = {}
            hdrs.update(headers or {})
            req = urllib.request.Request(url, data=body, headers=hdrs,
                                         method='POST')
            with urllib.request.urlopen(req, timeout=15) as resp:
                return resp.read(), resp.status, None
        except Exception as e:
            return b"", 0, str(e)

    def domainFront(self, url: str, front_domain: str) -> Tuple[bytes, Optional[str]]:
        # Domain fronting: send Host header pointing to real target,
        # but connect via CDN front domain
        try:
            import urllib.request
            from urllib.parse import urlparse
            parsed = urlparse(url)
            front_url = url.replace(parsed.netloc, front_domain)
            req = urllib.request.Request(front_url,
                                         headers={"Host": parsed.netloc})
            with urllib.request.urlopen(req, timeout=15) as resp:
                return resp.read(), None
        except Exception as e:
            return b"", str(e)


# ─────────────────────────────────────────────────────────────────────────────
# crypto module
# ─────────────────────────────────────────────────────────────────────────────

class CryptoModule:
    """
    crypto.aesEncrypt(key, data) → bytes
    crypto.aesDecrypt(key, data) → bytes
    crypto.xor(data, key) → bytes
    crypto.rc4(data, key) → bytes
    crypto.hash(data) → bytes (SHA-256, 32 bytes)
    crypto.hmac(key, data) → bytes
    crypto.base64encode(data) → string
    crypto.base64decode(s) → bytes
    """

    def aesEncrypt(self, key: bytes, data: bytes) -> bytes:
        if not _CRYPTO:
            # Fallback XOR
            return self.xor(data, key)
        key = self._pad_key(key, 32)
        iv  = os.urandom(16)
        cipher = Cipher(algorithms.AES(key), modes.CFB(iv),
                        backend=default_backend())
        enc = cipher.encryptor()
        return iv + enc.update(data) + enc.finalize()

    def aesDecrypt(self, key: bytes, data: bytes) -> bytes:
        if not _CRYPTO:
            return self.xor(data, key)
        key = self._pad_key(key, 32)
        iv, ciphertext = data[:16], data[16:]
        cipher = Cipher(algorithms.AES(key), modes.CFB(iv),
                        backend=default_backend())
        dec = cipher.decryptor()
        return dec.update(ciphertext) + dec.finalize()

    def xor(self, data: bytes, key: bytes) -> bytes:
        if isinstance(data, str): data = data.encode()
        if isinstance(key, str):  key  = key.encode()
        klen = len(key)
        return bytes(b ^ key[i % klen] for i, b in enumerate(data))

    def rc4(self, data: bytes, key: bytes) -> bytes:
        if isinstance(data, str): data = data.encode()
        if isinstance(key, str):  key  = key.encode()
        S = list(range(256))
        j = 0
        for i in range(256):
            j = (j + S[i] + key[i % len(key)]) % 256
            S[i], S[j] = S[j], S[i]
        i = j = 0
        out = []
        for byte in data:
            i = (i + 1) % 256
            j = (j + S[i]) % 256
            S[i], S[j] = S[j], S[i]
            out.append(byte ^ S[(S[i] + S[j]) % 256])
        return bytes(out)

    def hash(self, data: Any) -> bytes:
        if isinstance(data, str): data = data.encode()
        return hashlib.sha256(data).digest()

    def hmac(self, key: bytes, data: bytes) -> bytes:
        import hmac as _hmac
        if isinstance(key, str):  key  = key.encode()
        if isinstance(data, str): data = data.encode()
        return _hmac.new(key, data, hashlib.sha256).digest()

    def base64encode(self, data: bytes) -> str:
        if isinstance(data, str): data = data.encode()
        return base64.b64encode(data).decode()

    def base64decode(self, s: str) -> bytes:
        return base64.b64decode(s)

    @staticmethod
    def _pad_key(key: bytes, length: int) -> bytes:
        if isinstance(key, str): key = key.encode()
        return (key * (length // len(key) + 1))[:length]


# ─────────────────────────────────────────────────────────────────────────────
# evasion module
# ─────────────────────────────────────────────────────────────────────────────

class EvasionModule:
    """
    evasion.sleep(ms) — jittered sleep
    evasion.mutate() — trigger polymorphic re-morphing
    evasion.obfuscate(data) → bytes
    evasion.encryptBlock(data) → bytes
    evasion.checkDebugger() → bool
    evasion.checkSandbox() → bool
    evasion.loadDriver(path) → error   (BYOVD — simulated)
    evasion.disableEDR()               (simulated)
    evasion.antiVM() → bool
    """

    def __init__(self):
        self._xor_key = random.randint(1, 254)

    def sleep(self, ms: int):
        """Variable-timing sleep to evade timing analysis."""
        jitter = random.uniform(0.85, 1.15)
        time.sleep((ms / 1000.0) * jitter)

    def mutate(self):
        """Signal that the polymorphic engine should re-morph. In interpreter mode: log."""
        print("[JOCKY evasion] mutate() — polymorphic engine triggered")
        self._xor_key = random.randint(1, 254)

    def obfuscate(self, data: bytes) -> bytes:
        if isinstance(data, str): data = data.encode()
        # XOR with random key + base64 encode
        key = random.randint(1, 254)
        return bytes(b ^ key for b in data)

    def encryptBlock(self, data: Any) -> bytes:
        if isinstance(data, str): data = data.encode()
        return bytes(b ^ self._xor_key for b in data)

    def decryptBlock(self, data: bytes) -> bytes:
        return bytes(b ^ self._xor_key for b in data)

    def checkDebugger(self) -> bool:
        if _WINDOWS:
            try:
                import ctypes
                return bool(ctypes.windll.kernel32.IsDebuggerPresent())
            except Exception:
                pass
        # Linux: check TracerPid in /proc/self/status
        try:
            with open('/proc/self/status') as f:
                for line in f:
                    if line.startswith('TracerPid:'):
                        return int(line.split(':')[1].strip()) != 0
        except Exception:
            pass
        return False

    def checkSandbox(self) -> bool:
        """Heuristic sandbox detection."""
        indicators = [
            # Very low uptime
            time.time() < 100,
            # Too few processes
            (_PSUTIL and len(list(psutil.process_iter())) < 20),
            # No user directory files
            len(os.listdir(os.path.expanduser("~"))) < 3,
        ]
        return any(indicators)

    def antiVM(self) -> bool:
        """Heuristic VM detection via CPU count / memory."""
        try:
            if _PSUTIL:
                mem_gb = psutil.virtual_memory().total / (1024**3)
                if mem_gb < 2:
                    return True
            if os.cpu_count() and os.cpu_count() < 2:
                return True
        except Exception:
            pass
        return False

    def loadDriver(self, path: str) -> Optional[str]:
        """BYOVD — load vulnerable driver. Simulated in interpreter mode."""
        print(f"[JOCKY evasion] loadDriver({path!r}) — BYOVD simulated")
        return None

    def disableEDR(self):
        """Attempt kernel-level EDR disabling. Simulated in interpreter mode."""
        print("[JOCKY evasion] disableEDR() — kernel callback zeroing simulated")


# ─────────────────────────────────────────────────────────────────────────────
# debug module
# ─────────────────────────────────────────────────────────────────────────────

class DebugModule:
    """
    debug.log(msg)
    debug.dump(addr, length)
    debug.assert(cond, msg)
    debug.trace(msg)
    """

    def log(self, msg: Any):
        print(f"[JOCKY debug] {msg}")

    def dump(self, addr: int, length: int):
        buf = _mem_registry.get(addr, bytes(length))
        hex_str = ' '.join(f'{b:02X}' for b in buf[:length])
        print(f"[JOCKY debug] dump(0x{addr:016X}, {length}) = {hex_str}")

    def assert_(self, cond: bool, msg: str = "assertion failed"):
        if not cond:
            raise JockyError(f"[JOCKY] assert: {msg}")

    def trace(self, msg: str):
        import traceback
        print(f"[JOCKY debug] {msg}")
        traceback.print_stack(limit=4)


# ─────────────────────────────────────────────────────────────────────────────
# fmt module  (basic formatting)
# ─────────────────────────────────────────────────────────────────────────────

class FmtModule:
    """
    fmt.sprintf(fmt, ...args) → string
    fmt.printf(fmt, ...args)
    fmt.println(...args)
    fmt.print(...args)
    """

    def sprintf(self, fmt_str: str, *args) -> str:
        try:
            return fmt_str % args if args else fmt_str
        except Exception:
            return fmt_str + " " + " ".join(str(a) for a in args)

    def printf(self, fmt_str: str, *args):
        print(self.sprintf(fmt_str, *args), end="")

    def println(self, *args):
        print(*args)

    def print(self, *args):
        print(*args, end="")


# ─────────────────────────────────────────────────────────────────────────────
# MODULE REGISTRY  — maps module name → instance
# ─────────────────────────────────────────────────────────────────────────────

def build_stdlib() -> Dict[str, Any]:
    return {
        'sys':     SysModule(),
        'mem':     MemModule(),
        'proc':    ProcModule(),
        'fs':      FsModule(),
        'reg':     RegModule(),
        'net':     NetModule(),
        'crypto':  CryptoModule(),
        'evasion': EvasionModule(),
        'debug':   DebugModule(),
        'fmt':     FmtModule(),
    }
