# agent.py — JOCKY Cross-Platform Forensic Agent
# Runs on the TARGET machine (suspect's device)
# Supports: Windows & Linux
# Port: 5000 (HTTPS in production, HTTP for demo)

from flask import Flask, jsonify, request
from flask_cors import CORS
import psutil
import os
import platform
import datetime
import json
import hashlib
import socket
import subprocess

app = Flask(__name__)
CORS(app)

# ─── OS Detection ────────────────────────────────────────────────────────────
OS_TYPE = platform.system()       # "Windows" | "Linux" | "Darwin"
HOSTNAME = socket.gethostname()
AGENT_VERSION = "1.0.0-JOCKY"

print(f"""
╔══════════════════════════════════════════╗
║        JOCKY AGENT v{AGENT_VERSION}        ║
║  OS : {OS_TYPE:<35}║
║  Host : {HOSTNAME:<33}║
║  Listening on port 5000...               ║
╚══════════════════════════════════════════╝
""")

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
        "time": timestamp()
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
    """Scan a directory path for files (default: home dir + Desktop & Downloads)."""
    raw_path = request.args.get('path', '')
    if not raw_path:
        target_dirs = [
            os.path.expanduser('~'),
            os.path.join(os.path.expanduser('~'), 'Desktop'),
            os.path.join(os.path.expanduser('~'), 'Downloads'),
            os.path.join(os.path.expanduser('~'), 'Documents')
        ]
    else:
        target_dirs = [raw_path]

    file_list = []
    seen_paths = set()
    for p in target_dirs:
        if not os.path.exists(p):
            continue
        try:
            for entry in os.scandir(p):
                if entry.path in seen_paths:
                    continue
                seen_paths.add(entry.path)
                try:
                    stat = entry.stat()
                    ftype = 'Folder' if entry.is_dir() else (entry.name.split('.')[-1].upper() + ' File' if '.' in entry.name else 'File')
                    file_list.append({
                        'name':      entry.name,
                        'type':      ftype,
                        'size_kb':   round(stat.st_size / 1024, 2) if not entry.is_dir() else 0.0,
                        'modified':  datetime.datetime.fromtimestamp(stat.st_mtime).strftime('%Y-%m-%d %H:%M:%S'),
                        'path':      entry.path,
                    })
                except PermissionError:
                    pass
        except Exception:
            pass

    # Sort files first so files appear prominently before folders
    file_list.sort(key=lambda x: (1 if x['type'] == 'Folder' else 0, x['name'].lower()))

    result = {
        "os": OS_TYPE,
        "hostname": HOSTNAME,
        "scan": "files",
        "path": raw_path or os.path.expanduser('~'),
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
            """Read recent Windows Event Log login events."""
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
            except Exception as e:
                events = [{"error": str(e),
                           "note": "Run as Administrator for event log access"}]

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


# ─── Entry Point ─────────────────────────────────────────────────────────────
if __name__ == '__main__':
    app.run(host='0.0.0.0', port=5000, debug=False)
