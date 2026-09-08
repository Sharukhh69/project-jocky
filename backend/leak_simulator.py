# leak_simulator.py — JOCKY Controlled Data Leak Simulation Engine
# ──────────────────────────────────────────────────────────────────
# Generates realistic, benign forensic telemetry of an insider data leak.
# Used for live demonstrations, hackathon evaluations, and QA testing.

import json
import hashlib
import datetime
import sqlite3
import os

def simulate_leak_scenario(
    db_path: str,
    case_id: str,
    target_ip: str = "192.168.1.105",
    target_name: str = "DESKTOP-SUSPECT-04",
    suspect_user: str = "johndoe",
    usb_device: str = "SanDisk Ultra 64GB USB 3.0 (SN: 4C5300012304)",
    confidential_file: str = "D:\\Confidential_IP\\Defense_Source_V2.zip",
    cloud_ip: str = "104.244.42.1:443"
) -> dict:
    """
    Injects realistic, cryptographically hashed forensic artifacts of a data leak
    into the database for a target machine, establishing the timeline for demonstration.
    """
    conn = sqlite3.connect(db_path)
    c = conn.cursor()

    # Ensure target exists in database
    c.execute(
        'SELECT id FROM targets WHERE case_id=? AND target_ip=?',
        (case_id, target_ip)
    )
    row = c.fetchone()
    if not row:
        c.execute(
            'INSERT INTO targets (case_id, target_ip, target_port, target_name, os_type, status, last_seen) '
            'VALUES (?, ?, ?, ?, ?, ?, ?)',
            (case_id, target_ip, 5000, target_name, "Windows 11 Pro", "online", datetime.datetime.utcnow().isoformat())
        )

    # Base timestamp (Off-hours: 02:45 AM)
    base_date = datetime.datetime.utcnow().strftime("%Y-%m-%d")
    t1 = f"{base_date}T02:45:12"
    t2 = f"{base_date}T02:48:30"
    t3 = f"{base_date}T02:51:04"
    t4 = f"{base_date}T02:53:22"
    t5 = f"{base_date}T02:56:45"

    events = [
        # Event 1: Off-Hours User Authentication
        {
            "command": "scan.logins()",
            "timestamp": t1,
            "results": json.dumps({
                "count": 2,
                "users": [
                    {"user": suspect_user, "login_type": "Interactive (Console)", "time": t1, "session_id": 104},
                    {"user": "SYSTEM", "login_type": "Service", "time": f"{base_date}T00:00:01", "session_id": 0}
                ]
            })
        },
        # Event 2: File System Access / Staging
        {
            "command": "scan.files()",
            "timestamp": t2,
            "results": json.dumps({
                "count": 3,
                "files": [
                    {"path": confidential_file, "size_bytes": 145829100, "modified": t2, "status": "Accessed"},
                    {"path": "C:\\Users\\" + suspect_user + "\\Downloads\\staging.7z", "size_bytes": 142000000, "modified": t2, "status": "Created"},
                    {"path": "C:\\Windows\\Temp\\export_dump.bin", "size_bytes": 12000, "modified": t2, "status": "Written"}
                ]
            })
        },
        # Event 3: Suspicious Archive & Staging Utility
        {
            "command": "scan.processes()",
            "timestamp": t3,
            "results": json.dumps({
                "count": 45,
                "processes": [
                    {"pid": 4120, "name": "7z.exe", "command": f"7z.exe a -pSecret {confidential_file}", "user": suspect_user},
                    {"pid": 5892, "name": "megasync.exe", "command": "C:\\Program Files\\MegaSync\\megasync.exe", "user": suspect_user},
                    {"pid": 804, "name": "explorer.exe", "command": "C:\\Windows\\explorer.exe", "user": suspect_user}
                ]
            })
        },
        # Event 4: Physical USB Storage Mounting
        {
            "command": "scan.usb.history()",
            "timestamp": t4,
            "results": json.dumps({
                "count": 1,
                "devices": [
                    {
                        "device": usb_device,
                        "serial": "4C5300012304",
                        "mount_point": "E:\\",
                        "vendor_id": "0781",
                        "product_id": "5581",
                        "last_connected": t4
                    }
                ]
            })
        },
        # Event 5: Outbound Cloud Network Exfiltration Socket
        {
            "command": "scan.network.connections()",
            "timestamp": t5,
            "results": json.dumps({
                "count": 8,
                "connections": [
                    {
                        "local_addr": f"{target_ip}:52410",
                        "remote_addr": cloud_ip,
                        "status": "ESTABLISHED",
                        "process": "megasync.exe",
                        "protocol": "TCP"
                    },
                    {
                        "local_addr": f"{target_ip}:52412",
                        "remote_addr": "185.199.110.153:443",
                        "status": "TIME_WAIT",
                        "process": "curl.exe",
                        "protocol": "TCP"
                    }
                ]
            })
        }
    ]

    inserted_count = 0
    for ev in events:
        ev_hash = hashlib.sha256((case_id + target_ip + ev['command'] + ev['results'] + ev['timestamp']).encode()).hexdigest()
        c.execute(
            'INSERT INTO evidence (case_id, target_ip, command, results, timestamp, evidence_hash) '
            'VALUES (?, ?, ?, ?, ?, ?)',
            (case_id, target_ip, ev['command'], ev['results'], ev['timestamp'], ev_hash)
        )
        inserted_count += 1

    conn.commit()
    conn.close()

    return {
        "status": "success",
        "case_id": case_id,
        "simulated_target_ip": target_ip,
        "simulated_target_name": target_name,
        "suspect_user": suspect_user,
        "artifacts_injected": inserted_count,
        "summary": f"Injected {inserted_count} forensic timeline events for {target_name} ({target_ip}). Ready for Auto-Triage analysis."
    }
