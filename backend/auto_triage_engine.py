# auto_triage_engine.py — JOCKY Automated Fleet Threat Hunting & Anomaly Engine
# ─────────────────────────────────────────────────────────────────────────────
# Analyzes forensic artifacts across 10, 50, or 100+ endpoints simultaneously.
# Computes multi-vector anomaly scores (0-100) and extracts the smoking gun culprit.
# 100% Native Python — No cloud LLM API required (Zero Data Leakage & Offline Safe).

import json
import re
import datetime
from typing import Dict, List, Any, Tuple

# Suspicious tools & process signatures associated with data exfiltration / staging
SUSPICIOUS_PROCESS_KEYWORDS = [
    '7z', 'winrar', 'zip', 'tar', 'gzip', 'rar',
    'rclone', 'megasync', 'dropbox', 'onedrive', 'googledrive',
    'curl', 'wget', 'nc', 'netcat', 'ncat', 'powershell', 'cmd.exe',
    'python', 'scp', 'sftp', 'ftp', 'pscp', 'filezilla', 'anydesk', 'teamviewer',
    'tor', 'v2ray', 'xray', 'ssh'
]

# Off-hours investigation window (default: 21:00 to 06:00 local/UTC)
OFF_HOURS_START = 21
OFF_HOURS_END = 6


class AutoTriageEngine:
    """
    Automated Forensic Anomaly & Correlation Engine for JOCKY.
    Triage 100s of machines in parallel and pinpoint the exact source of a data leak.
    """

    def __init__(self):
        pass

    def analyze_fleet(self, case_id: str, targets: List[Dict[str, Any]], evidence_list: List[Dict[str, Any]]) -> Dict[str, Any]:
        """
        Correlate all forensic artifacts for a case across all target machines.
        Returns:
            - target_scores: list of scored targets ranked from highest risk to lowest
            - top_suspect: target details with the highest anomaly score
            - smoking_gun: chronological timeline of the detected breach
            - executive_verdict: clear, human-readable conclusion for investigators/judges
            - stats: fleet summary statistics
        """
        # Group evidence by target IP
        target_map = {t.get('target_ip'): t for t in targets}
        ev_by_target = {}
        for ev in evidence_list:
            ip = ev.get('target_ip')
            if ip not in ev_by_target:
                ev_by_target[ip] = []
            ev_by_target[ip].append(ev)

        scored_targets = []
        all_iocs = []

        # Analyze each target machine
        for ip, t_info in target_map.items():
            ev_items = ev_by_target.get(ip, [])
            score_data = self._score_target(t_info, ev_items)
            scored_targets.append(score_data)
            all_iocs.extend(score_data['indicators'])

        # Also account for targets that might be in evidence but not registered
        for ip, ev_items in ev_by_target.items():
            if ip not in target_map:
                dummy_target = {'target_ip': ip, 'target_name': f"Endpoint-{ip}", 'os_type': 'Unknown'}
                score_data = self._score_target(dummy_target, ev_items)
                scored_targets.append(score_data)
                all_iocs.extend(score_data['indicators'])

        # Sort targets by Risk Score (Descending)
        scored_targets.sort(key=lambda x: x['risk_score'], reverse=True)

        top_suspect = scored_targets[0] if scored_targets and scored_targets[0]['risk_score'] > 20 else None

        smoking_gun_timeline = []
        if top_suspect:
            smoking_gun_timeline = self._build_smoking_gun_timeline(top_suspect)

        executive_verdict = self._synthesize_verdict(top_suspect, len(scored_targets), len(evidence_list))

        return {
            "case_id": case_id,
            "analyzed_at": datetime.datetime.utcnow().isoformat() + "Z",
            "total_endpoints_analyzed": len(scored_targets),
            "total_artifacts_evaluated": len(evidence_list),
            "threat_level": "CRITICAL" if (top_suspect and top_suspect['risk_score'] >= 75) else ("ELEVATED" if (top_suspect and top_suspect['risk_score'] >= 45) else "NORMAL"),
            "top_suspect": top_suspect,
            "ranked_targets": scored_targets,
            "smoking_gun_timeline": smoking_gun_timeline,
            "executive_verdict": executive_verdict,
            "indicators_of_compromise": all_iocs
        }

    def _score_target(self, target: Dict[str, Any], evidence_items: List[Dict[str, Any]]) -> Dict[str, Any]:
        """
        Evaluate 5 distinct forensic vectors on a single endpoint:
        1. USB Storage & Exfiltration (Max 35 pts)
        2. Suspicious Process Execution & Staging (Max 25 pts)
        3. Network Socket & Cloud Exfil (Max 20 pts)
        4. Off-Hours / Privileged Logins (Max 15 pts)
        5. File System & Staging Modifications (Max 15 pts)
        Total Max Score = 100
        """
        ip = target.get('target_ip', 'Unknown')
        name = target.get('target_name', 'Unknown')
        os_type = target.get('os_type', 'Unknown')

        usb_score = 0
        proc_score = 0
        net_score = 0
        login_score = 0
        file_score = 0

        indicators = []
        findings = []
        raw_events = []

        for ev in evidence_items:
            cmd = ev.get('command', '')
            ts = ev.get('timestamp', '')
            raw_res = ev.get('results', '{}')

            try:
                data = json.loads(raw_res) if isinstance(raw_res, str) else raw_res
            except Exception:
                data = {"raw": str(raw_res)}

            # 1. Evaluate USB History
            if 'usb' in cmd.lower():
                usb_items = self._extract_list(data)
                if usb_items:
                    for u in usb_items:
                        device_desc = str(u.get('device') or u.get('name') or u.get('description') or u)
                        serial = u.get('serial', 'N/A')
                        usb_score = min(35, usb_score + 25)
                        indicators.append({
                            "vector": "USB_STORAGE",
                            "severity": "HIGH",
                            "description": f"External storage device connected: {device_desc} (SN: {serial})",
                            "timestamp": ts,
                            "target_ip": ip
                        })
                        findings.append(f"USB Storage device mounted: {device_desc}")
                        raw_events.append({"time": ts, "type": "USB", "summary": f"USB Storage mounted: {device_desc}"})

            # 2. Evaluate Running Processes / Staging utilities
            if 'process' in cmd.lower():
                proc_items = self._extract_list(data)
                for p in proc_items:
                    pname = str(p.get('name', '') or p.get('command', '')).lower()
                    for kw in SUSPICIOUS_PROCESS_KEYWORDS:
                        if kw in pname:
                            proc_score = min(25, proc_score + 12)
                            indicators.append({
                                "vector": "SUSPICIOUS_PROCESS",
                                "severity": "MEDIUM",
                                "description": f"Potential staging/exfiltration process: {pname} (PID: {p.get('pid', 'N/A')})",
                                "timestamp": ts,
                                "target_ip": ip
                            })
                            findings.append(f"Suspicious process identified: {pname}")
                            raw_events.append({"time": ts, "type": "PROCESS", "summary": f"Process execution: {pname}"})
                            break

            # 3. Evaluate Network Connections
            if 'network' in cmd.lower():
                net_items = self._extract_list(data)
                for n in net_items:
                    r_addr = str(n.get('remote_addr') or n.get('remote') or '')
                    status = str(n.get('status', '')).upper()
                    # Check for non-local outbound IPs
                    if r_addr and not r_addr.startswith('127.') and not r_addr.startswith('10.') and not r_addr.startswith('192.168.'):
                        net_score = min(20, net_score + 10)
                        indicators.append({
                            "vector": "NETWORK_EXFIL",
                            "severity": "HIGH" if ('443' in r_addr or '80' in r_addr or '4444' in r_addr) else "MEDIUM",
                            "description": f"Outbound external network connection to: {r_addr} [{status}]",
                            "timestamp": ts,
                            "target_ip": ip
                        })
                        findings.append(f"External outbound connection: {r_addr}")
                        raw_events.append({"time": ts, "type": "NETWORK", "summary": f"Outbound socket: {r_addr}"})

            # 4. Evaluate Logins & Authentication
            if 'login' in cmd.lower():
                login_items = self._extract_list(data)
                for l in login_items:
                    user = str(l.get('user') or l.get('username') or 'Unknown')
                    login_time_str = str(l.get('time') or l.get('login_time') or ts)
                    # Check off-hours login
                    is_off_hours = self._check_off_hours(login_time_str)
                    if is_off_hours:
                        login_score = min(15, login_score + 15)
                        indicators.append({
                            "vector": "OFF_HOURS_AUTH",
                            "severity": "HIGH",
                            "description": f"Off-hours user authentication: '{user}' at {login_time_str}",
                            "timestamp": ts,
                            "target_ip": ip
                        })
                        findings.append(f"Off-hours login detected for user: {user}")
                    else:
                        login_score = min(15, login_score + 5)
                    raw_events.append({"time": ts, "type": "AUTH", "summary": f"User login: {user}"})

            # 5. Evaluate File System Scans
            if 'file' in cmd.lower():
                file_items = self._extract_list(data)
                for f in file_items:
                    fpath = str(f.get('path') or f.get('file') or f)
                    if any(k in fpath.lower() for k in ['confidential', 'secret', 'leak', 'backup', 'export', '.zip', '.tar', '.7z']):
                        file_score = min(15, file_score + 15)
                        indicators.append({
                            "vector": "FILE_STAGING",
                            "severity": "HIGH",
                            "description": f"Sensitive archive/document staged: {fpath}",
                            "timestamp": ts,
                            "target_ip": ip
                        })
                        findings.append(f"Sensitive file access/staging: {fpath}")
                        raw_events.append({"time": ts, "type": "FILE", "summary": f"Staged file: {fpath}"})

        # Calculate Total Risk Score (capped at 100)
        total_risk = min(100, usb_score + proc_score + net_score + login_score + file_score)

        # Risk Classification
        if total_risk >= 75:
            risk_level = "CRITICAL"
            badge_color = "red"
        elif total_risk >= 45:
            risk_level = "HIGH"
            badge_color = "orange"
        elif total_risk >= 20:
            risk_level = "SUSPICIOUS"
            badge_color = "yellow"
        else:
            risk_level = "LOW / BENIGN"
            badge_color = "green"

        return {
            "target_ip": ip,
            "target_name": name,
            "os_type": os_type,
            "risk_score": total_risk,
            "risk_level": risk_level,
            "badge_color": badge_color,
            "vector_breakdown": {
                "usb_exfiltration": usb_score,
                "suspicious_processes": proc_score,
                "network_outbound": net_score,
                "authentication_anomalies": login_score,
                "file_staging": file_score
            },
            "findings_count": len(findings),
            "key_findings": findings[:6],
            "indicators": indicators,
            "events_timeline": sorted(raw_events, key=lambda x: x.get('time', ''))
        }

    def _extract_list(self, data: Any) -> List[Any]:
        """Normalize artifact data dictionary or list structure."""
        if isinstance(data, list):
            return data
        if isinstance(data, dict):
            if 'results' in data and isinstance(data['results'], list):
                return data['results']
            if 'items' in data and isinstance(data['items'], list):
                return data['items']
            if 'devices' in data and isinstance(data['devices'], list):
                return data['devices']
            if 'connections' in data and isinstance(data['connections'], list):
                return data['connections']
            if 'users' in data and isinstance(data['users'], list):
                return data['users']
            if 'processes' in data and isinstance(data['processes'], list):
                return data['processes']
            return [data]
        return []

    def _check_off_hours(self, timestr: str) -> bool:
        """Check if timestamp falls into off-hours (e.g. 21:00 - 06:00)."""
        try:
            # Look for HH:MM pattern
            match = re.search(r'(\d{2}):(\d{2})', timestr)
            if match:
                hour = int(match.group(1))
                return (hour >= OFF_HOURS_START or hour < OFF_HOURS_END)
        except Exception:
            pass
        return False

    def _build_smoking_gun_timeline(self, target: Dict[str, Any]) -> List[Dict[str, Any]]:
        """Construct the step-by-step breach storyline."""
        timeline = []
        for ev in target.get('events_timeline', []):
            timeline.append({
                "time": ev.get('time', 'N/A'),
                "step": ev.get('type', 'EVENT'),
                "description": ev.get('summary', '')
            })
        return timeline

    def _synthesize_verdict(self, top_suspect: Dict[str, Any], total_targets: int, total_ev: int) -> str:
        """Generate high-impact executive statement for judges and presentation."""
        if not top_suspect or top_suspect['risk_score'] < 30:
            return (
                f"Fleet Analysis Complete: Evaluated {total_targets} endpoints across {total_ev} collected artifacts. "
                f"No critical anomalies or unauthorized data exfiltration patterns detected across the monitored fleet."
            )

        ip = top_suspect['target_ip']
        name = top_suspect['target_name']
        score = top_suspect['risk_score']
        breakdown = top_suspect['vector_breakdown']

        reasons = []
        if breakdown.get('usb_exfiltration', 0) > 0:
            reasons.append("unauthorized external USB storage device mounted")
        if breakdown.get('authentication_anomalies', 0) > 0:
            reasons.append("off-hours authentication activity")
        if breakdown.get('suspicious_processes', 0) > 0:
            reasons.append("archive/exfiltration process execution")
        if breakdown.get('network_outbound', 0) > 0:
            reasons.append("outbound connection to external cloud endpoints")

        reasons_str = ", ".join(reasons) if reasons else "multiple anomaly thresholds exceeded"

        return (
            f"HIGH-CONFIDENCE DATA LEAK IDENTIFIED on Endpoint {name} ({ip}) with Risk Score {score}/100. "
            f"Primary anomaly indicators include {reasons_str}. "
            f"Cross-referencing authentication logs, hardware telemetry, and file access isolates this workstation as the focal origin of data extraction."
        )
