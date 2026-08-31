"""
SentinelSOC Correlation Engine & Incident Management Service
Correlates real-time security events into contextual incidents, mapping to MITRE ATT&CK techniques.
Persists incident state lightweight in SQLite so changes survive server restarts.
Enforces strict scenario isolation for concurrent simulation attack chains.
"""
import os
import json
import sqlite3
import logging
from datetime import datetime, timezone
from typing import Dict, Any, List, Optional
from app.models.schemas import SecurityEvent, Incident, MitreTechnique, calculate_risk_score, derive_risk_level, calculate_risk
from app.services.mitre_service import get_technique

logger = logging.getLogger("sentinel.correlation")

DB_PATH = os.getenv("SQLITE_DB_PATH", os.path.join(os.path.dirname(__file__), "..", "..", "sentinel.db"))

SCENARIO_INCIDENT_TEMPLATES: Dict[str, Dict[str, Any]] = {
    "scenario_credential_brute_force": {
        "title_template": "Credential Spray & Brute Force on {target}",
        "category": "Credential Access",
        "severity": "CRITICAL",
        "summary_template": "Detected multiple successive authentication failures and credential brute force pattern from {source_ip} targeting {target}.",
        "recommended_actions": [
            "Enforce immediate IP block on firewall for {source_ip}.",
            "Verify multi-factor authentication (MFA) status on affected service accounts.",
            "Audit SSH/RDP session authorization tables for successful logins from this IP.",
            "Lock targeted accounts temporarily and initiate credential resets."
        ],
        "related_cves": [],
        "initial_technique_ids": ["T1110", "T1078"]
    },
    "scenario_web_cve_exploitation": {
        "title_template": "Web Application Vulnerability Exploitation on {target}",
        "category": "Initial Access",
        "severity": "CRITICAL",
        "summary_template": "Multi-stage intrusion chain: Web vulnerability probing, SQL injection, and remote code execution payload executed against {target}.",
        "recommended_actions": [
            "Isolate host {target} from sensitive VLAN segments.",
            "Inspect web application access logs for anomalous POST payloads and file uploads.",
            "Scan web directories (/var/www/uploads/) for dropped webshells or backdoor scripts.",
            "Apply vendor emergency security patch immediately."
        ],
        "related_cves": ["CVE-2023-34362", "CVE-2024-3400"],
        "initial_technique_ids": ["T1190", "T1059.001"]
    },
    "scenario_reconnaissance_port_scan": {
        "title_template": "Network Reconnaissance & Vulnerability Probing on {target}",
        "category": "Reconnaissance",
        "severity": "HIGH",
        "summary_template": "High-velocity TCP SYN sweep, active service enumeration, and vulnerability scan detected targeting {target} from {source_ip}.",
        "recommended_actions": [
            "Configure rate limiting and perimeter firewall filters for {source_ip}.",
            "Verify no unintended services are exposed on {target}.",
            "Review perimeter ingress logs for reconnaissance patterns."
        ],
        "related_cves": [],
        "initial_technique_ids": ["T1595.002", "T1046"]
    },
    "scenario_powershell_privilege_escalation": {
        "title_template": "Suspicious PowerShell Execution & Privilege Escalation on {target}",
        "category": "Execution",
        "severity": "CRITICAL",
        "summary_template": "Obfuscated PowerShell cradle, defense evasion (AV tampering), and process injection detected on {target} from {source_ip}.",
        "recommended_actions": [
            "Terminate malicious PowerShell processes on {target}.",
            "Re-enable Windows Defender real-time protection and verify antivirus definitions.",
            "Capture memory dump of injected svchost process for forensic triage.",
            "Revoke elevated tokens and audit local administrator group membership."
        ],
        "related_cves": [],
        "initial_technique_ids": ["T1059.001", "T1562.001", "T1055", "T1068"]
    },
    "scenario_ransomware_execution": {
        "title_template": "Critical Ransomware & Lateral Movement Activity on {target}",
        "category": "Impact",
        "severity": "CRITICAL",
        "summary_template": "Rapid file encryption patterns, volume shadow copy deletion, and lateral SMB traversal observed from {source_ip} on {target}.",
        "recommended_actions": [
            "Sever network link immediately to halt encryption propagation across network shares.",
            "Verify offline backup repository integrity and snapshot air-gapping.",
            "Revoke domain administrative credentials and force kerberos ticket resets.",
            "Initiate incident response disaster recovery and forensic containment protocol."
        ],
        "related_cves": [],
        "initial_technique_ids": ["T1486", "T1490", "T1021.002"]
    },
    "scenario_data_exfiltration": {
        "title_template": "Unauthorized Database Compromise & Exfiltration on {target}",
        "category": "Exfiltration",
        "severity": "CRITICAL",
        "summary_template": "High-volume database extraction and encrypted staging transfer detected originating from non-whitelisted host {source_ip} on {target}.",
        "recommended_actions": [
            "Terminate active database connections immediately and rotate service credentials.",
            "Inspect SQL query logs for executed COPY or SELECT INTO statements.",
            "Verify perimeter firewall and DLP blocking rules for external destination IP.",
            "Perform forensic review of staged archive files on disk."
        ],
        "related_cves": [],
        "initial_technique_ids": ["T1041", "T1005", "T1048"]
    }
}


class CorrelationEngine:
    def __init__(self, db_path: Optional[str] = None):
        self._events_buffer: List[SecurityEvent] = []
        self._incidents: Dict[str, Incident] = {}
        self._incident_counter = 100
        self._db_path = db_path or DB_PATH
        self._init_sqlite()
        self._load_or_seed_incidents()

    def _get_db_conn(self) -> sqlite3.Connection:
        conn = sqlite3.connect(self._db_path)
        conn.row_factory = sqlite3.Row
        return conn

    def _init_sqlite(self):
        """Create incidents table if it does not exist and ensure all columns exist."""
        try:
            with self._get_db_conn() as conn:
                conn.execute("""
                    CREATE TABLE IF NOT EXISTS incidents (
                        incident_id TEXT PRIMARY KEY,
                        title TEXT NOT NULL,
                        severity TEXT NOT NULL,
                        status TEXT NOT NULL,
                        confidence REAL NOT NULL,
                        category TEXT NOT NULL,
                        source_ip TEXT NOT NULL,
                        target TEXT NOT NULL,
                        event_ids TEXT NOT NULL,
                        events_count INTEGER NOT NULL,
                        techniques TEXT NOT NULL,
                        related_cves TEXT NOT NULL,
                        created_at TEXT NOT NULL,
                        updated_at TEXT NOT NULL,
                        summary TEXT NOT NULL,
                        recommended_actions TEXT NOT NULL,
                        ai_analysis TEXT,
                        source_ips TEXT,
                        affected_targets TEXT,
                        attack_stage TEXT,
                        first_seen TEXT,
                        last_seen TEXT,
                        scenario_id TEXT,
                        risk TEXT,
                        risk_score INTEGER
                    )
                """)
                # Migrations for existing databases
                for col, col_type in (
                    ("source_ips", "TEXT"),
                    ("affected_targets", "TEXT"),
                    ("attack_stage", "TEXT"),
                    ("first_seen", "TEXT"),
                    ("last_seen", "TEXT"),
                    ("scenario_id", "TEXT"),
                    ("risk", "TEXT"),
                    ("risk_score", "INTEGER")
                ):
                    try:
                        conn.execute(f"ALTER TABLE incidents ADD COLUMN {col} {col_type}")
                    except Exception:
                        pass
                conn.commit()
        except Exception as e:
            logger.warning(f"Could not initialize SQLite incident table: {e}")

    def _save_incident_to_db(self, inc: Incident):
        try:
            if inc.risk_score is None:
                inc.risk_score = calculate_risk_score(inc.severity, inc.confidence)
            if not inc.risk:
                inc.risk = derive_risk_level(inc.risk_score)

            with self._get_db_conn() as conn:
                conn.execute("""
                    INSERT INTO incidents (
                        incident_id, title, severity, status, confidence, category,
                        source_ip, target, event_ids, events_count, techniques,
                        related_cves, created_at, updated_at, summary,
                        recommended_actions, ai_analysis,
                        source_ips, affected_targets, attack_stage, first_seen, last_seen, scenario_id,
                        risk, risk_score
                    ) VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)
                    ON CONFLICT(incident_id) DO UPDATE SET
                        title=excluded.title,
                        severity=excluded.severity,
                        status=excluded.status,
                        confidence=excluded.confidence,
                        event_ids=excluded.event_ids,
                        events_count=excluded.events_count,
                        techniques=excluded.techniques,
                        related_cves=excluded.related_cves,
                        updated_at=excluded.updated_at,
                        summary=excluded.summary,
                        recommended_actions=excluded.recommended_actions,
                        ai_analysis=excluded.ai_analysis,
                        source_ips=excluded.source_ips,
                        affected_targets=excluded.affected_targets,
                        attack_stage=excluded.attack_stage,
                        last_seen=excluded.last_seen,
                        scenario_id=excluded.scenario_id,
                        risk=excluded.risk,
                        risk_score=excluded.risk_score
                """, (
                    inc.incident_id,
                    inc.title,
                    inc.severity,
                    inc.status,
                    inc.confidence,
                    inc.category,
                    inc.source_ip,
                    inc.target,
                    json.dumps(inc.event_ids),
                    inc.events_count,
                    json.dumps([t.model_dump() for t in inc.techniques]),
                    json.dumps(inc.related_cves),
                    inc.created_at,
                    inc.updated_at,
                    inc.summary,
                    json.dumps(inc.recommended_actions),
                    json.dumps(inc.ai_analysis) if inc.ai_analysis else None,
                    json.dumps(inc.source_ips),
                    json.dumps(inc.affected_targets),
                    inc.attack_stage or "Initial Access",
                    inc.first_seen or inc.created_at,
                    inc.last_seen or inc.updated_at,
                    inc.scenario_id,
                    inc.risk,
                    inc.risk_score
                ))
                conn.commit()
        except Exception as e:
            logger.warning(f"Failed to persist incident {inc.incident_id} to SQLite: {e}")

    def _load_or_seed_incidents(self):
        """Load incidents from SQLite; if table is empty, seed baseline incidents."""
        try:
            with self._get_db_conn() as conn:
                rows = conn.execute("SELECT * FROM incidents").fetchall()
                if rows:
                    for row in rows:
                        techniques_data = json.loads(row["techniques"]) if row["techniques"] else []
                        techniques = [MitreTechnique(**t) for t in techniques_data]
                        ai_analysis = json.loads(row["ai_analysis"]) if row["ai_analysis"] else None

                        source_ips = json.loads(row["source_ips"]) if "source_ips" in row.keys() and row["source_ips"] else [row["source_ip"]]
                        affected_targets = json.loads(row["affected_targets"]) if "affected_targets" in row.keys() and row["affected_targets"] else [row["target"]]
                        attack_stage = row["attack_stage"] if "attack_stage" in row.keys() and row["attack_stage"] else "Initial Access"
                        first_seen = row["first_seen"] if "first_seen" in row.keys() and row["first_seen"] else row["created_at"]
                        last_seen = row["last_seen"] if "last_seen" in row.keys() and row["last_seen"] else row["updated_at"]
                        scenario_id = row["scenario_id"] if "scenario_id" in row.keys() and row["scenario_id"] else None
                        risk = row["risk"] if "risk" in row.keys() and row["risk"] else None
                        risk_score = row["risk_score"] if "risk_score" in row.keys() and row["risk_score"] is not None else None

                        # Legacy DB migration: detect scenario_id for known baseline seeds if missing
                        if not scenario_id:
                            title_lower = row["title"].lower()
                            if "brute force" in title_lower or "credential spray" in title_lower or "password spray" in title_lower:
                                scenario_id = "scenario_credential_brute_force"
                            elif "moveit" in title_lower or "web application exploit" in title_lower or "vulnerability exploit" in title_lower:
                                scenario_id = "scenario_web_cve_exploitation"
                            elif "ransomware" in title_lower or "shadow copy" in title_lower:
                                scenario_id = "scenario_ransomware_execution"
                            elif "powershell" in title_lower and "privilege" in title_lower:
                                scenario_id = "scenario_powershell_privilege_escalation"
                            elif "reconnaissance" in title_lower or "port scan" in title_lower:
                                scenario_id = "scenario_reconnaissance_port_scan"
                            elif "exfiltration" in title_lower or "database compromise" in title_lower:
                                scenario_id = "scenario_data_exfiltration"

                        inc = Incident(
                            incident_id=row["incident_id"],
                            id=row["incident_id"],
                            scenario_id=scenario_id,
                            title=row["title"],
                            severity=row["severity"],
                            status=row["status"],
                            confidence=row["confidence"],
                            risk=risk,
                            risk_score=risk_score,
                            category=row["category"],
                            source_ip=row["source_ip"],
                            target=row["target"],
                            source_ips=source_ips,
                            affected_targets=affected_targets,
                            attack_stage=attack_stage,
                            first_seen=first_seen,
                            last_seen=last_seen,
                            event_ids=json.loads(row["event_ids"]),
                            events_count=row["events_count"],
                            techniques=techniques,
                            related_cves=json.loads(row["related_cves"]),
                            created_at=row["created_at"],
                            updated_at=row["updated_at"],
                            summary=row["summary"],
                            recommended_actions=json.loads(row["recommended_actions"]),
                            ai_analysis=ai_analysis
                        )
                        self._incidents[inc.incident_id] = inc

                        # Track max incident counter
                        if inc.incident_id.startswith("INC-"):
                            try:
                                num = int(inc.incident_id.replace("INC-", ""))
                                if num > self._incident_counter:
                                    self._incident_counter = num
                            except ValueError:
                                pass
                    logger.info(f"Loaded {len(self._incidents)} incidents from SQLite persistence.")
                    return
        except Exception as e:
            logger.warning(f"Error reading incidents from SQLite: {e}")

        # Baseline seed
        now = datetime.now(timezone.utc).isoformat()
        t1110 = get_technique("T1110")
        t1078 = get_technique("T1078")
        t1190 = get_technique("T1190")
        t1059 = get_technique("T1059.001")

        inc1 = Incident(
            incident_id="INC-101",
            id="INC-101",
            scenario_id="scenario_credential_brute_force",
            title="Credential Spraying & SSH Brute Force Attack",
            severity="CRITICAL",
            status="OPEN",
            confidence=0.96,
            category="Credential Access",
            source_ip="192.168.1.105",
            target="auth-gateway.corp.internal",
            source_ips=["192.168.1.105"],
            affected_targets=["auth-gateway.corp.internal"],
            attack_stage="Credential Access / Account Compromise",
            first_seen=now,
            last_seen=now,
            event_ids=["SIM-1001", "SIM-1002", "SIM-1003", "SIM-1004"],
            events_count=4,
            techniques=[t for t in (t1110, t1078) if t is not None],
            related_cves=[],
            created_at=now,
            updated_at=now,
            summary="Rapid successive authentication failures detected against auth-gateway followed by brute force threshold violation and valid account abuse.",
            recommended_actions=[
                "Apply immediate firewall drop rule for source IP 192.168.1.105.",
                "Verify MFA status on targeted accounts (root, administrator, svc_backup).",
                "Audit SSH authorization logs for any subsequent successful sessions.",
                "Review credential rotation policies and terminate active sessions."
            ]
        )

        inc2 = Incident(
            incident_id="INC-102",
            id="INC-102",
            scenario_id="scenario_web_cve_exploitation",
            title="Public Web Application Exploit Chain (MOVEit / SQLi)",
            severity="CRITICAL",
            status="INVESTIGATING",
            confidence=0.94,
            category="Initial Access",
            source_ip="10.0.4.15",
            target="dmz-web-portal.corp.internal",
            source_ips=["10.0.4.15"],
            affected_targets=["dmz-web-portal.corp.internal"],
            attack_stage="Initial Access / Exploit Execution",
            first_seen=now,
            last_seen=now,
            event_ids=["SIM-1005", "SIM-1006", "SIM-1007", "SIM-1008"],
            events_count=4,
            techniques=[t for t in (t1190, t1059) if t is not None],
            related_cves=["CVE-2023-34362", "CVE-2024-3400"],
            created_at=now,
            updated_at=now,
            summary="Automated URI scanning followed by SQL injection and remote code execution exploit payloads targeting DMZ web portal endpoints.",
            recommended_actions=[
                "Enable WAF SQL injection and command injection blocking rules on reverse proxy.",
                "Inspect web application error logs for SQL syntax exceptions and abnormal POST requests.",
                "Verify database query parameterization and ORM sanitization.",
                "Scan filesystem for dropped web shells (/var/www/uploads/) and isolate affected container."
            ]
        )

        self._incidents[inc1.incident_id] = inc1
        self._incidents[inc2.incident_id] = inc2
        self._incident_counter = max(self._incident_counter, 102)
        self._save_incident_to_db(inc1)
        self._save_incident_to_db(inc2)

    def _determine_stage(self, event_type: str) -> str:
        mapping = {
            "PORT_SCAN": "Reconnaissance: Network Discovery",
            "SERVICE_ENUMERATION": "Reconnaissance: Service Enumeration",
            "VULNERABILITY_SCAN": "Reconnaissance: Vulnerability Scanning",
            "LOGIN_FAILURE": "Credential Access: Password Spray",
            "BRUTE_FORCE": "Credential Access: High-Velocity Brute Force",
            "SUSPICIOUS_LOGIN": "Initial Access: Valid Account Abuse",
            "SQL_INJECTION": "Initial Access: Web Injection Attempt",
            "EXPLOIT_ATTEMPT": "Initial Access: Vulnerability Exploitation",
            "MALWARE_ALERT": "Execution: Malicious Script / Web Shell",
            "POWERSHELL_EXECUTION": "Execution: Obfuscated PowerShell Command",
            "PROCESS_INJECTION": "Defense Evasion: Process Memory Injection",
            "DEFENSE_EVASION": "Defense Evasion: Antivirus / EDR Tampering",
            "PRIVILEGE_ESCALATION": "Privilege Escalation: Token / Kernel Elevation",
            "LATERAL_MOVEMENT": "Lateral Movement: Administrative SMB Access",
            "SMB_EXECUTION": "Lateral Movement: Remote Service Execution",
            "SHADOW_COPY_DELETION": "Impact: System Recovery Inhabitation",
            "RANSOMWARE_ACTIVITY": "Impact: High-Velocity Data Encryption",
            "DATA_STAGING": "Collection: Local Data Staging Archive",
            "DATA_EXFILTRATION": "Exfiltration: High-Volume Outbound Transfer",
            "OUTBOUND_TRANSFER": "Exfiltration: Protocol Exfiltration",
            "C2_COMMUNICATION": "Command and Control: External Beaconing",
            "CREDENTIAL_DUMP": "Credential Access: OS Credential Dumping"
        }
        return mapping.get(event_type.upper(), "Active Attack Progression")

    def process_event(self, event: SecurityEvent) -> Optional[Incident]:
        """Ingest a security event, add to sliding window, and run contextual correlation rules."""
        self._events_buffer.append(event)
        if len(self._events_buffer) > 250:
            self._events_buffer = self._events_buffer[-250:]

        now_str = datetime.now(timezone.utc).isoformat()
        stage = self._determine_stage(event.event_type)

        # ---------------------------------------------------------
        # CASE A: Event has scenario_id -> STRICT SIMULATION SCENARIO ISOLATION
        # ---------------------------------------------------------
        if event.scenario_id:
            existing_inc: Optional[Incident] = None
            for inc in self._incidents.values():
                if inc.status in ("OPEN", "INVESTIGATING") and inc.scenario_id == event.scenario_id:
                    existing_inc = inc
                    break

            if existing_inc:
                if event.event_id not in existing_inc.event_ids:
                    existing_inc.event_ids.append(event.event_id)
                    existing_inc.events_count = len(existing_inc.event_ids)

                if event.source_ip and event.source_ip not in existing_inc.source_ips:
                    existing_inc.source_ips.append(event.source_ip)

                if event.target and event.target not in existing_inc.affected_targets:
                    existing_inc.affected_targets.append(event.target)

                if event.mitre_technique and not any(t.id == event.mitre_technique.id for t in existing_inc.techniques):
                    existing_inc.techniques.append(event.mitre_technique)

                # Escalate severity if critical step occurs
                if event.severity.upper() == "CRITICAL" and existing_inc.severity != "CRITICAL":
                    existing_inc.severity = "CRITICAL"

                existing_inc.attack_stage = stage
                existing_inc.last_seen = event.timestamp or now_str
                existing_inc.updated_at = now_str
                existing_inc.confidence = min(0.99, round(existing_inc.confidence + 0.01, 2))
                existing_inc.risk_score = calculate_risk_score(existing_inc.severity, existing_inc.confidence)
                existing_inc.risk = derive_risk_level(existing_inc.risk_score)

                self._save_incident_to_db(existing_inc)
                return existing_inc

            # Create new incident strictly bound to this scenario_id
            self._incident_counter += 1
            inc_id = f"INC-{self._incident_counter}"
            template = SCENARIO_INCIDENT_TEMPLATES.get(event.scenario_id)

            if template:
                title = template["title_template"].format(target=event.target, source_ip=event.source_ip)
                category = template["category"]
                sev = "CRITICAL" if event.severity.upper() == "CRITICAL" else template["severity"]
                summary = template["summary_template"].format(target=event.target, source_ip=event.source_ip)
                actions = [a.format(target=event.target, source_ip=event.source_ip) for a in template["recommended_actions"]]
                related_cves = list(template.get("related_cves", []))
                tech_list = [get_technique(tid) for tid in template.get("initial_technique_ids", [])]
                techniques = [t for t in tech_list if t is not None]
                if event.mitre_technique and not any(t.id == event.mitre_technique.id for t in techniques):
                    techniques.append(event.mitre_technique)
            else:
                scen_name = event.metadata.get("scenario_name", event.scenario_id) if event.metadata else event.scenario_id
                title = f"Security Incident: {scen_name} on {event.target}"
                category = "Threat Activity"
                sev = event.severity.upper() if event.severity else "HIGH"
                summary = f"Multi-stage suspicious activity detected on {event.target} originating from {event.source_ip}."
                actions = [
                    f"Investigate active connections from {event.source_ip}.",
                    f"Review application and security logs for target {event.target}."
                ]
                related_cves = []
                techniques = [event.mitre_technique] if event.mitre_technique else []

            new_inc = Incident(
                incident_id=inc_id,
                id=inc_id,
                scenario_id=event.scenario_id,
                title=title,
                severity=sev,
                status="OPEN",
                confidence=0.95,
                category=category,
                source_ip=event.source_ip,
                target=event.target,
                source_ips=[event.source_ip],
                affected_targets=[event.target],
                attack_stage=stage,
                first_seen=event.timestamp or now_str,
                last_seen=event.timestamp or now_str,
                event_ids=[event.event_id],
                events_count=1,
                techniques=techniques,
                related_cves=related_cves,
                created_at=now_str,
                updated_at=now_str,
                summary=summary,
                recommended_actions=actions
            )
            self._incidents[inc_id] = new_inc
            self._save_incident_to_db(new_inc)
            logger.info(f"Created isolated scenario incident: {inc_id} ({event.scenario_id}) - {new_inc.title}")
            return new_inc

        # ---------------------------------------------------------
        # CASE B: Non-simulation Telemetry (scenario_id is None)
        # ---------------------------------------------------------
        existing_non_sim: Optional[Incident] = None
        for inc in self._incidents.values():
            if inc.status in ("OPEN", "INVESTIGATING") and inc.scenario_id is None:
                # Same attacker IP
                if event.source_ip == inc.source_ip or (inc.source_ips and event.source_ip in inc.source_ips):
                    existing_non_sim = inc
                    break
                # Same target under active exploit/ransomware/exfiltration
                if event.target == inc.target and event.event_type in ("EXPLOIT_ATTEMPT", "RANSOMWARE_ACTIVITY", "DATA_EXFILTRATION"):
                    existing_non_sim = inc
                    break

        if existing_non_sim:
            if event.event_id not in existing_non_sim.event_ids:
                existing_non_sim.event_ids.append(event.event_id)
                existing_non_sim.events_count = len(existing_non_sim.event_ids)

            if event.source_ip and event.source_ip not in existing_non_sim.source_ips:
                existing_non_sim.source_ips.append(event.source_ip)

            if event.target and event.target not in existing_non_sim.affected_targets:
                existing_non_sim.affected_targets.append(event.target)

            if event.mitre_technique and not any(t.id == event.mitre_technique.id for t in existing_non_sim.techniques):
                existing_non_sim.techniques.append(event.mitre_technique)

            if event.severity.upper() == "CRITICAL" and existing_non_sim.severity != "CRITICAL":
                existing_non_sim.severity = "CRITICAL"

            existing_non_sim.attack_stage = stage
            existing_non_sim.last_seen = event.timestamp or now_str
            existing_non_sim.updated_at = now_str
            existing_non_sim.confidence = min(0.99, round(existing_non_sim.confidence + 0.01, 2))
            existing_non_sim.risk_score = calculate_risk_score(existing_non_sim.severity, existing_non_sim.confidence)
            existing_non_sim.risk = derive_risk_level(existing_non_sim.risk_score)

            self._save_incident_to_db(existing_non_sim)
            return existing_non_sim

        # Rule-based clustering for non-simulation events
        non_sim_buffer = [e for e in self._events_buffer if not e.scenario_id]

        # Rule: Brute Force / Credential Abuse
        if event.event_type in ("BRUTE_FORCE", "LOGIN_FAILURE"):
            matching_events = [
                e for e in non_sim_buffer
                if e.source_ip == event.source_ip and e.event_type in ("LOGIN_FAILURE", "BRUTE_FORCE", "SUSPICIOUS_LOGIN")
            ]
            if len(matching_events) >= 3:
                self._incident_counter += 1
                inc_id = f"INC-{self._incident_counter}"
                t1110 = get_technique("T1110")
                t1078 = get_technique("T1078")
                new_inc = Incident(
                    incident_id=inc_id,
                    id=inc_id,
                    scenario_id=None,
                    title=f"Credential Spray & Brute Force on {event.target}",
                    severity="CRITICAL" if any(e.severity.upper() == "CRITICAL" for e in matching_events) else "HIGH",
                    status="OPEN",
                    confidence=0.95,
                    category="Credential Access",
                    source_ip=event.source_ip,
                    target=event.target,
                    source_ips=[event.source_ip],
                    affected_targets=[event.target],
                    attack_stage=stage,
                    first_seen=matching_events[0].timestamp if matching_events else now_str,
                    last_seen=now_str,
                    event_ids=[e.event_id for e in matching_events],
                    events_count=len(matching_events),
                    techniques=[t for t in (t1110, t1078) if t is not None],
                    related_cves=[],
                    created_at=now_str,
                    updated_at=now_str,
                    summary=f"Detected multiple successive failed login attempts followed by credential brute force pattern from {event.source_ip} against {event.target}.",
                    recommended_actions=[
                        f"Enforce immediate IP block on firewall for {event.source_ip}.",
                        "Verify multi-factor authentication (MFA) status on affected service accounts.",
                        "Audit SSH/RDP session authorization tables for successful logins from this IP.",
                        "Lock targeted accounts temporarily and initiate credential resets."
                    ]
                )
                self._incidents[inc_id] = new_inc
                self._save_incident_to_db(new_inc)
                logger.info(f"Correlated non-simulation incident: {inc_id} - {new_inc.title}")
                return new_inc

        # Rule: Web Exploit / Vulnerability Chain
        if event.event_type in ("EXPLOIT_ATTEMPT", "SQL_INJECTION", "MALWARE_ALERT", "VULNERABILITY_SCAN"):
            matching_events = [
                e for e in non_sim_buffer
                if e.target == event.target and e.event_type in ("PORT_SCAN", "SERVICE_ENUMERATION", "VULNERABILITY_SCAN", "SQL_INJECTION", "EXPLOIT_ATTEMPT", "MALWARE_ALERT")
            ]
            if len(matching_events) >= 2 or event.event_type in ("EXPLOIT_ATTEMPT", "MALWARE_ALERT"):
                self._incident_counter += 1
                inc_id = f"INC-{self._incident_counter}"
                t1190 = get_technique("T1190")
                t1059 = get_technique("T1059.001")
                new_inc = Incident(
                    incident_id=inc_id,
                    id=inc_id,
                    scenario_id=None,
                    title=f"Web Application Vulnerability Exploitation on {event.target}",
                    severity="CRITICAL",
                    status="OPEN",
                    confidence=0.94,
                    category="Initial Access",
                    source_ip=event.source_ip,
                    target=event.target,
                    source_ips=[event.source_ip],
                    affected_targets=[event.target],
                    attack_stage=stage,
                    first_seen=matching_events[0].timestamp if matching_events else now_str,
                    last_seen=now_str,
                    event_ids=[e.event_id for e in matching_events] or [event.event_id],
                    events_count=len(matching_events) if matching_events else 1,
                    techniques=[t for t in (t1190, t1059) if t is not None],
                    related_cves=["CVE-2023-34362", "CVE-2024-3400"],
                    created_at=now_str,
                    updated_at=now_str,
                    summary=f"Multi-stage intrusion chain: Web vulnerability probing and remote code execution payload executed against {event.target}.",
                    recommended_actions=[
                        f"Isolate host {event.target} from sensitive VLAN segments.",
                        "Inspect web application access logs for anomalous POST payloads and file uploads.",
                        "Scan web directories (/var/www/uploads/) for dropped webshells or backdoor scripts.",
                        "Apply vendor emergency security patch immediately."
                    ]
                )
                self._incidents[inc_id] = new_inc
                self._save_incident_to_db(new_inc)
                return new_inc

        # Rule: PowerShell / Defense Evasion / Privilege Escalation
        if event.event_type in ("POWERSHELL_EXECUTION", "DEFENSE_EVASION", "PROCESS_INJECTION", "PRIVILEGE_ESCALATION"):
            matching_events = [
                e for e in non_sim_buffer
                if (e.source_ip == event.source_ip or e.target == event.target) and e.event_type in ("POWERSHELL_EXECUTION", "DEFENSE_EVASION", "PROCESS_INJECTION", "PRIVILEGE_ESCALATION")
            ]
            self._incident_counter += 1
            inc_id = f"INC-{self._incident_counter}"
            t1059 = get_technique("T1059.001")
            t1055 = get_technique("T1055")
            t1562 = get_technique("T1562.001")
            t1068 = get_technique("T1068")
            new_inc = Incident(
                incident_id=inc_id,
                id=inc_id,
                scenario_id=None,
                title=f"Suspicious PowerShell Execution & Privilege Escalation on {event.target}",
                severity="CRITICAL",
                status="OPEN",
                confidence=0.95,
                category="Execution",
                source_ip=event.source_ip,
                target=event.target,
                source_ips=[event.source_ip],
                affected_targets=[event.target],
                attack_stage=stage,
                first_seen=matching_events[0].timestamp if matching_events else now_str,
                last_seen=now_str,
                event_ids=[e.event_id for e in matching_events] or [event.event_id],
                events_count=len(matching_events) if matching_events else 1,
                techniques=[t for t in (t1059, t1055, t1562, t1068) if t is not None],
                related_cves=[],
                created_at=now_str,
                updated_at=now_str,
                summary=f"Obfuscated PowerShell cradle, defense evasion (AV tampering), and process injection detected on {event.target}.",
                recommended_actions=[
                    f"Terminate malicious PowerShell processes on {event.target}.",
                    "Re-enable Windows Defender real-time protection and verify antivirus definitions.",
                    "Capture memory dump of injected svchost process for forensic triage.",
                    "Revoke elevated tokens and audit local administrator group membership."
                ]
            )
            self._incidents[inc_id] = new_inc
            self._save_incident_to_db(new_inc)
            return new_inc

        # Rule: Ransomware / Lateral Movement Chain
        if event.event_type in ("RANSOMWARE_ACTIVITY", "SHADOW_COPY_DELETION", "LATERAL_MOVEMENT"):
            matching_events = [
                e for e in non_sim_buffer
                if (e.source_ip == event.source_ip or e.target == event.target) and e.event_type in ("SUSPICIOUS_LOGIN", "LATERAL_MOVEMENT", "SHADOW_COPY_DELETION", "RANSOMWARE_ACTIVITY")
            ]
            self._incident_counter += 1
            inc_id = f"INC-{self._incident_counter}"
            t1486 = get_technique("T1486")
            t1490 = get_technique("T1490")
            t1021 = get_technique("T1021.002")
            new_inc = Incident(
                incident_id=inc_id,
                id=inc_id,
                scenario_id=None,
                title=f"Critical Ransomware & Lateral Movement Activity on {event.target}",
                severity="CRITICAL",
                status="OPEN",
                confidence=0.98,
                category="Impact",
                source_ip=event.source_ip,
                target=event.target,
                source_ips=[event.source_ip],
                affected_targets=[event.target],
                attack_stage=stage,
                first_seen=matching_events[0].timestamp if matching_events else now_str,
                last_seen=now_str,
                event_ids=[e.event_id for e in matching_events] or [event.event_id],
                events_count=len(matching_events) if matching_events else 1,
                techniques=[t for t in (t1486, t1490, t1021) if t is not None],
                related_cves=[],
                created_at=now_str,
                updated_at=now_str,
                summary=f"Rapid file encryption patterns, volume shadow copy deletion, and lateral SMB traversal observed from {event.source_ip} on {event.target}.",
                recommended_actions=[
                    "Sever network link immediately to halt encryption propagation across network shares.",
                    "Verify offline backup repository integrity and snapshot air-gapping.",
                    "Revoke domain administrative credentials and force kerberos ticket resets.",
                    "Initiate incident response disaster recovery and forensic containment protocol."
                ]
            )
            self._incidents[inc_id] = new_inc
            self._save_incident_to_db(new_inc)
            return new_inc

        # Rule: Data Exfiltration Chain
        if event.event_type in ("DATA_EXFILTRATION", "DATA_STAGING", "OUTBOUND_TRANSFER"):
            matching_events = [
                e for e in non_sim_buffer
                if (e.source_ip == event.source_ip or e.target == event.target) and e.event_type in ("LOGIN_FAILURE", "SUSPICIOUS_LOGIN", "DATA_STAGING", "DATA_EXFILTRATION", "OUTBOUND_TRANSFER")
            ]
            self._incident_counter += 1
            inc_id = f"INC-{self._incident_counter}"
            t1041 = get_technique("T1041")
            t1005 = get_technique("T1005")
            t1048 = get_technique("T1048")
            new_inc = Incident(
                incident_id=inc_id,
                id=inc_id,
                scenario_id=None,
                title=f"Unauthorized Database Compromise & Exfiltration on {event.target}",
                severity="CRITICAL",
                status="OPEN",
                confidence=0.96,
                category="Exfiltration",
                source_ip=event.source_ip,
                target=event.target,
                source_ips=[event.source_ip],
                affected_targets=[event.target],
                attack_stage=stage,
                first_seen=matching_events[0].timestamp if matching_events else now_str,
                last_seen=now_str,
                event_ids=[e.event_id for e in matching_events] or [event.event_id],
                events_count=len(matching_events) if matching_events else 1,
                techniques=[t for t in (t1041, t1005, t1048) if t is not None],
                related_cves=[],
                created_at=now_str,
                updated_at=now_str,
                summary=f"High-volume database extraction and encrypted staging transfer detected originating from non-whitelisted host {event.source_ip} on {event.target}.",
                recommended_actions=[
                    "Terminate active database connections immediately and rotate service credentials.",
                    "Inspect SQL query logs for executed COPY or SELECT INTO statements.",
                    "Verify perimeter firewall and DLP blocking rules for external destination IP.",
                    "Perform forensic review of staged archive files on disk."
                ]
            )
            self._incidents[inc_id] = new_inc
            self._save_incident_to_db(new_inc)
            return new_inc

        return None

    def get_incidents(
        self,
        status: Optional[str] = None,
        severity: Optional[str] = None,
        search: Optional[str] = None
    ) -> List[Incident]:
        """Retrieve incidents list with optional status/severity/search filtering."""
        incidents = list(self._incidents.values())

        if status:
            incidents = [i for i in incidents if i.status.upper() == status.upper()]

        if severity:
            incidents = [i for i in incidents if i.severity.upper() == severity.upper()]

        if search:
            s = search.lower()
            incidents = [
                i for i in incidents
                if s in i.title.lower()
                or s in i.incident_id.lower()
                or s in i.source_ip.lower()
                or s in i.target.lower()
                or s in i.summary.lower()
            ]

        return sorted(incidents, key=lambda x: x.updated_at, reverse=True)

    def get_incident_by_id(self, incident_id: str) -> Optional[Incident]:
        if incident_id in self._incidents:
            return self._incidents[incident_id]

        try:
            with self._get_db_conn() as conn:
                row = conn.execute("SELECT * FROM incidents WHERE incident_id = ?", (incident_id,)).fetchone()
                if row:
                    techniques_data = json.loads(row["techniques"]) if row["techniques"] else []
                    techniques = [MitreTechnique(**t) for t in techniques_data]
                    ai_analysis = json.loads(row["ai_analysis"]) if row["ai_analysis"] else None
                    source_ips = json.loads(row["source_ips"]) if "source_ips" in row.keys() and row["source_ips"] else [row["source_ip"]]
                    affected_targets = json.loads(row["affected_targets"]) if "affected_targets" in row.keys() and row["affected_targets"] else [row["target"]]
                    attack_stage = row["attack_stage"] if "attack_stage" in row.keys() and row["attack_stage"] else "Initial Access"
                    first_seen = row["first_seen"] if "first_seen" in row.keys() and row["first_seen"] else row["created_at"]
                    last_seen = row["last_seen"] if "last_seen" in row.keys() and row["last_seen"] else row["updated_at"]
                    scenario_id = row["scenario_id"] if "scenario_id" in row.keys() and row["scenario_id"] else None
                    risk = row["risk"] if "risk" in row.keys() and row["risk"] else None
                    risk_score = row["risk_score"] if "risk_score" in row.keys() and row["risk_score"] is not None else None

                    inc = Incident(
                        incident_id=row["incident_id"],
                        id=row["incident_id"],
                        scenario_id=scenario_id,
                        title=row["title"],
                        severity=row["severity"],
                        status=row["status"],
                        confidence=row["confidence"],
                        risk=risk,
                        risk_score=risk_score,
                        category=row["category"],
                        source_ip=row["source_ip"],
                        target=row["target"],
                        source_ips=source_ips,
                        affected_targets=affected_targets,
                        attack_stage=attack_stage,
                        first_seen=first_seen,
                        last_seen=last_seen,
                        event_ids=json.loads(row["event_ids"]),
                        events_count=row["events_count"],
                        techniques=techniques,
                        related_cves=json.loads(row["related_cves"]),
                        created_at=row["created_at"],
                        updated_at=row["updated_at"],
                        summary=row["summary"],
                        recommended_actions=json.loads(row["recommended_actions"]),
                        ai_analysis=ai_analysis
                    )
                    self._incidents[inc.incident_id] = inc
                    return inc
        except Exception as e:
            logger.warning(f"Error querying incident {incident_id} from SQLite: {e}")

        return None

    def update_incident_status(self, incident_id: str, new_status: str) -> Optional[Incident]:
        """Update incident lifecycle status (OPEN, INVESTIGATING, CONTAINED, RESOLVED)."""
        valid_statuses = ("OPEN", "INVESTIGATING", "CONTAINED", "RESOLVED")
        normalized = new_status.upper()
        if normalized not in valid_statuses:
            return None

        inc = self.get_incident_by_id(incident_id)
        if not inc:
            return None

        inc.status = normalized
        inc.updated_at = datetime.now(timezone.utc).isoformat()
        self._save_incident_to_db(inc)
        return inc

    def get_recent_events(self, limit: int = 50) -> List[SecurityEvent]:
        return list(reversed(self._events_buffer[-limit:]))


# Global singleton
correlation_engine = CorrelationEngine()
