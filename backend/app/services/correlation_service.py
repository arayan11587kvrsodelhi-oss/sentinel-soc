"""
SentinelSOC Correlation Engine & Incident Management Service
Correlates real-time security events into contextual incidents, mapping to MITRE ATT&CK techniques.
Persists incident state lightweight in SQLite so changes survive server restarts.
"""
import os
import json
import sqlite3
import logging
from datetime import datetime, timezone
from typing import Dict, Any, List, Optional
from app.models.schemas import SecurityEvent, Incident, MitreTechnique
from app.services.mitre_service import get_technique

logger = logging.getLogger("sentinel.correlation")

DB_PATH = os.getenv("SQLITE_DB_PATH", os.path.join(os.path.dirname(__file__), "..", "..", "sentinel.db"))


class CorrelationEngine:
    def __init__(self):
        self._events_buffer: List[SecurityEvent] = []
        self._incidents: Dict[str, Incident] = {}
        self._incident_counter = 100
        self._init_sqlite()
        self._load_or_seed_incidents()

    def _get_db_conn(self) -> sqlite3.Connection:
        conn = sqlite3.connect(DB_PATH)
        conn.row_factory = sqlite3.Row
        return conn

    def _init_sqlite(self):
        """Create incidents table if it does not exist."""
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
                        ai_analysis TEXT
                    )
                """)
                conn.commit()
        except Exception as e:
            logger.warning(f"Could not initialize SQLite incident table: {e}")

    def _save_incident_to_db(self, inc: Incident):
        try:
            with self._get_db_conn() as conn:
                conn.execute("""
                    INSERT INTO incidents (
                        incident_id, title, severity, status, confidence, category,
                        source_ip, target, event_ids, events_count, techniques,
                        related_cves, created_at, updated_at, summary,
                        recommended_actions, ai_analysis
                    ) VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)
                    ON CONFLICT(incident_id) DO UPDATE SET
                        status=excluded.status,
                        confidence=excluded.confidence,
                        event_ids=excluded.event_ids,
                        events_count=excluded.events_count,
                        updated_at=excluded.updated_at,
                        ai_analysis=excluded.ai_analysis
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
                    json.dumps(inc.ai_analysis) if inc.ai_analysis else None
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

                        inc = Incident(
                            incident_id=row["incident_id"],
                            id=row["incident_id"],
                            title=row["title"],
                            severity=row["severity"],
                            status=row["status"],
                            confidence=row["confidence"],
                            category=row["category"],
                            source_ip=row["source_ip"],
                            target=row["target"],
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
        t1190 = get_technique("T1190")

        inc1 = Incident(
            incident_id="INC-101",
            id="INC-101",
            title="SSH Credential Brute Force Attack",
            severity="CRITICAL",
            status="OPEN",
            confidence=0.94,
            category="Credential Access",
            source_ip="192.168.1.105",
            target="auth-gateway.corp.internal",
            event_ids=["SIM-1001", "SIM-1002", "SIM-1003", "SIM-1004"],
            events_count=4,
            techniques=[t1110] if t1110 else [],
            related_cves=[],
            created_at=now,
            updated_at=now,
            summary="Rapid successive authentication failures detected against auth-gateway followed by brute force threshold violation.",
            recommended_actions=[
                "Apply immediate firewall drop rule for source IP 192.168.1.105.",
                "Verify MFA status on targeted accounts (root, administrator, svc_backup).",
                "Audit SSH authorization logs for any subsequent successful sessions.",
                "Review credential rotation policies."
            ]
        )

        inc2 = Incident(
            incident_id="INC-102",
            id="INC-102",
            title="Public Web Application Exploit Attempt (MOVEit / SQLi)",
            severity="HIGH",
            status="INVESTIGATING",
            confidence=0.88,
            category="Initial Access",
            source_ip="10.0.4.15",
            target="dmz-web-portal.corp.internal",
            event_ids=["SIM-1005", "SIM-1006", "SIM-1007"],
            events_count=3,
            techniques=[t1190] if t1190 else [],
            related_cves=["CVE-2023-34362"],
            created_at=now,
            updated_at=now,
            summary="Automated URI scanning followed by SQL injection payloads targeting DMZ web portal endpoints.",
            recommended_actions=[
                "Enable WAF SQL injection blocking rules on reverse proxy.",
                "Inspect web application error logs for SQL syntax exceptions.",
                "Verify database query parameterization and ORM sanitization.",
                "Check for unauthorized file writes in /var/www/uploads/ directory."
            ]
        )

        self._incidents[inc1.incident_id] = inc1
        self._incidents[inc2.incident_id] = inc2
        self._save_incident_to_db(inc1)
        self._save_incident_to_db(inc2)

    def process_event(self, event: SecurityEvent) -> Optional[Incident]:
        """Ingest a security event, add to sliding window, and run correlation rules."""
        self._events_buffer.append(event)
        if len(self._events_buffer) > 200:
            self._events_buffer = self._events_buffer[-200:]

        now_str = datetime.now(timezone.utc).isoformat()

        # Rule 1: Brute Force Correlation
        if event.event_type in ("BRUTE_FORCE", "LOGIN_FAILURE"):
            matching_events = [
                e for e in self._events_buffer
                if e.source_ip == event.source_ip and e.event_type in ("LOGIN_FAILURE", "BRUTE_FORCE", "SUSPICIOUS_LOGIN")
            ]
            if len(matching_events) >= 3:
                existing_inc = next((
                    inc for inc in self._incidents.values()
                    if inc.source_ip == event.source_ip and inc.status in ("OPEN", "INVESTIGATING")
                    and "Brute Force" in inc.title
                ), None)

                if existing_inc:
                    if event.event_id not in existing_inc.event_ids:
                        existing_inc.event_ids.append(event.event_id)
                        existing_inc.events_count = len(existing_inc.event_ids)
                        existing_inc.updated_at = now_str
                        self._save_incident_to_db(existing_inc)
                    return existing_inc
                else:
                    self._incident_counter += 1
                    inc_id = f"INC-{self._incident_counter}"
                    t1110 = get_technique("T1110")
                    new_inc = Incident(
                        incident_id=inc_id,
                        id=inc_id,
                        title=f"Credential Attack & Brute Force on {event.target}",
                        severity="CRITICAL",
                        status="OPEN",
                        confidence=0.95,
                        category="Credential Access",
                        source_ip=event.source_ip,
                        target=event.target,
                        event_ids=[e.event_id for e in matching_events],
                        events_count=len(matching_events),
                        techniques=[t1110] if t1110 else [],
                        related_cves=[],
                        created_at=now_str,
                        updated_at=now_str,
                        summary=f"Detected multiple failed login attempts followed by brute force pattern from {event.source_ip}.",
                        recommended_actions=[
                            f"Block source IP {event.source_ip} on boundary firewall.",
                            "Review successful logins from this IP.",
                            "Enforce MFA across target services.",
                            "Lock compromised user accounts temporarily."
                        ]
                    )
                    self._incidents[inc_id] = new_inc
                    self._save_incident_to_db(new_inc)
                    logger.info(f"Correlated new incident: {inc_id} - {new_inc.title}")
                    return new_inc


        # Rule 2: Web Exploit / Vulnerability Chain
        if event.event_type in ("EXPLOIT_ATTEMPT", "SQL_INJECTION", "MALWARE_ALERT"):
            matching_events = [
                e for e in self._events_buffer
                if e.target == event.target and e.event_type in ("PORT_SCAN", "SERVICE_ENUMERATION", "SQL_INJECTION", "EXPLOIT_ATTEMPT", "MALWARE_ALERT")
            ]
            if len(matching_events) >= 2:
                existing_inc = next((
                    inc for inc in self._incidents.values()
                    if inc.target == event.target and inc.status in ("OPEN", "INVESTIGATING")
                    and "Exploit" in inc.title
                ), None)

                if existing_inc:
                    if event.event_id not in existing_inc.event_ids:
                        existing_inc.event_ids.append(event.event_id)
                        existing_inc.events_count = len(existing_inc.event_ids)
                        existing_inc.updated_at = now_str
                        self._save_incident_to_db(existing_inc)
                    return existing_inc
                else:
                    self._incident_counter += 1
                    inc_id = f"INC-{self._incident_counter}"
                    t1190 = get_technique("T1190")
                    new_inc = Incident(
                        incident_id=inc_id,
                        id=inc_id,
                        title=f"Web Application Exploit & Compromise on {event.target}",
                        severity="CRITICAL",
                        status="OPEN",
                        confidence=0.92,
                        category="Initial Access",
                        source_ip=event.source_ip,
                        target=event.target,
                        event_ids=[e.event_id for e in matching_events],
                        events_count=len(matching_events),
                        techniques=[t1190] if t1190 else [],
                        related_cves=["CVE-2023-34362", "CVE-2024-3400"],
                        created_at=now_str,
                        updated_at=now_str,
                        summary=f"Multi-stage intrusion chain: Port scanning, vulnerability enumeration, and exploit payloads executed against {event.target}.",
                        recommended_actions=[
                            f"Isolate host {event.target} from network segment.",
                            "Inspect web server access logs for anomalous POST payloads.",
                            "Scan filesystem for dropped web shells or backdoor scripts.",
                            "Apply vendor emergency patch."
                        ]
                    )
                    self._incidents[inc_id] = new_inc
                    self._save_incident_to_db(new_inc)
                    return new_inc

        # Rule 3: Ransomware / Privilege Escalation Chain
        if event.event_type in ("RANSOMWARE_ACTIVITY", "PRIVILEGE_ESCALATION"):
            matching_events = [
                e for e in self._events_buffer
                if e.source_ip == event.source_ip and e.event_type in ("SUSPICIOUS_LOGIN", "PRIVILEGE_ESCALATION", "C2_COMMUNICATION", "RANSOMWARE_ACTIVITY")
            ]
            self._incident_counter += 1
            inc_id = f"INC-{self._incident_counter}"
            t1486 = get_technique("T1486")
            t1003 = get_technique("T1003")
            techniques = [t for t in (t1486, t1003) if t is not None]

            new_inc = Incident(
                incident_id=inc_id,
                id=inc_id,
                title=f"Critical Ransomware / Data Destruction Activity on {event.target}",
                severity="CRITICAL",
                status="OPEN",
                confidence=0.98,
                category="Impact",
                source_ip=event.source_ip,
                target=event.target,
                event_ids=[e.event_id for e in matching_events] or [event.event_id],
                events_count=len(matching_events) if matching_events else 1,
                techniques=techniques,
                related_cves=[],
                created_at=now_str,
                updated_at=now_str,
                summary=f"Rapid encryption and privileged process manipulation observed from {event.source_ip} on {event.target}.",
                recommended_actions=[
                    "Sever network link immediately to stop encryption propagation.",
                    "Verify offline backup repository integrity.",
                    "Revoke domain-level administrative credentials.",
                    "Initiate business continuity and forensic containment procedures."
                ]
            )
            self._incidents[inc_id] = new_inc
            self._save_incident_to_db(new_inc)
            return new_inc

        # Rule 4: Data Exfiltration Chain
        if event.event_type in ("DATA_EXFILTRATION",):
            matching_events = [
                e for e in self._events_buffer
                if e.source_ip == event.source_ip and e.event_type in ("LOGIN_FAILURE", "SUSPICIOUS_LOGIN", "DATA_EXFILTRATION")
            ]
            self._incident_counter += 1
            inc_id = f"INC-{self._incident_counter}"
            t1041 = get_technique("T1041")
            techniques = [t1041] if t1041 else []

            new_inc = Incident(
                incident_id=inc_id,
                id=inc_id,
                title=f"Database Exfiltration Anomaly on {event.target}",
                severity="CRITICAL",
                status="OPEN",
                confidence=0.93,
                category="Exfiltration",
                source_ip=event.source_ip,
                target=event.target,
                event_ids=[e.event_id for e in matching_events] or [event.event_id],
                events_count=len(matching_events) if matching_events else 1,
                techniques=techniques,
                related_cves=[],
                created_at=now_str,
                updated_at=now_str,
                summary=f"High-volume unauthorized data transfer detected originating from non-whitelisted host {event.source_ip} on {event.target}.",
                recommended_actions=[
                    "Terminate active database connections immediately.",
                    "Inspect database query logs for table exfiltration dumps.",
                    "Rotate master database service credentials.",
                    "Check perimeter DLP alerts for external destination IP."
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
        return self._incidents.get(incident_id)

    def update_incident_status(self, incident_id: str, new_status: str) -> Optional[Incident]:
        """Update incident lifecycle status (OPEN, INVESTIGATING, CONTAINED, RESOLVED)."""
        valid_statuses = ("OPEN", "INVESTIGATING", "CONTAINED", "RESOLVED")
        normalized = new_status.upper()
        if normalized not in valid_statuses:
            return None

        inc = self._incidents.get(incident_id)
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
