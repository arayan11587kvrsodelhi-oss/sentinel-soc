"""
SentinelSOC Automated Response & Playbook Simulation Service
Executes purely simulated containment actions (IP Ban, Firewall Block, Credential Revocation, Host Isolation).
All actions are strictly simulated, auditable, and safe. Zero real-world infrastructure modification.
"""
import os
import json
import sqlite3
import logging
import uuid
from datetime import datetime, timezone
from typing import Dict, Any, List, Optional
from pydantic import BaseModel, Field

logger = logging.getLogger("sentinel.response")
DB_PATH = os.getenv("SQLITE_DB_PATH", os.path.join(os.path.dirname(__file__), "..", "..", "sentinel.db"))


class SimulatedActionRequest(BaseModel):
    action_type: str  # IP_BAN, FIREWALL_BLOCK, CREDENTIAL_REVOCATION, HOST_ISOLATION
    target: str
    incident_id: Optional[str] = None
    reason: Optional[str] = "Automated AI Analyst containment recommendation"
    triggered_by: Optional[str] = "Sentinel AI Copilot"


class SimulatedActionRecord(BaseModel):
    action_id: str
    action_type: str
    action_label: str
    target: str
    incident_id: Optional[str] = None
    timestamp: str
    triggered_by: str
    reason: str
    status: str = "SIMULATED SUCCESS"
    details: str
    simulation: bool = True


class ResponseService:
    def __init__(self):
        self._audit_log: List[SimulatedActionRecord] = []
        self._init_sqlite()
        self._load_audit_log()

    def _get_db_conn(self) -> sqlite3.Connection:
        conn = sqlite3.connect(DB_PATH)
        conn.row_factory = sqlite3.Row
        return conn

    def _init_sqlite(self):
        """Create response_actions table if it does not exist."""
        try:
            with self._get_db_conn() as conn:
                conn.execute("""
                    CREATE TABLE IF NOT EXISTS response_actions (
                        action_id TEXT PRIMARY KEY,
                        action_type TEXT NOT NULL,
                        action_label TEXT NOT NULL,
                        target TEXT NOT NULL,
                        incident_id TEXT,
                        timestamp TEXT NOT NULL,
                        triggered_by TEXT NOT NULL,
                        reason TEXT NOT NULL,
                        status TEXT NOT NULL,
                        details TEXT NOT NULL,
                        simulation INTEGER NOT NULL DEFAULT 1
                    )
                """)
                conn.commit()
        except Exception as e:
            logger.warning(f"Could not initialize response_actions SQLite table: {e}")

    def _load_audit_log(self):
        try:
            with self._get_db_conn() as conn:
                rows = conn.execute("SELECT * FROM response_actions ORDER BY timestamp DESC LIMIT 100").fetchall()
                for r in rows:
                    rec = SimulatedActionRecord(
                        action_id=r["action_id"],
                        action_type=r["action_type"],
                        action_label=r["action_label"],
                        target=r["target"],
                        incident_id=r["incident_id"],
                        timestamp=r["timestamp"],
                        triggered_by=r["triggered_by"],
                        reason=r["reason"],
                        status=r["status"],
                        details=r["details"],
                        simulation=bool(r["simulation"])
                    )
                    self._audit_log.append(rec)
        except Exception as e:
            logger.warning(f"Error loading response audit logs: {e}")

    def execute_simulated_action(self, req: SimulatedActionRequest) -> SimulatedActionRecord:
        """Executes a strictly simulated response action and writes to audit log."""
        action_type = req.action_type.upper().strip()
        action_id = f"ACT-{uuid.uuid4().hex[:8].upper()}"
        now_ts = datetime.now(timezone.utc).isoformat()

        if action_type in ("IP_BAN", "SIMULATE IP BAN"):
            label = "[ SIMULATE IP BAN ]"
            details = f"Simulated boundary gateway drop rule active for attacker IP {req.target}. Inbound and outbound packets blocked."
        elif action_type in ("FIREWALL_BLOCK", "SIMULATE FIREWALL BLOCK"):
            label = "[ SIMULATE FIREWALL BLOCK ]"
            details = f"Simulated perimeter firewall access control list updated to reject traffic to/from {req.target} on all ports."
        elif action_type in ("CREDENTIAL_REVOCATION", "SIMULATE CREDENTIAL REVOCATION"):
            label = "[ SIMULATE CREDENTIAL REVOCATION ]"
            details = f"Simulated active Kerberos/OAuth session tokens terminated and password reset enforced for identity {req.target}."
        elif action_type in ("HOST_ISOLATION", "SIMULATE HOST ISOLATION"):
            label = "[ SIMULATE HOST ISOLATION ]"
            details = f"Simulated EDR network containment active on asset {req.target}. Only SOC management telemetry allowed."
        else:
            label = f"[ SIMULATE {action_type} ]"
            details = f"Simulated containment policy applied to target {req.target}."

        record = SimulatedActionRecord(
            action_id=action_id,
            action_type=action_type,
            action_label=label,
            target=req.target,
            incident_id=req.incident_id,
            timestamp=now_ts,
            triggered_by=req.triggered_by or "Sentinel AI Copilot",
            reason=req.reason or "Defensive containment recommendation",
            status="SIMULATED SUCCESS",
            details=details,
            simulation=True
        )

        try:
            with self._get_db_conn() as conn:
                conn.execute("""
                    INSERT INTO response_actions (
                        action_id, action_type, action_label, target, incident_id,
                        timestamp, triggered_by, reason, status, details, simulation
                    ) VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)
                """, (
                    record.action_id, record.action_type, record.action_label, record.target,
                    record.incident_id, record.timestamp, record.triggered_by, record.reason,
                    record.status, record.details, 1
                ))
                conn.commit()
        except Exception as e:
            logger.warning(f"Error persisting response action: {e}")

        self._audit_log.insert(0, record)
        logger.info(f"Executed simulated action: {record.action_label} on {record.target} (ID: {record.action_id})")
        return record

    def get_audit_log(self, limit: int = 50) -> List[SimulatedActionRecord]:
        return self._audit_log[:limit]


# Global singleton
response_service = ResponseService()
