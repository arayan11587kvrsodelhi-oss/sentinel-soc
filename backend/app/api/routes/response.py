from fastapi import APIRouter, HTTPException, Query
from typing import List, Dict, Any, Optional
from app.services.response_service import response_service, SimulatedActionRequest, SimulatedActionRecord
from app.services.correlation_service import correlation_engine
from app.services.mitre_service import MITRE_TECHNIQUES
from app.services.simulation_service import SCENARIOS

router = APIRouter()


@router.post("/response/simulate-action", response_model=SimulatedActionRecord)
async def simulate_response_action(payload: SimulatedActionRequest):
    """
    Executes a simulated SOC containment action (IP_BAN, FIREWALL_BLOCK, CREDENTIAL_REVOCATION, HOST_ISOLATION).
    Strictly simulated, auditable, and safe.
    """
    try:
        record = response_service.execute_simulated_action(payload)
        return record
    except Exception as exc:
        raise HTTPException(status_code=500, detail=f"Failed to execute simulated action: {str(exc)}")


@router.get("/response/audit-log", response_model=List[SimulatedActionRecord])
async def get_response_audit_log(limit: int = Query(50, ge=1, le=100)):
    """Retrieve history of executed simulated response actions."""
    return response_service.get_audit_log(limit=limit)


@router.get("/mitre/matrix", response_model=List[Dict[str, Any]])
async def get_mitre_attack_matrix():
    """
    Returns full MITRE ATT&CK Matrix coverage with observed vs simulated vs not observed status,
    correlated incidents, and event counts.
    """
    incidents = correlation_engine.get_incidents()
    events = correlation_engine.get_recent_events(limit=250)

    # Collect observed technique IDs and incident mappings
    tech_incidents: Dict[str, List[str]] = {}
    tech_events_count: Dict[str, int] = {}

    for inc in incidents:
        for t in inc.techniques:
            if t.id not in tech_incidents:
                tech_incidents[t.id] = []
            if inc.incident_id not in tech_incidents[t.id]:
                tech_incidents[t.id].append(inc.incident_id)

    for ev in events:
        if ev.mitre_technique and ev.mitre_technique.id:
            tid = ev.mitre_technique.id
            tech_events_count[tid] = tech_events_count.get(tid, 0) + 1

    # Catalog simulated techniques
    simulated_tids = set()
    for scen in SCENARIOS:
        for step in scen.get("steps", []):
            from app.services.mitre_service import EVENT_TYPE_TO_MITRE
            mt = EVENT_TYPE_TO_MITRE.get(step.get("event_type", "").upper())
            if mt:
                simulated_tids.add(mt)

    matrix = []
    for tid, tech in MITRE_TECHNIQUES.items():
        is_observed = tid in tech_incidents or (tech_events_count.get(tid, 0) > 0)
        is_simulated = tid in simulated_tids

        status = "OBSERVED" if is_observed else ("SIMULATED" if is_simulated else "NOT_OBSERVED")

        matrix.append({
            "id": tech.id,
            "name": tech.name,
            "tactic": tech.tactic,
            "description": tech.description,
            "url": tech.url,
            "status": status,
            "incidents_count": len(tech_incidents.get(tid, [])),
            "events_count": tech_events_count.get(tid, 0),
            "related_incident_ids": tech_incidents.get(tid, [])
        })

    return matrix
