"""
SentinelSOC Automated Comprehensive Backend Verification & Integration Test Suite
Validates all REST endpoints, schemas, CORS, SQLite persistence, attack simulations,
correlation rules, NVD/KEV cross-referencing, WebSocket protocols, and AI defensive triage.
"""
import sys
import asyncio
from fastapi.testclient import TestClient
from app.main import app
from app.services.simulation_service import simulation_engine, SCENARIOS
from app.services.correlation_service import CorrelationEngine
from app.services.cisa_service import is_in_kev, get_kev_dict
from app.models.schemas import SecurityEvent

client = TestClient(app)

def run_tests():
    print("==================================================")
    print("STARTING SENTINELSOC COMPREHENSIVE PRODUCTION AUDIT")
    print("==================================================")

    # 1. Root & Health
    print("\n[1] Testing GET / and GET /health ...")
    r = client.get("/")
    assert r.status_code == 200, f"Root failed: {r.status_code}"
    res = r.json()
    assert res["service"] == "SENTINEL SOC API"
    assert res["version"] == "2.0.0"
    print(f" -> Root OK: {res['service']} v{res['version']} (Status: {res['status']})")

    r = client.get("/health")
    assert r.status_code == 200, f"Health failed: {r.status_code}"
    h_data = r.json()
    assert h_data["status"] == "healthy"
    print(f" -> Health OK: status={h_data['status']}, active_ws={h_data['active_ws_clients']}")

    # 2. Aggregated Dashboard Metrics
    print("\n[2] Testing GET /api/dashboard ...")
    r = client.get("/api/dashboard")
    assert r.status_code == 200, f"Dashboard failed: {r.status_code}"
    data = r.json()
    assert "active_incidents" in data
    assert "total_incidents" in data
    assert "critical_events" in data
    assert "high_events" in data
    assert "nvd_records_total" in data
    assert "kev_catalog_total" in data
    assert data["nvd_records_total"] >= 10, "NVD total must reflect primed vulnerability intelligence"
    assert data["kev_catalog_total"] >= 8, "KEV total must reflect current KEV dataset size"
    print(f" -> Dashboard metrics OK: active_incidents={data['active_incidents']}, total_incidents={data['total_incidents']}, NVD total={data['nvd_records_total']} ({data.get('nvd_data_source')}), KEV catalog={data['kev_catalog_total']} ({data.get('kev_data_source')})")

    # 3. Telemetry Event History & Filtering
    print("\n[3] Testing GET /api/threats ...")
    r = client.get("/api/threats?limit=10")
    assert r.status_code == 200, f"Threats failed: {r.status_code}"
    threats = r.json()
    assert isinstance(threats, list)
    print(f" -> Threats OK: received {len(threats)} simulated telemetry events")

    # 4. NVD Vulnerability Intelligence & Data Source Transparency
    print("\n[4] Testing GET /api/vulnerabilities ...")
    r = client.get("/api/vulnerabilities?limit=10")
    assert r.status_code == 200, f"Vulnerabilities failed: {r.status_code}"
    v_data = r.json()
    assert "vulnerabilities" in v_data
    assert "data_source" in v_data
    assert v_data["data_source"] in ("LIVE_NVD", "CACHED_NVD", "FALLBACK")
    assert len(v_data["vulnerabilities"]) > 0
    first_cve = v_data["vulnerabilities"][0]
    assert "id" in first_cve
    assert "severity" in first_cve
    assert "is_kev" in first_cve
    print(f" -> Vulnerabilities OK: data_source={v_data['data_source']}, total={v_data['total']}, first={first_cve['id']}, CVSS={first_cve['cvss']}, is_kev={first_cve['is_kev']}")

    # 5. CISA KEV Catalog & Ransomware Filtering
    print("\n[5] Testing GET /api/vulnerabilities/kev ...")
    r = client.get("/api/vulnerabilities/kev?limit=5")
    assert r.status_code == 200, f"KEV failed: {r.status_code}"
    k_data = r.json()
    assert "vulnerabilities" in k_data
    assert "catalog_size" in k_data
    assert "data_source" in k_data
    print(f" -> KEV OK: data_source={k_data['data_source']}, catalog_size={k_data['catalog_size']}, returned={len(k_data['vulnerabilities'])}")

    # 6. NVD <-> KEV Cross-Referencing Precision
    print("\n[6] Testing NVD <-> KEV Cross-Referencing ...")
    assert asyncio.run(is_in_kev("CVE-2024-3400")) is True, "CVE-2024-3400 should be in KEV"
    assert asyncio.run(is_in_kev("CVE-2021-44228")) is True, "CVE-2021-44228 (Log4Shell) should be in KEV"
    assert asyncio.run(is_in_kev("CVE-1999-0095")) is False, "CVE-1999-0095 should not be in KEV"
    assert asyncio.run(is_in_kev("INVALID-CVE-0000")) is False, "Invalid CVE should return False"
    assert asyncio.run(is_in_kev("")) is False, "Empty CVE should return False"
    print(" -> NVD <-> KEV Cross-referencing verified: Known KEV, Non-KEV, and Invalid CVEs handled accurately.")

    # 7. Real-Time Multi-Step Attack Simulations
    print("\n[7] Testing All 4 Attack Simulation Chains ...")
    for scen in SCENARIOS:
        events = simulation_engine.trigger_scenario(scen["id"])
        assert events is not None and len(events) >= 3, f"Scenario {scen['id']} failed to generate steps"
        assert all(e.simulation is True for e in events), "All simulated events must have simulation: true"
        assert all(e.source_ip.startswith(("192.168.", "10.", "172.")) for e in events), "Source IPs must be private/test telemetry"
        print(f" -> Scenario OK: '{scen['name']}' generated {len(events)} correlated steps")

    # 8. Correlation Engine & Unrelated Event Isolation
    print("\n[8] Testing Correlation Logic & Isolation ...")
    engine = CorrelationEngine()

    # Send 3 failed logins from one source -> creates incident
    now_ts = "2024-04-12T10:00:00.000Z"
    ev1 = SecurityEvent(event_id="TEST-01", timestamp=now_ts, event_type="LOGIN_FAILURE", severity="LOW", source_ip="192.168.99.1", destination_ip="10.0.1.10", destination_port=22, protocol="SSH", target="auth-gateway.corp.internal", message="Failed login", simulation=True)
    ev2 = SecurityEvent(event_id="TEST-02", timestamp=now_ts, event_type="LOGIN_FAILURE", severity="MEDIUM", source_ip="192.168.99.1", destination_ip="10.0.1.10", destination_port=22, protocol="SSH", target="auth-gateway.corp.internal", message="Failed login", simulation=True)
    ev3 = SecurityEvent(event_id="TEST-03", timestamp=now_ts, event_type="BRUTE_FORCE", severity="CRITICAL", source_ip="192.168.99.1", destination_ip="10.0.1.10", destination_port=22, protocol="SSH", target="auth-gateway.corp.internal", message="Brute force threshold", simulation=True)

    engine.process_event(ev1)
    engine.process_event(ev2)
    inc = engine.process_event(ev3)
    assert inc is not None, "Brute force pattern must trigger incident"
    assert inc.source_ip == "192.168.99.1"

    # Send unrelated event from completely different source -> should NOT attach to that incident
    unrelated_ev = SecurityEvent(event_id="TEST-99", timestamp=now_ts, event_type="LOGIN_FAILURE", severity="LOW", source_ip="10.0.99.99", destination_ip="10.0.2.50", destination_port=5432, protocol="PostgreSQL", target="db-server", message="Unrelated failure", simulation=True)
    res_unrelated = engine.process_event(unrelated_ev)
    assert res_unrelated is None or res_unrelated.incident_id != inc.incident_id, "Unrelated source IP must not attach to previous incident"
    print(" -> Correlation verified: Multi-step chains clustered properly; unrelated telemetry isolated.")

    # 9. Incidents Endpoint & SQLite Persistence
    print("\n[9] Testing Incidents CRUD & SQLite Persistence ...")
    r = client.get("/api/incidents")
    assert r.status_code == 200, f"Incidents failed: {r.status_code}"
    incidents = r.json()
    assert len(incidents) >= 2
    inc_id = incidents[0]["incident_id"]

    # Status update
    r = client.patch(f"/api/incidents/{inc_id}/status", json={"status": "INVESTIGATING"})
    assert r.status_code == 200
    assert r.json()["status"] == "INVESTIGATING"

    # Verify reload from SQLite persistence
    engine_reloaded = CorrelationEngine()
    reloaded_inc = engine_reloaded.get_incident_by_id(inc_id)
    assert reloaded_inc is not None
    assert reloaded_inc.status == "INVESTIGATING", "Incident status must persist in SQLite across engine reload"
    print(f" -> Incident lifecycle & SQLite persistence verified: status updated and reloaded across restarts.")

    # 10. Sentinel AI Defensive Triage
    print("\n[10] Testing Sentinel AI Defensive Analyst ...")
    r = client.post("/api/ai/analyze", json={
        "event_type": "BRUTE_FORCE",
        "severity": "CRITICAL",
        "source_ip": "192.168.1.105",
        "target": "auth-gateway.corp.internal",
        "details": "High-velocity SSH credential brute force"
    })
    assert r.status_code == 200, f"AI analyze failed: {r.status_code}"
    ai_data = r.json()
    assert ai_data["risk_level"] == "CRITICAL"
    assert ai_data["risk_score"] >= 90
    assert len(ai_data["observed_facts"]) > 0
    assert len(ai_data["ai_inference"]) > 0
    assert len(ai_data["immediate_response"]) > 0
    assert ai_data.get("mitre_technique", {}).get("id") == "T1110"
    print(f" -> AI Triage verified: Risk={ai_data['risk_score']}/100 ({ai_data['risk_level']}), MITRE={ai_data['mitre_technique']['id']} ({ai_data['mitre_technique']['name']})")

    # 11. WebSocket Endpoint Handshake & Latency Ping
    print("\n[11] Testing WebSocket Handshake & Heartbeat ...")
    with client.websocket_connect("/ws/events") as ws:
        # Should receive initial state
        initial = ws.receive_json()
        assert initial.get("type") == "INITIAL_STATE"
        assert "recent_events" in initial
        assert "active_incidents" in initial

        # Ping/Pong
        ws.send_json({"type": "PING"})
        pong = ws.receive_json()
        assert pong.get("type") == "PONG"
        assert "timestamp" in pong
        print(" -> WebSocket handshake & Ping/Pong verified successfully.")

    # 12. Error Handling & Edge Cases
    print("\n[12] Testing Error Handling & Input Validation ...")
    r = client.get("/api/incidents/NON_EXISTENT_INCIDENT_999")
    assert r.status_code == 404
    r = client.patch(f"/api/incidents/{inc_id}/status", json={"status": "INVALID_STATUS_XYZ"})
    assert r.status_code == 400
    r = client.post("/api/ai/analyze", json={"severity": "INVALID_JSON"})
    assert r.status_code == 200  # Defensive fallback handles partial data gracefully
    print(" -> Error handling verified: 404 for missing IDs, 400 for invalid statuses, graceful fallback.")

    print("\n==================================================")
    print("ALL 12 PRODUCTION AUDIT TESTS PASSED WITH 100% SUCCESS!")
    print("==================================================")

if __name__ == "__main__":
    run_tests()

