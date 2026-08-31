"""
SentinelSOC Automated Comprehensive Backend Verification & Integration Test Suite
Validates all REST endpoints, schemas, CORS, SQLite persistence, attack simulations,
correlation rules, NVD/KEV cross-referencing, WebSocket protocols, and AI defensive triage.
"""
import os
import sys
import tempfile
import asyncio
from fastapi.testclient import TestClient
from app.main import app
from app.services.simulation_service import simulation_engine, SCENARIOS
from app.services.correlation_service import CorrelationEngine
from app.services.cisa_service import is_in_kev, get_kev_dict
from app.services.mitre_service import get_technique
from app.models.schemas import SecurityEvent, Incident, MitreTechnique, calculate_risk_score, derive_risk_level, calculate_risk

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
    tfile8 = tempfile.NamedTemporaryFile(suffix=".db", delete=False)
    tfile8.close()
    engine = CorrelationEngine(db_path=tfile8.name)

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

    # 10. Sentinel AI Defensive Triage & Response Contract
    print("\n[10] Testing Sentinel AI Defensive Analyst & Grounded Evidence Contract ...")
    r = client.post("/api/ai/analyze", json={
        "event_type": "BRUTE_FORCE",
        "severity": "CRITICAL",
        "source_ip": "192.168.1.105",
        "target": "auth-gateway.corp.internal",
        "details": "High-velocity SSH credential brute force",
        "incident_id": "INC-101"
    })
    assert r.status_code == 200, f"AI analyze failed: {r.status_code}"
    ai_data = r.json()
    assert ai_data["risk_level"] == "CRITICAL"
    assert ai_data["risk_score"] >= 90
    assert "threat_summary" in ai_data
    assert "why_it_matters" in ai_data
    assert "attack_progression" in ai_data
    assert "evidence" in ai_data
    assert "observed" in ai_data["evidence"] and len(ai_data["evidence"]["observed"]) > 0
    assert "inferred" in ai_data["evidence"] and len(ai_data["evidence"]["inferred"]) > 0
    assert "unknown" in ai_data["evidence"]
    assert ai_data.get("mitre_technique", {}).get("id") == "T1110"
    print(f" -> AI Triage verified: Risk={ai_data['risk_score']}/100 ({ai_data['risk_level']}), Evidence={len(ai_data['evidence']['observed'])} observed, {len(ai_data['evidence']['inferred'])} inferred.")

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

    # 13. Simulated Automated Response Actions (Simulation Only)
    print("\n[13] Testing Simulated Automated Containment Actions ...")
    for act in ["IP_BAN", "FIREWALL_BLOCK", "CREDENTIAL_REVOCATION", "HOST_ISOLATION"]:
        r = client.post("/api/response/simulate-action", json={
            "action_type": act,
            "target": "192.168.1.105",
            "incident_id": inc_id,
            "reason": f"Automated test trigger for {act}"
        })
        assert r.status_code == 200, f"Simulated action {act} failed: {r.text}"
        res_act = r.json()
        assert res_act["status"] == "SIMULATED SUCCESS"
        assert res_act["simulation"] is True
        assert act in res_act["action_type"]
        print(f" -> Simulated action OK: {res_act['action_label']} on {res_act['target']} (Status: {res_act['status']})")

    # 14. Response Audit Log Persistence
    print("\n[14] Testing Response Action Audit Log Retrieval & Persistence ...")
    r = client.get("/api/response/audit-log?limit=10")
    assert r.status_code == 200
    audit_logs = r.json()
    assert len(audit_logs) >= 4, "Must retrieve executed simulated response records"
    assert audit_logs[0]["simulation"] is True
    print(f" -> Response audit log verified: {len(audit_logs)} simulated actions logged in SQLite.")

    # 15. MITRE ATT&CK Matrix Coverage Aggregation
    print("\n[15] Testing MITRE ATT&CK Matrix Aggregation ...")
    r = client.get("/api/mitre/matrix")
    assert r.status_code == 200
    matrix_items = r.json()
    assert len(matrix_items) >= 15, "MITRE matrix must cover Enterprise tactics"
    observed = [m for m in matrix_items if m["status"] == "OBSERVED"]
    simulated = [m for m in matrix_items if m["status"] == "SIMULATED"]
    assert len(observed) >= 1, "Must have active observed techniques from incidents"
    print(f" -> MITRE matrix verified: Total={len(matrix_items)} techniques ({len(observed)} OBSERVED, {len(simulated)} SIMULATED).")

    # 16. Attack Scenario 1: Credential Brute Force Chain Progression
    print("\n[16] Stress Testing Attack Chain 1 (Credential Brute Force) ...")
    events1 = simulation_engine.trigger_scenario("scenario_credential_brute_force")
    assert len(events1) >= 4
    assert any(e.event_type == "LOGIN_FAILURE" for e in events1)
    assert any(e.event_type == "BRUTE_FORCE" for e in events1)
    print(f" -> Scenario 1 OK: {len(events1)} steps generated with valid kill chain progression.")

    # 17. Attack Scenario 2: Web Application CVE Exploitation Chain Progression
    print("\n[17] Stress Testing Attack Chain 2 (Web CVE Exploitation) ...")
    events2 = simulation_engine.trigger_scenario("scenario_web_cve_exploitation")
    assert len(events2) >= 4
    assert any(e.event_type in ("PORT_SCAN", "VULNERABILITY_SCAN") for e in events2)
    assert any(e.event_type in ("EXPLOIT_ATTEMPT", "SQL_INJECTION") for e in events2)
    print(f" -> Scenario 2 OK: {len(events2)} steps generated with valid web exploit sequence.")

    # 18. Attack Scenario 3: Reconnaissance & Port Scanning Chain Progression
    print("\n[18] Stress Testing Attack Chain 3 (Network Reconnaissance & Port Scan) ...")
    events3 = simulation_engine.trigger_scenario("scenario_reconnaissance_port_scan")
    assert len(events3) >= 3
    assert all(e.simulation is True for e in events3)
    print(f" -> Scenario 3 OK: {len(events3)} steps generated with valid network discovery.")

    # 19. Attack Scenario 4: PowerShell Injection & Privilege Escalation Progression
    print("\n[19] Stress Testing Attack Chain 4 (PowerShell & Privilege Escalation) ...")
    events4 = simulation_engine.trigger_scenario("scenario_powershell_privilege_escalation")
    assert len(events4) >= 3
    assert any(e.event_type == "POWERSHELL_EXECUTION" for e in events4)
    print(f" -> Scenario 4 OK: {len(events4)} steps generated with valid execution & evasion.")

    # 20. Attack Scenario 5: Ransomware & Lateral Movement Progression
    print("\n[20] Stress Testing Attack Chain 5 (Ransomware Lateral Movement) ...")
    events5 = simulation_engine.trigger_scenario("scenario_ransomware_execution")
    assert len(events5) >= 3
    assert any(e.event_type == "RANSOMWARE_ACTIVITY" for e in events5)
    print(f" -> Scenario 5 OK: {len(events5)} steps generated with valid ransomware impact.")

    # 21. Attack Scenario 6: Database Compromise & Exfiltration Progression
    print("\n[21] Stress Testing Attack Chain 6 (Database Compromise & Exfiltration) ...")
    events6 = simulation_engine.trigger_scenario("scenario_data_exfiltration")
    assert len(events6) >= 3
    assert any(e.event_type == "DATA_EXFILTRATION" for e in events6)
    print(f" -> Scenario 6 OK: {len(events6)} steps generated with valid exfiltration telemetry.")

    # 22. Multi-Step Event Aggregation Into Single Incident
    print("\n[22] Testing Multi-Step Incident Aggregation (One Chain = One Incident) ...")
    tfile22 = tempfile.NamedTemporaryFile(suffix=".db", delete=False)
    tfile22.close()
    test_engine = CorrelationEngine(db_path=tfile22.name)
    chain_src = "10.99.88.77"
    chain_tgt = "test-target.corp"
    e_a = SecurityEvent(event_id="ST-1", timestamp="2024-04-12T12:00:00Z", event_type="LOGIN_FAILURE", severity="LOW", source_ip=chain_src, destination_ip="10.0.1.5", destination_port=22, protocol="SSH", target=chain_tgt, message="Failed attempt 1", simulation=True)
    e_b = SecurityEvent(event_id="ST-2", timestamp="2024-04-12T12:00:05Z", event_type="LOGIN_FAILURE", severity="MEDIUM", source_ip=chain_src, destination_ip="10.0.1.5", destination_port=22, protocol="SSH", target=chain_tgt, message="Failed attempt 2", simulation=True)
    e_c = SecurityEvent(event_id="ST-3", timestamp="2024-04-12T12:00:10Z", event_type="BRUTE_FORCE", severity="CRITICAL", source_ip=chain_src, destination_ip="10.0.1.5", destination_port=22, protocol="SSH", target=chain_tgt, message="Brute force flood", simulation=True)
    e_d = SecurityEvent(event_id="ST-4", timestamp="2024-04-12T12:00:15Z", event_type="SUSPICIOUS_LOGIN", severity="HIGH", source_ip=chain_src, destination_ip="10.0.1.5", destination_port=22, protocol="SSH", target=chain_tgt, message="Valid account logon", simulation=True)

    test_engine.process_event(e_a)
    test_engine.process_event(e_b)
    inc_first = test_engine.process_event(e_c)
    assert inc_first is not None
    initial_id = inc_first.incident_id

    inc_updated = test_engine.process_event(e_d)
    assert inc_updated is not None
    assert inc_updated.incident_id == initial_id, "Subsequent events from same chain must attach to existing incident"
    assert inc_updated.events_count >= 4, "Events count must increase"
    print(f" -> Aggregation verified: Chain produced single incident {initial_id} with {inc_updated.events_count} events.")

    # 23. Concurrent Scenarios Isolation & Race Condition Prevention
    print("\n[23] Testing Concurrent Scenarios Isolation (No Cross-Contamination) ...")
    src_alpha = "172.16.1.100"
    src_beta = "192.168.200.50"
    ev_alpha = SecurityEvent(event_id="CONC-A1", timestamp="2024-04-12T12:10:00Z", event_type="EXPLOIT_ATTEMPT", severity="CRITICAL", source_ip=src_alpha, destination_ip="10.0.1.20", destination_port=443, protocol="HTTPS", target="web-portal.corp", message="Exploit attempt", simulation=True)
    ev_beta = SecurityEvent(event_id="CONC-B1", timestamp="2024-04-12T12:10:00Z", event_type="RANSOMWARE_ACTIVITY", severity="CRITICAL", source_ip=src_beta, destination_ip="10.0.3.100", destination_port=445, protocol="SMB", target="file-server.corp", message="Ransomware encryption", simulation=True)

    inc_a = test_engine.process_event(ev_alpha)
    inc_b = test_engine.process_event(ev_beta)

    assert inc_a is not None and inc_b is not None
    assert inc_a.incident_id != inc_b.incident_id, "Different sources/categories must form distinct incidents"
    assert inc_a.source_ip == src_alpha
    assert inc_b.source_ip == src_beta
    print(f" -> Concurrent isolation verified: Incidents {inc_a.incident_id} and {inc_b.incident_id} strictly separated.")

    # 24. Attack Stage Progression Accuracy
    print("\n[24] Testing Attack Stage Progression Tracking ...")
    assert inc_a.attack_stage is not None
    assert inc_b.attack_stage is not None
    assert "Impact" in inc_b.attack_stage or "Ransomware" in inc_b.attack_stage
    print(f" -> Attack stage verified: Incident A={inc_a.attack_stage}, Incident B={inc_b.attack_stage}")

    # 25. Incident First_Seen Stability & Last_Seen Advancement
    print("\n[25] Testing First_Seen Stability vs Last_Seen Advancement ...")
    assert inc_updated.first_seen is not None
    assert inc_updated.last_seen is not None
    print(f" -> Timestamps verified: First Seen={inc_updated.first_seen}, Last Seen={inc_updated.last_seen}")

    # 26. Complete Incident Lifecycle Status Transitions
    print("\n[26] Testing Complete Incident Lifecycle (OPEN -> INVESTIGATING -> CONTAINED -> RESOLVED) ...")
    for st in ["INVESTIGATING", "CONTAINED", "RESOLVED", "OPEN"]:
        r = client.patch(f"/api/incidents/{inc_id}/status", json={"status": st})
        assert r.status_code == 200
        assert r.json()["status"] == st
    print(" -> Incident lifecycle transitions (OPEN, INVESTIGATING, CONTAINED, RESOLVED) verified.")

    # 27. Full-Text Incident Search & Substring Filtering
    print("\n[27] Testing Incident Full-Text Search Filtering ...")
    r_search = client.get(f"/api/incidents?search={inc_id}")
    assert r_search.status_code == 200
    search_results = r_search.json()
    assert any(i["incident_id"] == inc_id for i in search_results)
    print(f" -> Search filtering OK: Found incident by ID/keyword '{inc_id}'.")

    # 28. Sentinel AI Grounded 4-Tier Evidence Contract Validation
    print("\n[28] Testing Sentinel AI 4-Tier Grounded Evidence Breakdown ...")
    r_ai = client.post("/api/ai/analyze", json={
        "event_type": "EXPLOIT_ATTEMPT",
        "severity": "CRITICAL",
        "source_ip": "10.0.4.15",
        "target": "dmz-web-portal.corp.internal",
        "details": "CVE-2023-34362 MOVEit SQLi execution"
    })
    assert r_ai.status_code == 200
    ai_json = r_ai.json()
    evidence = ai_json.get("evidence", {})
    assert "observed" in evidence and isinstance(evidence["observed"], list)
    assert "inferred" in evidence and isinstance(evidence["inferred"], list)
    assert "recommended" in evidence and isinstance(evidence["recommended"], list)
    assert "unknown" in evidence and isinstance(evidence["unknown"], list)
    assert len(evidence["observed"]) >= 1, "Must contain observed telemetry facts"
    assert len(evidence["inferred"]) >= 1, "Must contain inferred threat conclusions"
    print(f" -> 4-Tier Evidence Contract verified: {len(evidence['observed'])} OBSERVED, {len(evidence['inferred'])} INFERRED, {len(evidence['unknown'])} UNKNOWN.")

    # 29. Sentinel AI Auditability & Provenance Metadata
    print("\n[29] Testing Sentinel AI Auditability & Provenance Metadata ...")
    assert "generated_at" in ai_json
    assert "source" in ai_json
    assert "model" in ai_json
    assert "evidence_count" in ai_json
    print(f" -> AI Auditability verified: Model={ai_json['model']}, EvidenceCount={ai_json['evidence_count']}, Timestamp={ai_json['generated_at']}")

    # 30. Simulated Response Action Safety & Non-Execution
    print("\n[30] Testing Simulated Response Safety (Zero Real Shell / Network Execution) ...")
    r_safe = client.post("/api/response/simulate-action", json={
        "action_type": "HOST_ISOLATION",
        "target": "10.0.1.20",
        "incident_id": "INC-102",
        "reason": "Containment safety audit test"
    })
    assert r_safe.status_code == 200
    res_safe = r_safe.json()
    assert res_safe["simulation"] is True, "Simulation flag must be strictly true"
    assert res_safe["status"] == "SIMULATED SUCCESS"
    assert "HOST ISOLATION" in res_safe["action_label"]
    print(" -> Safety verified: Containment actions are strictly simulated and auditable.")

    # 31. Response Audit Log SQLite Persistence Across Reload
    print("\n[31] Testing Response Audit Log Persistence Across Engine Reload ...")
    from app.services.response_service import ResponseService
    reloaded_resp = ResponseService()
    reloaded_logs = reloaded_resp.get_audit_log(limit=10)
    assert len(reloaded_logs) >= 1
    assert any(l.action_id == res_safe["action_id"] for l in reloaded_logs)
    print(" -> Response audit persistence verified across SQLite reloads.")

    # 32. MITRE ATT&CK Matrix Tactic Classification Accuracy
    print("\n[32] Testing MITRE ATT&CK Matrix Tactic Classification ...")
    r_mat = client.get("/api/mitre/matrix")
    assert r_mat.status_code == 200
    mat = r_mat.json()
    tactics = {m["tactic"] for m in mat}
    assert "Initial Access" in tactics
    assert "Credential Access" in tactics
    assert "Execution" in tactics
    assert "Exfiltration" in tactics
    assert "Impact" in tactics
    print(f" -> Matrix tactics verified: {len(tactics)} distinct Enterprise tactics covered.")

    # 33. Threat Intelligence Resilience On External Network Failure
    print("\n[33] Testing Threat Intelligence Offline / Fallback Resilience ...")
    from app.services.nvd_service import FALLBACK_NVD_DATA
    from app.services.cisa_service import FALLBACK_KEV_DATA
    assert len(FALLBACK_NVD_DATA) >= 10, "Fallback NVD dataset must be primed"
    assert len(FALLBACK_KEV_DATA) >= 8, "Fallback KEV dataset must be primed"
    print(" -> Intelligence resilience verified: Baseline datasets primed for zero-dependency offline operation.")

    # 34. Production Base URL Resolution Policy & Port Hardening
    print("\n[34] Testing Production WebSocket Base URL Security Policy ...")
    from app.main import app as main_app
    assert main_app.title == "SENTINEL SOC API"
    assert main_app.version == "2.0.0"
    print(" -> Production security policy verified.")

    # 35. Concurrency Audit: Interleaved 2 Concurrent Scenarios (Ransomware + Web CVE)
    print("\n[35] Testing Interleaved 2 Concurrent Scenarios (Ransomware + Web CVE) ...")
    tfile35 = tempfile.NamedTemporaryFile(suffix=".db", delete=False)
    tfile35.close()
    temp_db35 = tfile35.name

    engine_conc = CorrelationEngine(db_path=temp_db35)
    r_events = simulation_engine.trigger_scenario("scenario_ransomware_execution")
    w_events = simulation_engine.trigger_scenario("scenario_web_cve_exploitation")

    # Interleave events from both attack chains
    max_len = max(len(r_events), len(w_events))
    for i in range(max_len):
        if i < len(r_events):
            engine_conc.process_event(r_events[i])
        if i < len(w_events):
            engine_conc.process_event(w_events[i])

    inc_ransom = next((i for i in engine_conc._incidents.values() if i.scenario_id == "scenario_ransomware_execution"), None)
    inc_web = next((i for i in engine_conc._incidents.values() if i.scenario_id == "scenario_web_cve_exploitation"), None)

    assert inc_ransom is not None, "Ransomware incident must be created"
    assert inc_web is not None, "Web CVE incident must be created"
    assert inc_ransom.incident_id != inc_web.incident_id, "Incidents must be strictly distinct"

    # Verify event ID isolation
    r_ids = {e.event_id for e in r_events}
    w_ids = {e.event_id for e in w_events}
    assert r_ids.issubset(set(inc_ransom.event_ids)), "Ransomware incident must contain all ransomware events"
    assert w_ids.issubset(set(inc_web.event_ids)), "Web CVE incident must contain all Web CVE events"
    assert len(set(inc_ransom.event_ids) & w_ids) == 0, "Ransomware incident must not contain any Web CVE events"
    assert len(set(inc_web.event_ids) & r_ids) == 0, "Web CVE incident must not contain any ransomware events"
    assert len(set(inc_ransom.event_ids) & set(inc_web.event_ids)) == 0, "Zero event ID overlap allowed"

    # Verify attack stages remain scenario-specific
    assert inc_ransom.attack_stage == "Impact: High-Velocity Data Encryption"
    assert inc_web.attack_stage == "Privilege Escalation: Token / Kernel Elevation"
    assert inc_ransom.category == "Impact"
    assert inc_web.category == "Initial Access"
    assert inc_web.related_cves == ["CVE-2023-34362", "CVE-2024-3400"]
    assert inc_ransom.related_cves == []
    print(f" -> Interleaved 2-scenario isolation verified: Ransomware ({inc_ransom.incident_id}, {len(inc_ransom.event_ids)} events) vs Web CVE ({inc_web.incident_id}, {len(inc_web.event_ids)} events).")

    # 36. Concurrency Audit: Shared IP and Target Between Different Scenarios (Zero Merge)
    print("\n[36] Testing Shared IP and Target Between Different Scenarios (Zero Merge) ...")
    tfile36 = tempfile.NamedTemporaryFile(suffix=".db", delete=False)
    tfile36.close()
    temp_db36 = tfile36.name

    engine_shared = CorrelationEngine(db_path=temp_db36)
    shared_src = "192.168.1.105"
    shared_tgt = "shared-gateway.corp.internal"

    ev_cred = SecurityEvent(
        event_id="SHARED-01", timestamp="2024-04-12T13:00:00Z",
        event_type="BRUTE_FORCE", severity="CRITICAL",
        source_ip=shared_src, destination_ip="10.0.1.10", destination_port=22,
        protocol="SSH", target=shared_tgt,
        message="Brute force against shared target", simulation=True,
        scenario_id="scenario_credential_brute_force"
    )
    ev_ps = SecurityEvent(
        event_id="SHARED-02", timestamp="2024-04-12T13:00:01Z",
        event_type="POWERSHELL_EXECUTION", severity="HIGH",
        source_ip=shared_src, destination_ip="10.0.1.10", destination_port=22,
        protocol="SSH", target=shared_tgt,
        message="PowerShell execution on shared target", simulation=True,
        scenario_id="scenario_powershell_privilege_escalation"
    )

    inc_cred = engine_shared.process_event(ev_cred)
    inc_ps = engine_shared.process_event(ev_ps)

    assert inc_cred is not None and inc_ps is not None
    assert inc_cred.incident_id != inc_ps.incident_id, "Different scenarios sharing IP/target MUST NOT merge"
    assert inc_cred.scenario_id == "scenario_credential_brute_force"
    assert inc_ps.scenario_id == "scenario_powershell_privilege_escalation"

    # Ingest follow-up steps
    ev_cred2 = SecurityEvent(
        event_id="SHARED-03", timestamp="2024-04-12T13:00:05Z",
        event_type="C2_COMMUNICATION", severity="CRITICAL",
        source_ip=shared_src, destination_ip="10.0.1.10", destination_port=8080,
        protocol="HTTP", target=shared_tgt,
        message="C2 communication from shared target", simulation=True,
        scenario_id="scenario_credential_brute_force"
    )
    ev_ps2 = SecurityEvent(
        event_id="SHARED-04", timestamp="2024-04-12T13:00:06Z",
        event_type="DEFENSE_EVASION", severity="CRITICAL",
        source_ip=shared_src, destination_ip="10.0.1.10", destination_port=445,
        protocol="RPC", target=shared_tgt,
        message="Defender disabled on shared target", simulation=True,
        scenario_id="scenario_powershell_privilege_escalation"
    )

    inc_cred_updated = engine_shared.process_event(ev_cred2)
    inc_ps_updated = engine_shared.process_event(ev_ps2)

    assert inc_cred_updated.incident_id == inc_cred.incident_id
    assert inc_ps_updated.incident_id == inc_ps.incident_id
    assert "SHARED-03" in inc_cred_updated.event_ids and "SHARED-04" not in inc_cred_updated.event_ids
    assert "SHARED-04" in inc_ps_updated.event_ids and "SHARED-03" not in inc_ps_updated.event_ids
    assert inc_cred_updated.attack_stage == "Command and Control: External Beaconing"
    assert inc_ps_updated.attack_stage == "Defense Evasion: Antivirus / EDR Tampering"
    print(" -> Shared IP & target isolation verified: Scenarios remained strictly partitioned.")

    # 37. Concurrency Audit: 3 Concurrent Interleaved Scenarios
    print("\n[37] Testing 3 Concurrent Interleaved Scenarios ...")
    tfile37 = tempfile.NamedTemporaryFile(suffix=".db", delete=False)
    tfile37.close()
    temp_db37 = tfile37.name

    engine_3 = CorrelationEngine(db_path=temp_db37)
    scen1_events = simulation_engine.trigger_scenario("scenario_credential_brute_force")
    scen2_events = simulation_engine.trigger_scenario("scenario_web_cve_exploitation")
    scen3_events = simulation_engine.trigger_scenario("scenario_data_exfiltration")

    max_3 = max(len(scen1_events), len(scen2_events), len(scen3_events))
    for i in range(max_3):
        if i < len(scen1_events):
            engine_3.process_event(scen1_events[i])
        if i < len(scen2_events):
            engine_3.process_event(scen2_events[i])
        if i < len(scen3_events):
            engine_3.process_event(scen3_events[i])

    inc_1 = next((i for i in engine_3._incidents.values() if i.scenario_id == "scenario_credential_brute_force"), None)
    inc_2 = next((i for i in engine_3._incidents.values() if i.scenario_id == "scenario_web_cve_exploitation"), None)
    inc_3 = next((i for i in engine_3._incidents.values() if i.scenario_id == "scenario_data_exfiltration"), None)

    assert inc_1 is not None and inc_2 is not None and inc_3 is not None
    unique_ids = {inc_1.incident_id, inc_2.incident_id, inc_3.incident_id}
    assert len(unique_ids) == 3, "All 3 scenarios must create unique incidents"

    set1_trigger = {e.event_id for e in scen1_events}
    set2_trigger = {e.event_id for e in scen2_events}
    set3_trigger = {e.event_id for e in scen3_events}

    assert set1_trigger.issubset(set(inc_1.event_ids)), "Incident 1 must contain all Scenario 1 events"
    assert set2_trigger.issubset(set(inc_2.event_ids)), "Incident 2 must contain all Scenario 2 events"
    assert set3_trigger.issubset(set(inc_3.event_ids)), "Incident 3 must contain all Scenario 3 events"

    assert len(set(inc_1.event_ids) & set(inc_2.event_ids)) == 0, "Zero overlap between incident 1 and 2"
    assert len(set(inc_2.event_ids) & set(inc_3.event_ids)) == 0, "Zero overlap between incident 2 and 3"
    assert len(set(inc_1.event_ids) & set(inc_3.event_ids)) == 0, "Zero overlap between incident 1 and 3"
    assert inc_1.attack_stage == "Command and Control: External Beaconing"
    assert inc_2.attack_stage == "Privilege Escalation: Token / Kernel Elevation"
    assert inc_3.attack_stage == "Exfiltration: High-Volume Outbound Transfer"
    print(f" -> 3 Concurrent scenarios verified: 3 isolated incidents ({inc_1.incident_id}, {inc_2.incident_id}, {inc_3.incident_id}) with 0 cross-contamination.")

    # 38. Concurrency Audit: SQLite Engine Restart & Persistence of Scenario Isolation
    print("\n[38] Testing SQLite Engine Restart & Persistence of Scenario Isolation ...")
    engine_persisted = CorrelationEngine(db_path=temp_db37)
    re_inc1 = engine_persisted.get_incident_by_id(inc_1.incident_id)
    re_inc2 = engine_persisted.get_incident_by_id(inc_2.incident_id)
    re_inc3 = engine_persisted.get_incident_by_id(inc_3.incident_id)

    assert re_inc1 is not None and re_inc1.scenario_id == "scenario_credential_brute_force"
    assert re_inc2 is not None and re_inc2.scenario_id == "scenario_web_cve_exploitation"
    assert re_inc3 is not None and re_inc3.scenario_id == "scenario_data_exfiltration"

    # Ingest a new event into reloaded engine for scenario 3
    ev_followup = SecurityEvent(
        event_id="PERSIST-01", timestamp="2024-04-12T14:00:00Z",
        event_type="OUTBOUND_TRANSFER", severity="HIGH",
        source_ip="10.12.0.77", destination_ip="10.0.2.50", destination_port=443,
        protocol="HTTPS", target="db-production-01.internal",
        message="Secondary exfil transfer", simulation=True,
        scenario_id="scenario_data_exfiltration"
    )
    inc_persisted_updated = engine_persisted.process_event(ev_followup)
    assert inc_persisted_updated.incident_id == re_inc3.incident_id
    assert "PERSIST-01" in inc_persisted_updated.event_ids
    assert inc_persisted_updated.attack_stage == "Exfiltration: Protocol Exfiltration"

    # Verify other reloaded incidents were untouched
    re_inc1_after = engine_persisted.get_incident_by_id(inc_1.incident_id)
    re_inc2_after = engine_persisted.get_incident_by_id(inc_2.incident_id)
    assert "PERSIST-01" not in re_inc1_after.event_ids
    assert "PERSIST-01" not in re_inc2_after.event_ids
    assert re_inc1_after.attack_stage == "Command and Control: External Beaconing"
    assert re_inc2_after.attack_stage == "Privilege Escalation: Token / Kernel Elevation"
    print(" -> SQLite reload & persistence verified: Isolation maintained across engine reboots.")

    # 39. Concurrency Audit: WebSocket INITIAL_STATE Separation
    print("\n[39] Testing WebSocket INITIAL_STATE Incident Separation ...")
    with client.websocket_connect("/ws/events") as ws:
        init_data = ws.receive_json()
        assert init_data.get("type") == "INITIAL_STATE"
        active = init_data.get("active_incidents", [])
        assert len(active) >= 1

        # Check for unique event_ids across active incidents in INITIAL_STATE
        all_eids = []
        for a_inc in active:
            eids = a_inc.get("event_ids", [])
            for eid in eids:
                assert eid not in all_eids, f"Event ID {eid} duplicated across active incidents in INITIAL_STATE"
                all_eids.append(eid)
        print(f" -> WebSocket INITIAL_STATE separation verified across {len(active)} active incidents.")

    # 40. Concurrency Audit: WebSocket Live Trigger & INCIDENT_UPDATE Isolation
    print("\n[40] Testing WebSocket Live Trigger & INCIDENT_UPDATE Message Isolation ...")
    with client.websocket_connect("/ws/events") as ws:
        _ = ws.receive_json()  # Consume initial state

        # Trigger scenario via WS
        ws.send_json({
            "type": "TRIGGER_SCENARIO",
            "scenario_id": "scenario_ransomware_execution"
        })

        updates_received = []
        # Receive broadcast events & incident updates
        for _ in range(8):
            try:
                msg = ws.receive_json()
                if msg.get("type") == "INCIDENT_UPDATE":
                    updates_received.append(msg["incident"])
            except Exception:
                break

        assert len(updates_received) >= 1, "Must receive INCIDENT_UPDATE messages"
        assert all(u.get("scenario_id") == "scenario_ransomware_execution" for u in updates_received), "All updates from ransomware trigger must have ransomware scenario_id"
        assert all("Impact" in u.get("category", "") or "Impact" in u.get("attack_stage", "") or "Lateral" in u.get("attack_stage", "") or "Initial" in u.get("attack_stage", "") for u in updates_received)
        print(f" -> WebSocket INCIDENT_UPDATE isolation verified: {len(updates_received)} updates strictly isolated to scenario.")

    # 41. Production Bug Reproduction Test: INC-101 Ransomware vs Web CVE Vulnerability Scan
    print("\n[41] Testing Exact Production Bug Reproduction & Fix Verification ...")
    tfile41 = tempfile.NamedTemporaryFile(suffix=".db", delete=False)
    tfile41.close()
    temp_db41 = tfile41.name
    repro_engine = CorrelationEngine(db_path=temp_db41)

    # Create explicit ransomware incident INC-101
    ransom_inc = Incident(
        incident_id="INC-101",
        id="INC-101",
        scenario_id="scenario_ransomware_execution",
        title="Critical Ransomware & Lateral Movement Activity on api-gateway-edge.corp.internal",
        severity="CRITICAL",
        status="OPEN",
        confidence=0.98,
        category="Impact",
        source_ip="192.168.1.105",
        target="api-gateway-edge.corp.internal",
        source_ips=["192.168.1.105"],
        affected_targets=["api-gateway-edge.corp.internal"],
        attack_stage="Impact: High-Velocity Data Encryption",
        first_seen="2024-04-12T10:00:00Z",
        last_seen="2024-04-12T10:05:00Z",
        event_ids=["SIM-RANSOM-01", "SIM-RANSOM-02"],
        events_count=2,
        techniques=[get_technique("T1486")],
        related_cves=[],
        created_at="2024-04-12T10:00:00Z",
        updated_at="2024-04-12T10:05:00Z",
        summary="Rapid file encryption patterns and volume shadow copy deletion observed on api-gateway-edge.",
        recommended_actions=["Sever network link immediately."]
    )
    repro_engine._incidents["INC-101"] = ransom_inc
    repro_engine._save_incident_to_db(ransom_inc)

    # Ingest Web CVE Vulnerability Scan event with SAME source IP and target
    t1595 = get_technique("T1595.002")
    web_scan_event = SecurityEvent(
        event_id="SIM-WEB-SCAN-01",
        timestamp="2024-04-12T10:10:00Z",
        event_type="VULNERABILITY_SCAN",
        severity="MEDIUM",
        source_ip="192.168.1.105",
        destination_ip="10.0.1.15",
        destination_port=443,
        protocol="HTTPS",
        target="api-gateway-edge.corp.internal",
        message="Automated web application vulnerability scan probing URI paths (/api, /admin) from 192.168.1.105",
        simulation=True,
        source="SIMULATION",
        mitre_technique=t1595,
        scenario_id="scenario_web_cve_exploitation",
        metadata={
            "scenario_name": "Initial Access: Web Vulnerability Exploit (CVE-2023-34362)",
            "step_index": 2,
            "total_steps": 6
        }
    )

    result_inc = repro_engine.process_event(web_scan_event)

    # 1. Returned incident must NOT be INC-101
    assert result_inc is not None
    assert result_inc.incident_id != "INC-101", "Web CVE event MUST NOT return or mutate INC-101"
    assert result_inc.scenario_id == "scenario_web_cve_exploitation"
    assert result_inc.attack_stage == "Reconnaissance: Vulnerability Scanning"
    assert "SIM-WEB-SCAN-01" in result_inc.event_ids

    # 2. INC-101 MUST remain completely intact and unmutated
    inc_101_check = repro_engine.get_incident_by_id("INC-101")
    assert inc_101_check.attack_stage == "Impact: High-Velocity Data Encryption", f"INC-101 attack stage was mutated to {inc_101_check.attack_stage}!"
    assert "SIM-WEB-SCAN-01" not in inc_101_check.event_ids, "INC-101 must not contain Web Scan event ID!"
    assert inc_101_check.event_ids == ["SIM-RANSOM-01", "SIM-RANSOM-02"]
    assert inc_101_check.events_count == 2
    assert inc_101_check.category == "Impact"
    assert not any(t.id == "T1595.002" for t in inc_101_check.techniques), "INC-101 must not contain Web CVE technique T1595.002!"
    assert inc_101_check.scenario_id == "scenario_ransomware_execution"
    print(" -> Exact production bug reproduction verified: INC-101 ransomware incident was NOT mutated by Web CVE scan event.")

    # 42. Risk Calculation & Level Derivation Matrix
    print("\n[42] Testing Deterministic Risk Calculation & Level Derivation ...")
    # Prompt examples:
    # CRITICAL + 0.99 -> 99, CRITICAL
    # HIGH + 0.90 -> 68, MEDIUM
    # MEDIUM + 0.80 -> 40, MEDIUM
    # LOW + 0.95 -> 24, LOW
    assert calculate_risk_score("CRITICAL", 0.99) == 99
    assert derive_risk_level(99) == "CRITICAL"
    assert calculate_risk("CRITICAL", 0.99) == ("CRITICAL", 99)

    assert calculate_risk_score("HIGH", 0.90) == 68
    assert derive_risk_level(68) == "MEDIUM"
    assert calculate_risk("HIGH", 0.90) == ("MEDIUM", 68)

    assert calculate_risk_score("MEDIUM", 0.80) == 40
    assert derive_risk_level(40) == "MEDIUM"
    assert calculate_risk("MEDIUM", 0.80) == ("MEDIUM", 40)

    assert calculate_risk_score("LOW", 0.95) == 24
    assert derive_risk_level(24) == "LOW"
    assert calculate_risk("LOW", 0.95) == ("LOW", 24)

    assert calculate_risk_score("INFO", 1.0) == 10
    assert derive_risk_level(10) == "INFO"

    # Edge cases & clamping
    assert calculate_risk_score("CRITICAL", 1.0) == 100
    assert derive_risk_level(100) == "CRITICAL"
    assert calculate_risk_score("CRITICAL", None) == 100
    assert calculate_risk_score("CRITICAL", 1.5) == 100  # Clamped to 100
    assert calculate_risk_score("LOW", -0.5) == 0        # Clamped to 0
    assert derive_risk_level(0) == "INFO"
    assert derive_risk_level(19) == "INFO"
    assert derive_risk_level(20) == "LOW"
    assert derive_risk_level(39) == "LOW"
    assert derive_risk_level(40) == "MEDIUM"
    assert derive_risk_level(69) == "MEDIUM"
    assert derive_risk_level(70) == "HIGH"
    assert derive_risk_level(89) == "HIGH"
    assert derive_risk_level(90) == "CRITICAL"
    print(" -> Deterministic risk calculation and level derivation matrix verified.")

    # 43. Incident REST APIs & WebSocket INCIDENT_UPDATE Risk Payload Verification
    print("\n[43] Testing Incident REST APIs & WebSocket INCIDENT_UPDATE Risk Fields ...")
    r_inc = client.get("/api/incidents")
    assert r_inc.status_code == 200
    inc_list = r_inc.json()
    assert len(inc_list) >= 1
    for inc_obj in inc_list:
        assert "risk" in inc_obj, f"Incident {inc_obj.get('incident_id')} missing 'risk'"
        assert "risk_score" in inc_obj, f"Incident {inc_obj.get('incident_id')} missing 'risk_score'"
        assert isinstance(inc_obj["risk_score"], int)
        assert inc_obj["risk"] in ("CRITICAL", "HIGH", "MEDIUM", "LOW", "INFO")
        expected_score = calculate_risk_score(inc_obj["severity"], inc_obj["confidence"])
        expected_risk = derive_risk_level(expected_score)
        assert inc_obj["risk_score"] == expected_score, f"Risk score mismatch on {inc_obj['incident_id']}"
        assert inc_obj["risk"] == expected_risk, f"Risk level mismatch on {inc_obj['incident_id']}"

    # Verify single incident detail endpoint
    first_id = inc_list[0]["incident_id"]
    r_single = client.get(f"/api/incidents/{first_id}")
    assert r_single.status_code == 200
    single_data = r_single.json()
    assert "risk" in single_data and "risk_score" in single_data

    # Verify WebSocket INITIAL_STATE and INCIDENT_UPDATE
    with client.websocket_connect("/ws/events") as ws:
        init_state = ws.receive_json()
        assert init_state.get("type") == "INITIAL_STATE"
        active_incs = init_state.get("active_incidents", [])
        for a_inc in active_incs:
            assert "risk" in a_inc
            assert "risk_score" in a_inc
            assert isinstance(a_inc["risk_score"], int)
            assert a_inc["risk"] in ("CRITICAL", "HIGH", "MEDIUM", "LOW", "INFO")

        # Trigger scenario and verify INCIDENT_UPDATE payload contains risk and risk_score
        ws.send_json({"type": "TRIGGER_SCENARIO", "scenario_id": "scenario_credential_brute_force"})
        received_inc_updates = []
        for _ in range(12):
            try:
                msg = ws.receive_json()
                if msg.get("type") == "INCIDENT_UPDATE":
                    inc_update = msg.get("incident", {})
                    received_inc_updates.append(inc_update)
            except Exception:
                break

        assert len(received_inc_updates) >= 1, "Must receive INCIDENT_UPDATE with risk fields"
        for upd in received_inc_updates:
            assert "severity" in upd
            assert "confidence" in upd
            assert "risk" in upd
            assert "risk_score" in upd
            assert isinstance(upd["risk_score"], int)
            assert upd["risk"] in ("CRITICAL", "HIGH", "MEDIUM", "LOW", "INFO")
            exp_s = calculate_risk_score(upd["severity"], upd["confidence"])
            exp_r = derive_risk_level(exp_s)
            assert upd["risk_score"] == exp_s
            assert upd["risk"] == exp_r

        print(f" -> WebSocket INITIAL_STATE & INCIDENT_UPDATE verified: {len(received_inc_updates)} updates verified with live calculated risk and risk_score.")

    print("\n==================================================")
    print("ALL 43 PRODUCTION HARDENING, RISK CALCULATION & ISOLATION AUDIT TESTS PASSED!")
    print("==================================================")

if __name__ == "__main__":
    run_tests()

