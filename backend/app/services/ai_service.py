"""
Sentinel AI Defensive Analyst Service
Provides high-fidelity, structured defensive cybersecurity triage, MITRE ATT&CK mapping,
fact vs inference separation, and actionable incident response playbooks.
"""
import os
import json
import logging
from typing import Dict, Any, Optional
import httpx
from datetime import datetime, timezone

from app.models.schemas import AnalysisResponse, AnalysisRequest
from app.services.mitre_service import map_event_to_mitre, get_technique

logger = logging.getLogger("sentinel.ai")


def _generate_expert_defensive_analysis(data: Dict[str, Any]) -> AnalysisResponse:
    """
    Expert heuristic defensive cybersecurity engine.
    Produces rigorous, production-grade SOC triage without requiring external LLM API tokens.
    """
    event_type = str(data.get("event_type") or "SECURITY_ALERT").upper()
    severity = str(data.get("severity") or "MEDIUM").upper()
    details = str(data.get("details") or "")
    src_ip = str(data.get("source_ip") or "Simulated Telemetry Source")
    target = str(data.get("target") or "Target Asset")
    affected_assets = [target] if target else ["Target Asset"]

    mitre_tech = map_event_to_mitre(event_type)

    if "BRUTE" in event_type or "LOGIN" in event_type:
        risk_score = 92 if severity == "CRITICAL" else 78
        classification = "Credential Access / Authentication Brute Force"
        confidence = 0.94
        summary = f"High-velocity authentication failures detected from {src_ip} targeting {target}. Indicates automated password guessing or spraying attempts."
        observed_facts = [
            f"Observed repeated failed logon attempts originating from source {src_ip}.",
            f"Target destination service: {target}.",
            f"Severity level categorized as {severity} by telemetry telemetry."
        ]
        ai_inference = [
            "Source is exhibiting automated credential testing patterns consistent with brute force tooling.",
            "Risk of account lockout or legitimate service denial if attacks persist.",
            "Potential for lateral pivot if credentials match administrative service accounts."
        ]
        immediate_response = [
            f"Temporarily rate-limit or drop packets from {src_ip} at network border.",
            f"Inspect target {target} for any subsequent successful session tokens.",
            "Check targeted user accounts for compromised password re-use."
        ]
        investigation_steps = [
            "Query SIEM authentication logs for the past 24 hours from this source IP.",
            "Verify whether Multi-Factor Authentication (MFA) was prompted and approved.",
            "Check if target accounts have elevated domain or local administrative privileges."
        ]
        long_term_hardening = [
            "Enforce strict account lockout thresholds (e.g. 5 attempts in 10 minutes).",
            "Require phishing-resistant FIDO2 / hardware token MFA on all external services.",
            "Transition remote access from public SSH/RDP to zero-trust bastion/VPN with IP whitelisting."
        ]

    elif "EXPLOIT" in event_type or "SQL" in event_type or "WEB" in event_type:
        risk_score = 96 if severity == "CRITICAL" else 84
        classification = "Initial Access / Web Application Vulnerability Exploitation"
        confidence = 0.95
        summary = f"Exploit payload patterns detected against {target} from {src_ip}. Active attempt to leverage software vulnerability for remote code execution or unauthorized data access."
        observed_facts = [
            f"Inbound HTTP/HTTPS payload directed at {target}.",
            f"Malicious parameter strings or exploit signatures matched web defense telemetry.",
            f"Originating telemetry source IP: {src_ip}."
        ]
        ai_inference = [
            "Adversary is attempting to leverage public vulnerability (e.g. CVE-2023-34362 / CVE-2024-3400).",
            "If vulnerable component is unpatched, arbitrary code execution or database extraction is imminent."
        ]
        immediate_response = [
            f"Isolate or apply emergency WAF signature block on {target}.",
            "Review application error and access logs for HTTP 200/500 anomalous responses.",
            "Terminate suspicious child processes spawned by web server process."
        ]
        investigation_steps = [
            "Extract complete raw HTTP request payload and headers for signature analysis.",
            "Check web root and temporary directories (/tmp, /var/tmp) for web shells or droppers.",
            "Review database audit trails for unauthorized table extraction."
        ]
        long_term_hardening = [
            "Apply latest vendor security patch updates.",
            "Deploy Web Application Firewall (WAF) in blocking mode.",
            "Implement parameterized SQL queries and strict input schema validation."
        ]

    elif "RANSOMWARE" in event_type or "MALWARE" in event_type:
        risk_score = 98
        classification = "Impact / Ransomware & Malicious Code Execution"
        confidence = 0.97
        summary = f"High-velocity file modification or malicious binary activity detected on {target}. Immediate containment required to prevent enterprise data destruction."
        observed_facts = [
            f"High-frequency file system modifications or process execution anomalies on {target}.",
            f"Alert triggered with severity {severity}."
        ]
        ai_inference = [
            "High probability of ransomware payload or malicious dropper execution.",
            "Adversary may attempt lateral propagation across SMB shares and domain controllers."
        ]
        immediate_response = [
            f"Immediately disconnect {target} from the corporate network.",
            "Verify that immutable backup repositories are air-gapped and intact.",
            "Suspend affected user accounts and invalidate Kerberos golden tickets."
        ]
        investigation_steps = [
            "Acquire memory dump and disk forensic image from affected host.",
            "Identify initial infection vector (phishing attachment, web exploit, or RDP brute force).",
            "Trace parent process trees and scheduled tasks/registry run keys."
        ]
        long_term_hardening = [
            "Enforce Endpoint Detection and Response (EDR) in active prevention mode.",
            "Restrict SMBv1/v2 lateral communications between client workstations.",
            "Implement AppLocker / Software Restriction Policies for script execution."
        ]

    elif "PORT_SCAN" in event_type or "ENUMERATION" in event_type:
        risk_score = 45 if severity == "LOW" else 65
        classification = "Discovery / Network Reconnaissance"
        confidence = 0.89
        summary = f"Port scanning or service enumeration activity detected from {src_ip}. Adversary is mapping open ports and fingerprinting network services."
        observed_facts = [
            f"Multiple connection attempts across various TCP/UDP ports targeting {target}.",
            f"Source identifier: {src_ip}."
        ]
        ai_inference = [
            "Reconnaissance phase of cyber kill chain; adversary is seeking vulnerable entry points.",
            "May precede targeted exploit attempts against identified open listening ports."
        ]
        immediate_response = [
            f"Verify that firewall access control lists (ACLs) restrict non-essential ports on {target}.",
            f"Monitor {src_ip} for follow-up exploit attempts."
        ]
        investigation_steps = [
            "Identify all responding open ports on the target host.",
            "Check if any exposed services have known unpatched vulnerabilities (CISA KEV / NVD)."
        ]
        long_term_hardening = [
            "Close unneeded public-facing listening ports.",
            "Implement network segmentation and internal honeypots/canary tokens."
        ]

    else:
        risk_score = 60
        classification = f"Security Telemetry / {event_type}"
        confidence = 0.85
        summary = f"Security anomaly {event_type} observed on {target} from source {src_ip}."
        observed_facts = [
            f"Event type {event_type} logged with severity {severity}.",
            f"Target: {target}, Source: {src_ip}."
        ]
        ai_inference = [
            "Telemetry anomaly requires verification against baseline system behavior."
        ]
        immediate_response = [
            "Review recent configuration changes and system access records.",
            "Verify whether the reported activity matches planned maintenance."
        ]
        investigation_steps = [
            "Correlate with adjacent host and firewall telemetry.",
            "Check vulnerability intelligence status for affected host services."
        ]
        long_term_hardening = [
            "Maintain continuous SOC log monitoring and least-privilege access."
        ]

    return AnalysisResponse(
        risk_score=risk_score,
        risk_level=severity if severity in ("CRITICAL", "HIGH", "MEDIUM", "LOW") else "HIGH",
        classification=classification,
        confidence=confidence,
        summary=summary,
        observed_facts=observed_facts,
        ai_inference=ai_inference,
        mitre_technique=mitre_tech,
        affected_assets=affected_assets,
        immediate_response=immediate_response,
        investigation_steps=investigation_steps,
        long_term_hardening=long_term_hardening,
        source="Sentinel AI Defensive Engine (Rule-based Expert)",
        generated_at=datetime.now(timezone.utc).isoformat()
    )


async def analyze_incident(data: Dict[str, Any]) -> Dict[str, Any]:
    """
    Perform deep defensive analysis on a security event or incident.
    Seamlessly uses configured LLM provider or expert defensive heuristic engine.
    """
    api_key = os.getenv("AI_API_KEY")
    api_base_url = os.getenv("AI_API_BASE_URL")
    ai_model = os.getenv("AI_MODEL", "gpt-3.5-turbo")

    # If no LLM credentials configured, immediately return rich expert rule-based analysis
    if not api_key or not api_base_url:
        expert_res = _generate_expert_defensive_analysis(data)
        return expert_res.model_dump()

    # If LLM configured, prompt defensively with strict JSON schema
    prompt = f"""
You are Sentinel AI, an expert defensive cybersecurity analyst in a SOC.
Analyze the following security telemetry defensively and return a strictly valid JSON response:
Telemetry Data:
{json.dumps(data)}

Required JSON Schema:
{{
  "risk_score": <integer between 0 and 100>,
  "risk_level": "<CRITICAL|HIGH|MEDIUM|LOW>",
  "classification": "<string classification>",
  "confidence": <float between 0.0 and 1.0>,
  "summary": "<concise defensive summary>",
  "observed_facts": ["<fact 1>", "<fact 2>"],
  "ai_inference": ["<inference 1>", "<inference 2>"],
  "immediate_response": ["<step 1>", "<step 2>"],
  "investigation_steps": ["<step 1>", "<step 2>"],
  "long_term_hardening": ["<step 1>", "<step 2>"]
}}
Do NOT include any offensive instructions or markdown formatting. Output raw JSON only.
"""

    payload = {
        "model": ai_model,
        "messages": [
            {"role": "system", "content": "You are a defensive cybersecurity analyst. Provide only defensive, defensive-engineering recommendations and structured JSON."},
            {"role": "user", "content": prompt}
        ],
        "temperature": 0.2
    }
    headers = {"Authorization": f"Bearer {api_key}", "Content-Type": "application/json"}

    try:
        async with httpx.AsyncClient(timeout=15) as client:
            resp = await client.post(api_base_url, json=payload, headers=headers)
            resp.raise_for_status()
            res_json = resp.json()

        content = res_json["choices"][0]["message"]["content"]
        # Strip markdown ticks if present
        if content.startswith("```json"):
            content = content[7:]
        if content.startswith("```"):
            content = content[3:]
        if content.endswith("```"):
            content = content[:-3]

        parsed = json.loads(content.strip())
        parsed["source"] = f"Sentinel AI LLM ({ai_model})"
        parsed["generated_at"] = datetime.now(timezone.utc).isoformat()
        parsed["mitre_technique"] = map_event_to_mitre(data.get("event_type", ""))

        return parsed
    except Exception as exc:
        logger.warning(f"External LLM API analysis failed ({exc}). Falling back to Expert Defensive Engine.")
        fallback = _generate_expert_defensive_analysis(data)
        res = fallback.model_dump()
        res["source"] = "Sentinel AI Defensive Engine (Fallback)"
        return res

