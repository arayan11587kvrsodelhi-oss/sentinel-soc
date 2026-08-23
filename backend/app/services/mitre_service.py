"""
MITRE ATT&CK Service
Comprehensive mappings and helper lookups for Enterprise ATT&CK framework tactics and techniques.
"""
from typing import Optional, Dict, Any
from app.models.schemas import MitreTechnique

MITRE_TECHNIQUES: Dict[str, MitreTechnique] = {
    "T1110": MitreTechnique(
        id="T1110",
        name="Brute Force",
        tactic="Credential Access",
        description="Adversaries may use brute force techniques to attempt authentication by guessing passwords or hashes.",
        url="https://attack.mitre.org/techniques/T1110/"
    ),
    "T1110.001": MitreTechnique(
        id="T1110.001",
        name="Password Spraying",
        tactic="Credential Access",
        description="Adversaries may use a single or small list of commonly used passwords against many different accounts.",
        url="https://attack.mitre.org/techniques/T1110/001/"
    ),
    "T1046": MitreTechnique(
        id="T1046",
        name="Network Service Discovery",
        tactic="Discovery",
        description="Adversaries may attempt to get a listing of services running on remote hosts to find vulnerable targets.",
        url="https://attack.mitre.org/techniques/T1046/"
    ),
    "T1190": MitreTechnique(
        id="T1190",
        name="Exploit Public-Facing Application",
        tactic="Initial Access",
        description="Adversaries may attempt to exploit vulnerabilities in Internet-facing software to gain initial execution access.",
        url="https://attack.mitre.org/techniques/T1190/"
    ),
    "T1078": MitreTechnique(
        id="T1078",
        name="Valid Accounts",
        tactic="Defense Evasion, Persistence",
        description="Adversaries may obtain and abuse credentials of existing accounts as a means of gaining access or evading detection.",
        url="https://attack.mitre.org/techniques/T1078/"
    ),
    "T1068": MitreTechnique(
        id="T1068",
        name="Exploitation for Privilege Escalation",
        tactic="Privilege Escalation",
        description="Adversaries may exploit software vulnerabilities in an elevated service or kernel to elevate access levels.",
        url="https://attack.mitre.org/techniques/T1068/"
    ),
    "T1486": MitreTechnique(
        id="T1486",
        name="Data Encrypted for Impact",
        tactic="Impact",
        description="Adversaries may encrypt data on target systems or filesystems to interrupt the availability of system and network resources.",
        url="https://attack.mitre.org/techniques/T1486/"
    ),
    "T1041": MitreTechnique(
        id="T1041",
        name="Exfiltration Over C2 Channel",
        tactic="Exfiltration",
        description="Adversaries may steal data by exfiltrating it over an existing Command and Control channel.",
        url="https://attack.mitre.org/techniques/T1041/"
    ),
    "T1059.001": MitreTechnique(
        id="T1059.001",
        name="Command and Scripting Interpreter: PowerShell",
        tactic="Execution",
        description="Adversaries may abuse PowerShell commands and scripts for execution and evasion.",
        url="https://attack.mitre.org/techniques/T1059/001/"
    ),
    "T1071.001": MitreTechnique(
        id="T1071.001",
        name="Application Layer Protocol: Web Protocols",
        tactic="Command and Control",
        description="Adversaries may communicate using application layer protocols associated with web traffic (HTTP/HTTPS).",
        url="https://attack.mitre.org/techniques/T1071/001/"
    ),
    "T1003": MitreTechnique(
        id="T1003",
        name="OS Credential Dumping",
        tactic="Credential Access",
        description="Adversaries may dump credentials from the operating system memory or security stores (e.g., LSASS).",
        url="https://attack.mitre.org/techniques/T1003/"
    ),
    "T1566": MitreTechnique(
        id="T1566",
        name="Phishing",
        tactic="Initial Access",
        description="Adversaries may send phishing messages with malicious attachments or links to gain execution.",
        url="https://attack.mitre.org/techniques/T1566/"
    ),
}

EVENT_TYPE_TO_MITRE: Dict[str, str] = {
    "BRUTE_FORCE": "T1110",
    "LOGIN_FAILURE": "T1110.001",
    "PORT_SCAN": "T1046",
    "SERVICE_ENUMERATION": "T1046",
    "EXPLOIT_ATTEMPT": "T1190",
    "WEB_ATTACK": "T1190",
    "SQL_INJECTION": "T1190",
    "SUSPICIOUS_LOGIN": "T1078",
    "PRIVILEGE_ESCALATION": "T1068",
    "MALWARE_ALERT": "T1059.001",
    "RANSOMWARE_ACTIVITY": "T1486",
    "DATA_EXFILTRATION": "T1041",
    "C2_COMMUNICATION": "T1071.001",
    "CREDENTIAL_DUMP": "T1003",
}


def get_technique(technique_id: str) -> Optional[MitreTechnique]:
    """Retrieve MITRE technique details by ID."""
    return MITRE_TECHNIQUES.get(technique_id)


def map_event_to_mitre(event_type: str) -> Optional[MitreTechnique]:
    """Map a security event type string to corresponding MITRE technique."""
    tid = EVENT_TYPE_TO_MITRE.get(event_type.upper())
    if tid and tid in MITRE_TECHNIQUES:
        return MITRE_TECHNIQUES[tid]
    return None
