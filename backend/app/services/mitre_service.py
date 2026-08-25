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
    "T1595.002": MitreTechnique(
        id="T1595.002",
        name="Active Scanning: Vulnerability Scanning",
        tactic="Reconnaissance",
        description="Adversaries may scan for vulnerabilities in public-facing systems to identify exploitable attack vectors.",
        url="https://attack.mitre.org/techniques/T1595/002/"
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
    "T1055": MitreTechnique(
        id="T1055",
        name="Process Injection",
        tactic="Defense Evasion, Privilege Escalation",
        description="Adversaries may inject code into processes in order to evade process-based defenses and elevate privileges.",
        url="https://attack.mitre.org/techniques/T1055/"
    ),
    "T1021.002": MitreTechnique(
        id="T1021.002",
        name="Remote Services: SMB/Windows Admin Shares",
        tactic="Lateral Movement",
        description="Adversaries may leverage SMB and admin shares to interact with remote systems and execute code.",
        url="https://attack.mitre.org/techniques/T1021/002/"
    ),
    "T1562.001": MitreTechnique(
        id="T1562.001",
        name="Impair Defenses: Disable or Modify Tools",
        tactic="Defense Evasion",
        description="Adversaries may modify and disable security tools, such as antivirus and EDR, to avoid detection.",
        url="https://attack.mitre.org/techniques/T1562/001/"
    ),
    "T1486": MitreTechnique(
        id="T1486",
        name="Data Encrypted for Impact",
        tactic="Impact",
        description="Adversaries may encrypt data on target systems or filesystems to interrupt the availability of system and network resources.",
        url="https://attack.mitre.org/techniques/T1486/"
    ),
    "T1490": MitreTechnique(
        id="T1490",
        name="Inhibit System Recovery",
        tactic="Impact",
        description="Adversaries may delete or disable system recovery mechanisms, such as Volume Shadow Copies, to prevent restoration.",
        url="https://attack.mitre.org/techniques/T1490/"
    ),
    "T1041": MitreTechnique(
        id="T1041",
        name="Exfiltration Over C2 Channel",
        tactic="Exfiltration",
        description="Adversaries may steal data by exfiltrating it over an existing Command and Control channel.",
        url="https://attack.mitre.org/techniques/T1041/"
    ),
    "T1048": MitreTechnique(
        id="T1048",
        name="Exfiltration Over Alternative Protocol",
        tactic="Exfiltration",
        description="Adversaries may steal data by exfiltrating it over a different protocol or staging storage bucket.",
        url="https://attack.mitre.org/techniques/T1048/"
    ),
    "T1005": MitreTechnique(
        id="T1005",
        name="Data from Local System",
        tactic="Collection",
        description="Adversaries may search for and gather sensitive files and database records from target local systems.",
        url="https://attack.mitre.org/techniques/T1005/"
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
    "VULNERABILITY_SCAN": "T1595.002",
    "EXPLOIT_ATTEMPT": "T1190",
    "WEB_ATTACK": "T1190",
    "SQL_INJECTION": "T1190",
    "SUSPICIOUS_LOGIN": "T1078",
    "PRIVILEGE_ESCALATION": "T1068",
    "PROCESS_INJECTION": "T1055",
    "DEFENSE_EVASION": "T1562.001",
    "LATERAL_MOVEMENT": "T1021.002",
    "SMB_EXECUTION": "T1021.002",
    "POWERSHELL_EXECUTION": "T1059.001",
    "MALWARE_ALERT": "T1059.001",
    "RANSOMWARE_ACTIVITY": "T1486",
    "SHADOW_COPY_DELETION": "T1490",
    "DATA_STAGING": "T1005",
    "DATA_EXFILTRATION": "T1041",
    "OUTBOUND_TRANSFER": "T1048",
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
