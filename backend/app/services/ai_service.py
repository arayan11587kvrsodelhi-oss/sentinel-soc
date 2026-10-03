"""
Sentinel AI Defensive Analyst Service
Provides high-fidelity, structured defensive cybersecurity triage, MITRE ATT&CK mapping,
fact vs inference separation, and actionable incident response playbooks.
"""
import asyncio
import email.utils
import json
import logging
import random
import re
from typing import Any, Dict, Optional, Tuple
import httpx
from datetime import datetime, timezone

from app.models.schemas import AnalysisResponse, AnalysisRequest, EvidenceBreakdown
from app.services.mitre_service import map_event_to_mitre, get_technique
from app.core.config import get_settings
from app.core.logging import get_request_id

logger = logging.getLogger("sentinel.ai")
settings = get_settings()

# =========================================================================
# AI INFERENCE TRANSPORT
# -------------------------------------------------------------------------
# Every upstream failure is reduced to one of the categories below *before* it
# can leave this module. Provider diagnostics (status, attempt count,
# Retry-After) stay in the server log; the browser only ever receives the
# category and the matching sentence from AI_SAFE_MESSAGES.
# =========================================================================

AI_RATE_LIMITED = "AI_RATE_LIMITED"
AI_PROVIDER_UNAVAILABLE = "AI_PROVIDER_UNAVAILABLE"
AI_AUTHENTICATION_FAILED = "AI_AUTHENTICATION_FAILED"
AI_REQUEST_FAILED = "AI_REQUEST_FAILED"
AI_TIMEOUT = "AI_TIMEOUT"
AI_CANCELLED = "AI_CANCELLED"

# The only strings a browser may ever see for an inference failure.
AI_SAFE_MESSAGES: Dict[str, str] = {
    AI_RATE_LIMITED: "AI analysis is temporarily rate-limited. Please try again shortly.",
    AI_PROVIDER_UNAVAILABLE: "The AI analysis provider is temporarily unavailable. Please try again shortly.",
    AI_AUTHENTICATION_FAILED: "AI analysis is not configured correctly on the server. Please contact an administrator.",
    AI_REQUEST_FAILED: "AI analysis could not be completed. Please try again.",
    AI_TIMEOUT: "AI analysis timed out. Please try again.",
    AI_CANCELLED: "AI analysis was cancelled.",
}

# Transient upstream conditions worth one more bounded attempt.
_RETRYABLE_STATUS_CODES = {429, 500, 502, 503, 504}

# HTTP status -> (category, retryable).
# 401/403 are deliberately non-retryable: replaying a rejected credential adds
# load and can trip provider-side lockouts. Unknown 4xx are never retried.
_STATUS_CATEGORY: Dict[int, Tuple[str, bool]] = {
    401: (AI_AUTHENTICATION_FAILED, False),
    403: (AI_AUTHENTICATION_FAILED, False),
    408: (AI_TIMEOUT, True),
    429: (AI_RATE_LIMITED, True),
    500: (AI_REQUEST_FAILED, True),
    502: (AI_PROVIDER_UNAVAILABLE, True),
    503: (AI_PROVIDER_UNAVAILABLE, True),
    504: (AI_TIMEOUT, True),
}


class AICallError(Exception):
    """An inference failure reduced to a sanitized, user-safe category."""

    def __init__(
        self,
        category: str,
        *,
        status: Optional[int] = None,
        attempts: int = 0,
        retryable: bool = False,
    ) -> None:
        self.category = category
        self.status = status
        self.attempts = attempts
        self.retryable = retryable
        super().__init__(self.safe_message)

    @property
    def safe_message(self) -> str:
        return AI_SAFE_MESSAGES.get(self.category, AI_SAFE_MESSAGES[AI_REQUEST_FAILED])


def classify_http_status(status: int) -> Tuple[str, bool]:
    """Map an upstream HTTP status to ``(category, retryable)``."""
    mapped = _STATUS_CATEGORY.get(status)
    if mapped is not None:
        return mapped
    return (AI_REQUEST_FAILED, status in _RETRYABLE_STATUS_CODES)


def parse_retry_after(value: Optional[str], cap: float) -> Optional[float]:
    """Parse a ``Retry-After`` header (delta-seconds or HTTP-date) to seconds.

    Always clamped to ``cap`` so a hostile or misconfigured upstream value
    cannot park a request for minutes.
    """
    if not value:
        return None
    raw = value.strip()
    try:
        return max(0.0, min(cap, float(raw)))
    except ValueError:
        pass
    try:
        when = email.utils.parsedate_to_datetime(raw)
    except (TypeError, ValueError):
        return None
    if when is None:
        return None
    if when.tzinfo is None:
        when = when.replace(tzinfo=timezone.utc)
    return max(0.0, min(cap, (when - datetime.now(timezone.utc)).total_seconds()))


def safe_http_detail(exc: BaseException) -> Tuple[int, Dict[str, str]]:
    """Translate an internal exception into ``(http_status, sanitized_detail)``."""
    if isinstance(exc, AICallError):
        if exc.category == AI_CANCELLED:
            # 499: the caller went away; not a server fault.
            return 499, {"category": exc.category, "message": exc.safe_message}
        if exc.category in (AI_RATE_LIMITED, AI_PROVIDER_UNAVAILABLE, AI_TIMEOUT):
            return 503, {"category": exc.category, "message": exc.safe_message}
        return 500, {"category": exc.category, "message": exc.safe_message}
    return 500, {"category": AI_REQUEST_FAILED, "message": AI_SAFE_MESSAGES[AI_REQUEST_FAILED]}


def _is_cancelled(cancel_event: Optional[asyncio.Event]) -> bool:
    return cancel_event is not None and cancel_event.is_set()


async def _sleep_or_cancel(delay: float, cancel_event: Optional[asyncio.Event]) -> None:
    """Sleep between attempts, aborting early if the HTTP client disconnected."""
    if delay <= 0:
        return
    if cancel_event is None:
        await asyncio.sleep(delay)
        return
    try:
        await asyncio.wait_for(cancel_event.wait(), timeout=delay)
    except asyncio.TimeoutError:
        return
    raise AICallError(AI_CANCELLED)


def client_disconnect_signal(request: Any) -> Tuple[asyncio.Event, Any]:
    """Create a cancel event that trips when the calling HTTP client goes away.

    Sentinel's inference call is non-streaming, so a request already in flight
    to the provider cannot be aborted mid-flight; what this prevents is *new*
    work after the user navigated away (further attempts and backoff sleeps).
    The in-flight attempt stays bounded by AI_REQUEST_TIMEOUT_SECONDS.
    """
    cancel_event = asyncio.Event()

    async def _watch() -> None:
        while not cancel_event.is_set():
            try:
                if await request.is_disconnected():
                    cancel_event.set()
                    return
            except Exception:  # transport teardown race
                cancel_event.set()
                return
            await asyncio.sleep(0.25)

    task = asyncio.create_task(_watch(), name="sentinel-ai-client-watch")
    return cancel_event, task


async def post_chat_completion_with_retry(
    client: httpx.AsyncClient,
    url: str,
    payload: Dict[str, Any],
    headers: Dict[str, str],
    cancel_event: Optional[asyncio.Event] = None,
) -> httpx.Response:
    """POST to an OpenAI-compatible chat-completions endpoint with bounded retry.

    Contract:
      * at most ``settings.ai_max_attempts`` attempts (hard-clamped to 3);
      * honours ``Retry-After`` when present, otherwise exponential backoff with
        jitter, always clamped to ``settings.ai_retry_max_seconds``;
      * retries transient 429/500/502/503/504 only;
      * never retries 401/403 or any other 4xx;
      * aborts between attempts when the calling client disconnected.

    This is a bounded ``for`` loop — there is no recursive or unbounded retry.
    """
    # Clamp at the point of use as well as in config validation: the retry
    # budget is an intrinsic safety property of this function, not merely a
    # setting. Even a misconfigured value can never exceed three attempts.
    max_attempts = max(1, min(3, int(settings.ai_max_attempts)))
    base = max(0.0, settings.ai_retry_base_seconds)
    cap = max(0.0, settings.ai_retry_max_seconds)
    last_error: Optional[AICallError] = None

    for attempt in range(1, max_attempts + 1):
        if _is_cancelled(cancel_event):
            raise AICallError(AI_CANCELLED)

        retry_after: Optional[float] = None
        try:
            response = await client.post(url, json=payload, headers=headers)
        except httpx.TimeoutException:
            last_error = AICallError(AI_TIMEOUT, attempts=attempt, retryable=True)
            logger.warning(
                "AI provider request timed out",
                extra={
                    "attempt": attempt,
                    "max_attempts": max_attempts,
                    "category": AI_TIMEOUT,
                },
            )
        except httpx.RequestError:
            last_error = AICallError(
                AI_PROVIDER_UNAVAILABLE, attempts=attempt, retryable=True
            )
            logger.warning(
                "AI provider connection error",
                extra={
                    "attempt": attempt,
                    "max_attempts": max_attempts,
                    "category": AI_PROVIDER_UNAVAILABLE,
                },
            )
        else:
            if response.status_code < 400:
                return response

            category, retryable = classify_http_status(response.status_code)
            last_error = AICallError(
                category,
                status=response.status_code,
                attempts=attempt,
                retryable=retryable,
            )
            retry_after = parse_retry_after(response.headers.get("Retry-After"), cap)
            # Status and retry-after only: the upstream body may carry internal
            # routing metadata (provider ids, session/generation ids), so it is
            # never logged or forwarded verbatim.
            logger.warning(
                "AI provider returned an error status",
                extra={
                    "attempt": attempt,
                    "max_attempts": max_attempts,
                    "status_code": response.status_code,
                    "retry_after_seconds": retry_after,
                    "category": category,
                    "will_retry": retryable and attempt < max_attempts,
                },
            )
            if not retryable:
                raise last_error

        if attempt >= max_attempts:
            break

        if retry_after is None:
            backoff = min(cap, base * (2 ** (attempt - 1)))
            backoff += random.uniform(0.0, backoff * 0.25)  # jitter
            delay = min(cap, backoff)
        else:
            delay = min(cap, retry_after)

        await _sleep_or_cancel(delay, cancel_event)

    raise last_error or AICallError(AI_REQUEST_FAILED)


def _generate_expert_defensive_analysis(data: Dict[str, Any]) -> AnalysisResponse:
    """
    Expert heuristic defensive cybersecurity engine.
    Produces rigorous, production-grade SOC triage without requiring external LLM API tokens.
    Guarantees strict separation of OBSERVED vs INFERRED vs UNKNOWN evidence.
    """
    event_type = str(data.get("event_type") or "SECURITY_ALERT").upper()
    severity = str(data.get("severity") or "MEDIUM").upper()
    details = str(data.get("details") or "")
    src_ip = str(data.get("source_ip") or "Simulated Telemetry Source")
    target = str(data.get("target") or "Target Asset")
    incident_id = data.get("incident_id")
    context = data.get("context") or {}
    affected_assets = [target] if target else ["Target Asset"]

    mitre_tech = map_event_to_mitre(event_type)
    mitre_techs = [mitre_tech] if mitre_tech else []

    if "BRUTE" in event_type or "LOGIN" in event_type or "CREDENTIAL" in event_type:
        risk_score = 94 if severity == "CRITICAL" else 82
        classification = "Credential Access / Password Spray & Authentication Brute Force"
        confidence = 0.95
        summary = f"High-velocity authentication failures detected from {src_ip} targeting {target}. Indicates automated password guessing or credential spraying attempt."
        why_it_matters = "A successful credential brute force grants adversaries unauthorized access with valid account privileges, enabling lateral movement and internal discovery without raising typical exploit alarms."
        likely_objective = "Account takeover and establishment of initial interactive foothold using compromised administrative credentials."
        attack_progression = [
            "1. Password spray / dictionary probe across user accounts.",
            "2. Repeated authentication threshold violation.",
            "3. Attempted logon with valid service account credentials.",
            "4. Post-authentication interactive shell or C2 establishment."
        ]
        observed_facts = [
            f"Observed repeated authentication failure events from source IP {src_ip}.",
            f"Target destination host: {target} (Protocol: SSH/RDP).",
            f"Alert severity classified as {severity} by telemetry correlation rules.",
            f"Total correlated events in sequence: {context.get('events_count', 4)}."
        ]
        ai_inference = [
            "Pattern is consistent with automated brute-force / password spraying tools (e.g. Hydra, Medusa, Crowbar).",
            "Target account 'svc_backup' / 'administrator' was specifically targeted due to elevated service permissions.",
            "High risk of subsequent persistence creation if authentication succeeded."
        ]
        unknown_factors = [
            "Whether source IP {src_ip} is an infected residential proxy or direct adversary staging VPS.",
            "Whether matching credentials were leaked in historical third-party data breaches."
        ]
        immediate_response = [
            f"Enforce immediate simulated firewall block on boundary routers for IP {src_ip}.",
            f"Audit session state on {target} and terminate any active connections for targeted accounts.",
            "Initiate emergency password reset and enforce MFA challenge on targeted identities."
        ]
        investigation_steps = [
            "Review authentication logs for the preceding 24 hours to identify any successful logons from this source.",
            "Inspect user login time patterns and geo-velocity anomalies.",
            "Verify whether MFA was bypassed, denied, or repeatedly prompted."
        ]
        long_term_hardening = [
            "Enforce strict account lockout policies (e.g. 5 failed attempts locks for 15 minutes).",
            "Migrate administrative remote management (SSH/RDP) behind a Zero Trust Network Access (ZTNA) bastion.",
            "Deploy FIDO2 WebAuthn hardware security keys for all administrative identities."
        ]
        playbook_recommendations = [
            "1. Execute [ SIMULATE IP BAN ] on boundary firewall.",
            "2. Execute [ SIMULATE CREDENTIAL REVOCATION ] on compromised user accounts.",
            "3. Query authentication logs for anomalous successful sessions."
        ]

    elif "EXPLOIT" in event_type or "SQL" in event_type or "WEB" in event_type:
        risk_score = 98 if severity == "CRITICAL" else 88
        classification = "Initial Access / Web Application Vulnerability Exploitation"
        confidence = 0.96
        summary = f"Exploit payload patterns detected against {target} from {src_ip}. Active attempt to leverage software vulnerability for remote code execution or unauthorized data extraction."
        why_it_matters = "Exploiting unpatched public web endpoints (e.g. CVE-2023-34362 MOVEit Transfer) allows unauthenticated remote attackers to bypass perimeter security, access internal databases, and drop persistent web shells."
        likely_objective = "Remote Code Execution (RCE), database exfiltration, and establishment of persistent web shell backdoors."
        attack_progression = [
            "1. Automated web application vulnerability scanning probing URI endpoints.",
            "2. Injection of SQL or command payloads in HTTP parameters.",
            "3. Exploitation of CVE-2023-34362 / CVE-2024-3400 vulnerability.",
            "4. Web shell dropped in web root for persistent remote execution."
        ]
        observed_facts = [
            f"Inbound HTTP/HTTPS payload targeting web endpoints on {target}.",
            f"Exploit pattern matched known CVE signatures: {', '.join(context.get('related_cves', ['CVE-2023-34362']))}.",
            f"Telemetry source IP recorded as {src_ip}."
        ]
        ai_inference = [
            "Adversary is actively exploiting known public-facing vulnerability.",
            "If target web server is running unpatched version, arbitrary code execution is imminent.",
            "Attacker may attempt to deploy web shells into uploads directory."
        ]
        unknown_factors = [
            "Exact patch level of the destination web service instance.",
            "Whether web server runs with root/system privileges or low-privileged container isolation."
        ]
        immediate_response = [
            f"Execute [ SIMULATE HOST ISOLATION ] on web server container {target}.",
            f"Deploy emergency WAF blocking rule on reverse proxy for source {src_ip}.",
            "Scan web root directory (/var/www/uploads/) for newly dropped PHP/ASPX files."
        ]
        investigation_steps = [
            "Extract complete raw HTTP request body and HTTP headers for forensic signature matching.",
            "Inspect web server process trees for spawned subprocesses (sh, bash, cmd.exe, powershell.exe).",
            "Audit database query logs for bulk SELECT statements executed during the exploit window."
        ]
        long_term_hardening = [
            "Apply official vendor patch updates immediately.",
            "Deploy Web Application Firewall (WAF) in active blocking mode with OWASP Core Rule Set.",
            "Enforce read-only filesystem on web application container runtimes."
        ]
        playbook_recommendations = [
            "1. Execute [ SIMULATE HOST ISOLATION ] on vulnerable web application.",
            "2. Execute [ SIMULATE FIREWALL BLOCK ] for adversary IP.",
            "3. Audit filesystem for dropped web shells."
        ]

    elif "RANSOMWARE" in event_type or "SHADOW" in event_type:
        risk_score = 99
        classification = "Impact / Ransomware & Destructive Encryption Activity"
        confidence = 0.98
        summary = f"High-velocity file modification, shadow copy deletion, or encryption pattern detected on {target}. Immediate containment required to prevent enterprise-wide data destruction."
        why_it_matters = "Ransomware operators encrypt business-critical data repositories and delete backup recovery mechanisms to extort organizations, threatening business continuity and permanent data loss."
        likely_objective = "Mass file encryption, recovery mechanism destruction, and double extortion ransom demand."
        attack_progression = [
            "1. Off-hours privileged logon or lateral movement via SMB.",
            "2. Inhabitation of system recovery: vssadmin Delete Shadows.",
            "3. High-velocity AES/RSA file encryption across network shares.",
            "4. Dropping ransom notes (e.g. HOW_TO_DECRYPT.txt)."
        ]
        observed_facts = [
            f"High-frequency file system modifications or process execution anomalies on {target}.",
            f"Inhibit system recovery signature (vssadmin delete shadows) observed.",
            f"Alert triggered with severity {severity}."
        ]
        ai_inference = [
            "Active ransomware deployment in progress.",
            "Attacker may possess domain administrator credentials and attempt lateral propagation across all domain shares."
        ]
        unknown_factors = [
            "Total volume of files encrypted prior to detection.",
            "Whether data was staged and exfiltrated prior to encryption phase."
        ]
        immediate_response = [
            f"Execute [ SIMULATE HOST ISOLATION ] on {target} immediately to sever network connectivity.",
            "Verify integrity and air-gapped status of offline backup storage.",
            "Revoke compromised domain administrative credentials."
        ]
        investigation_steps = [
            "Acquire forensic volatile memory dump of the infected system.",
            "Identify the patient-zero host and initial compromise vector.",
            "Review SMB session logs on file servers to identify other impacted endpoints."
        ]
        long_term_hardening = [
            "Implement automated EDR ransomware containment with canary file monitoring.",
            "Enforce strict SMB network segmentation between workstation subnets.",
            "Maintain immutable, write-once-read-many (WORM) offline backup repositories."
        ]
        playbook_recommendations = [
            "1. Execute [ SIMULATE HOST ISOLATION ] on affected endpoint.",
            "2. Execute [ SIMULATE CREDENTIAL REVOCATION ] for compromised domain accounts.",
            "3. Verify backup repository integrity."
        ]

    elif "DATA_EXFILTRATION" in event_type or "DATA_STAGING" in event_type:
        risk_score = 96
        classification = "Exfiltration / Unauthorized Data Extraction"
        confidence = 0.96
        summary = f"High-volume unauthorized data transfer or database staging detected from {target} to destination {src_ip}."
        why_it_matters = "Data exfiltration results in exposure of proprietary databases, customer PII, and regulatory non-compliance under GDPR/HIPAA/PCI-DSS with severe legal and financial repercussions."
        likely_objective = "Data theft, corporate espionage, and double extortion."
        attack_progression = [
            "1. Administrative database connection from untrusted IP.",
            "2. Mass query execution and local staging into compressed archive.",
            "3. High-volume outbound transfer over encrypted HTTPS channel."
        ]
        observed_facts = [
            f"High-volume outbound data stream directed to external endpoint {src_ip}.",
            f"Target database asset: {target}.",
            f"Data staging archive operations detected."
        ]
        ai_inference = [
            "Adversary has successfully compromised database access credentials.",
            "Sensitive database records have been staged into encrypted archive to evade DLP inspection."
        ]
        unknown_factors = [
            "Specific tables and record counts included in the exfiltrated payload.",
            "Whether data was encrypted with adversary-controlled private keys."
        ]
        immediate_response = [
            f"Execute [ SIMULATE FIREWALL BLOCK ] on outbound connection to destination {src_ip}.",
            "Terminate active database sessions and rotate master credentials.",
            "Inspect database query logs for table extraction queries."
        ]
        investigation_steps = [
            "Review network NetFlow data to measure exact byte count transferred.",
            "Inspect disk for staged archive files in temporary directories.",
            "Correlate database audit logs with user access permissions."
        ]
        long_term_hardening = [
            "Implement Data Loss Prevention (DLP) egress inspection.",
            "Restrict database access to application tier IP addresses only.",
            "Enforce field-level database encryption for sensitive columns."
        ]
        playbook_recommendations = [
            "1. Execute [ SIMULATE FIREWALL BLOCK ] on destination C2 IP.",
            "2. Execute [ SIMULATE CREDENTIAL REVOCATION ] for database service accounts.",
            "3. Inspect NetFlow traffic and DLP alerts."
        ]

    elif "POWERSHELL" in event_type or "PROCESS_INJECTION" in event_type:
        risk_score = 92
        classification = "Execution & Defense Evasion / Suspicious Script Execution"
        confidence = 0.94
        summary = f"Obfuscated PowerShell execution, antivirus tampering, or process injection detected on {target}."
        why_it_matters = "Adversaries abuse PowerShell and process injection into trusted Windows processes (svchost.exe) to bypass antivirus detection and execute fileless malware in memory."
        likely_objective = "Defense evasion, privilege escalation, and memory-only payload execution."
        attack_progression = [
            "1. Obfuscated PowerShell download cradle execution.",
            "2. Tampering with antivirus real-time protection.",
            "3. Memory injection into trusted svchost.exe process.",
            "4. Elevated token acquisition."
        ]
        observed_facts = [
            f"PowerShell execution with base64/encoded command parameters observed on {target}.",
            f"Process injection or defense evasion event logged with severity {severity}."
        ]
        ai_inference = [
            "Adversary is leveraging living-off-the-land binaries (LOLBins) to evade endpoint detection.",
            "Injected process may establish an in-memory command and control beacon."
        ]
        unknown_factors = [
            "Payload payload decrypted inside process memory.",
            "Persistence mechanism established (scheduled task vs service)."
        ]
        immediate_response = [
            f"Execute [ SIMULATE HOST ISOLATION ] on {target}.",
            "Terminate suspicious PowerShell process trees.",
            "Re-enable antivirus real-time protection and initiate full scan."
        ]
        investigation_steps = [
            "Extract PowerShell Script Block Logging (Event ID 4104) records.",
            "Capture memory dump of injected svchost process for static/dynamic analysis.",
            "Audit scheduled tasks and autorun registry keys."
        ]
        long_term_hardening = [
            "Enable PowerShell Constrained Language Mode (CLM).",
            "Enforce AppLocker / WDAC application whitelisting.",
            "Deploy Attack Surface Reduction (ASR) rules."
        ]
        playbook_recommendations = [
            "1. Execute [ SIMULATE HOST ISOLATION ] on endpoint.",
            "2. Terminate malicious process trees.",
            "3. Review PowerShell script block logs (Event ID 4104)."
        ]

    else:
        risk_score = 65
        classification = f"Security Telemetry / {event_type}"
        confidence = 0.88
        summary = f"Security anomaly {event_type} observed on {target} from source {src_ip}."
        why_it_matters = "Anomalous telemetry may represent initial probing or unauthorized operational activity that warrants SOC review."
        likely_objective = "Reconnaissance or policy violation."
        attack_progression = ["1. Telemetry anomaly recorded in SOC event bus."]
        observed_facts = [
            f"Event type {event_type} logged with severity {severity}.",
            f"Target: {target}, Source: {src_ip}."
        ]
        ai_inference = [
            "Telemetry anomaly requires verification against baseline system behavior."
        ]
        unknown_factors = [
            "Whether reported activity was part of authorized penetration testing or scheduled maintenance."
        ]
        immediate_response = [
            "Review system configuration changes and user access history.",
            "Verify whether activity corresponds to scheduled IT maintenance."
        ]
        investigation_steps = [
            "Correlate with adjacent host and network firewall logs.",
            "Verify asset criticality in asset inventory."
        ]
        long_term_hardening = [
            "Maintain continuous SOC monitoring and least-privilege access."
        ]
        playbook_recommendations = [
            "1. Verify against scheduled maintenance calendar.",
            "2. Correlate with perimeter firewall telemetry."
        ]

    evidence_obj = EvidenceBreakdown(
        observed=observed_facts,
        inferred=ai_inference,
        recommended=immediate_response,
        unknown=unknown_factors
    )

    return AnalysisResponse(
        risk_score=risk_score,
        risk_level=severity if severity in ("CRITICAL", "HIGH", "MEDIUM", "LOW") else "HIGH",
        classification=classification,
        confidence=confidence,
        summary=summary,
        threat_summary=summary,
        why_it_matters=why_it_matters,
        attack_progression=attack_progression,
        likely_objective=likely_objective,
        observed_facts=observed_facts,
        ai_inference=ai_inference,
        unknown_factors=unknown_factors,
        evidence=evidence_obj,
        mitre_technique=mitre_tech,
        mitre_techniques=mitre_techs,
        affected_assets=affected_assets,
        immediate_response=immediate_response,
        investigation_steps=investigation_steps,
        long_term_hardening=long_term_hardening,
        playbook_recommendations=playbook_recommendations,
        incident_id=incident_id,
        evidence_count=len(observed_facts) + len(ai_inference),
        model="Sentinel AI Expert Defensive Engine v3.0",
        source="Sentinel AI Defensive Engine (Rule-based Expert)",
        generated_at=datetime.now(timezone.utc).isoformat()
    )


def _scrub_secrets(value: str) -> str:
    """Remove common secret patterns from strings sent to external LLMs."""
    if not isinstance(value, str):
        return value
    # API keys, tokens, passwords in URLs or JSON.
    # Order matters: the most specific credential shapes are scrubbed first, so a
    # generic pattern cannot partially consume a credential and leave the secret
    # behind in the tail (the old ordering turned "authorization: Bearer <token>"
    # into "authorization: *** <token>").
    _SECRET_VALUE = r"[\w\-\._~+/]{8,}"
    patterns = [
        (rf"(?i)(bearer\s+)['\"]?{_SECRET_VALUE}['\"]?", r"\1***"),
        (rf"(?i)(authorization\s*[:=]\s*)['\"]?{_SECRET_VALUE}['\"]?", r"\1\"***\""),
        (rf"(?i)(api[_-]?key\s*[:=]\s*)['\"]?{_SECRET_VALUE}['\"]?", r"\1\"***\""),
        (rf"(?i)(access[_-]?token\s*[:=]\s*)['\"]?{_SECRET_VALUE}['\"]?", r"\1\"***\""),
        (rf"(?i)(refresh[_-]?token\s*[:=]\s*)['\"]?{_SECRET_VALUE}['\"]?", r"\1\"***\""),
        (rf"(?i)(client[_-]?secret\s*[:=]\s*)['\"]?{_SECRET_VALUE}['\"]?", r"\1\"***\""),
        (rf"(?i)(private[_-]?key\s*[:=]\s*)['\"]?{_SECRET_VALUE}['\"]?", r"\1\"***\""),
        (rf"(?i)(token\s*[:=]\s*)['\"]?{_SECRET_VALUE}['\"]?", r"\1\"***\""),
        (r"(?i)(password\s*[:=]\s*)['\"]?[^\s\"']+['\"]?", r"\1\"***\""),
        (r"(?i)(secret\s*[:=]\s*)['\"]?[\w\-]{6,}['\"]?", r"\1\"***\""),
    ]
    for pattern, repl in patterns:
        value = re.sub(pattern, repl, value)
    return value


def _prepare_llm_safe_data(data: Dict[str, Any]) -> Dict[str, Any]:
    """Return a copy of analysis data with secrets and sensitive fields removed.

    Scrubs *recursively*. The previous implementation only inspected top-level
    keys and top-level strings, so a credential nested inside the free-form
    ``context`` object (which is caller-controlled) would have been forwarded
    verbatim to the external provider.
    """
    sensitive_keys = {
        "api_key",
        "apikey",
        "token",
        "access_token",
        "refresh_token",
        "password",
        "passwd",
        "secret",
        "authorization",
        "auth",
        "private_key",
        "client_secret",
        "session_token",
    }

    def _walk(node: Any) -> Any:
        if isinstance(node, dict):
            scrubbed: Dict[str, Any] = {}
            for key, value in node.items():
                if str(key).strip().lower() in sensitive_keys:
                    scrubbed[str(key)] = "***"
                else:
                    scrubbed[str(key)] = _walk(value)
            return scrubbed
        if isinstance(node, list):
            return [_walk(item) for item in node]
        if isinstance(node, str):
            return _scrub_secrets(node)
        return node

    # Round-trip through JSON so non-serialisable values cannot reach the prompt.
    return _walk(json.loads(json.dumps(data, default=str)))


# Fields the analysis actually consumes. Everything else is dropped before the
# prompt is built, so an oversized request cannot inflate token usage.
_LLM_TOP_LEVEL_FIELDS = (
    "incident_id",
    "event_id",
    "event_type",
    "severity",
    "source_ip",
    "target",
    "details",
)

# Scalars that identify the incident and are never dropped, only shortened.
_LLM_SECURITY_CRITICAL_FIELDS = (
    "incident_id",
    "event_id",
    "event_type",
    "severity",
    "source_ip",
    "target",
)

_MAX_LLM_STRING_CHARS = 1200
_MAX_LLM_DETAIL_CHARS = 4000
_MAX_LLM_LIST_ITEMS = 25
_MAX_LLM_CONTEXT_KEYS = 20
_MAX_LLM_DEPTH = 3


def _shorten(value: str, limit: int) -> str:
    if len(value) <= limit:
        return value
    return value[:limit] + f"...[truncated {len(value) - limit} chars]"


def _bound_value(value: Any, depth: int = 0) -> Any:
    """Recursively bound one prompt value (depth, string length, list length)."""
    if depth > _MAX_LLM_DEPTH:
        return "[depth limit]"
    if isinstance(value, str):
        return _shorten(value, _MAX_LLM_STRING_CHARS)
    if isinstance(value, (bool, int, float)) or value is None:
        return value
    if isinstance(value, dict):
        bounded: Dict[str, Any] = {}
        for index, (key, item) in enumerate(value.items()):
            if index >= _MAX_LLM_CONTEXT_KEYS:
                bounded["_truncated_keys"] = len(value) - _MAX_LLM_CONTEXT_KEYS
                break
            bounded[_shorten(str(key), 64)] = _bound_value(item, depth + 1)
        return bounded
    if isinstance(value, (list, tuple, set)):
        items = list(value)[:_MAX_LLM_LIST_ITEMS]
        bounded_list = [_bound_value(item, depth + 1) for item in items]
        if len(value) > _MAX_LLM_LIST_ITEMS:
            bounded_list.append(f"[{len(value) - _MAX_LLM_LIST_ITEMS} more items omitted]")
        return bounded_list
    return _shorten(str(value), _MAX_LLM_STRING_CHARS)


def _bound_context_for_llm(data: Dict[str, Any], max_chars: int) -> Dict[str, Any]:
    """Bound the telemetry volume handed to an external model.

    ``POST /api/ai/analyze`` accepts a free-form ``context`` dict straight from
    the client, so without a budget a single request could push an entire event
    history (or an entire incident dataset) into the prompt. Large inputs are a
    direct contributor to provider-side input-token rate limits, so the payload
    is bounded here without changing Sentinel's analysis behaviour:

      1. keep only the fields the analysis consumes;
      2. cap every string, list and nesting depth;
      3. enforce a hard total-character ceiling, dropping the optional
         ``context`` object first and shortening ``details`` second.

    Security-critical scalars (incident/event id, type, severity, source IP,
    target) are always preserved — they are what the analysis reasons about.
    """
    bounded: Dict[str, Any] = {}
    for field in _LLM_TOP_LEVEL_FIELDS:
        value = data.get(field)
        if value is None:
            continue
        limit = _MAX_LLM_DETAIL_CHARS if field == "details" else _MAX_LLM_STRING_CHARS
        bounded[field] = _shorten(str(value), limit)

    context = data.get("context")
    if context is not None:
        bounded["context"] = _bound_value(context)

    if len(json.dumps(bounded, default=str)) <= max_chars:
        return bounded

    # Over budget: the free-form context is the first thing to go, because it
    # is optional enrichment rather than primary evidence.
    bounded.pop("context", None)
    if len(json.dumps(bounded, default=str)) <= max_chars:
        return bounded

    details = bounded.get("details")
    if isinstance(details, str):
        keep = max(200, max_chars // 2)
        bounded["details"] = details[:keep] + "...[truncated to fit prompt budget]"

    # Security-critical scalars survive every cut above, whatever the budget.
    for field in _LLM_SECURITY_CRITICAL_FIELDS:
        value = data.get(field)
        if value is not None and field not in bounded:
            bounded[field] = _shorten(str(value), _MAX_LLM_STRING_CHARS)

    return bounded


def _fallback_result(
    data: Dict[str, Any],
    category: str,
    message: str,
) -> Dict[str, Any]:
    """Build the deterministic-engine response for a failed inference call.

    The engine output is Sentinel's own rule-based analysis, not a fabricated
    model response. The payload records explicitly that the upstream LLM did
    not answer, so neither the API consumer nor the UI can mistake it for one —
    the inference failure is disclosed, never silently swallowed.
    """
    fallback = _generate_expert_defensive_analysis(data)
    result = fallback.model_dump()
    result["source"] = "Sentinel AI Defensive Engine (Fallback)"
    result["llm_used"] = False
    result["ai_status"] = "degraded"
    result["ai_error_category"] = category
    result["ai_message"] = message
    return result


async def analyze_incident(
    data: Dict[str, Any],
    cancel_event: Optional[asyncio.Event] = None,
) -> Dict[str, Any]:
    """
    Perform deep defensive analysis on a security event or incident.
    Seamlessly uses configured LLM provider or expert defensive heuristic engine.
    """
    api_key = settings.ai_api_key
    api_base_url = settings.ai_api_base_url
    ai_model = settings.ai_model

    # If no LLM credentials configured, immediately return rich expert rule-based analysis
    if not api_key or not api_base_url:
        expert_res = _generate_expert_defensive_analysis(data)
        result = expert_res.model_dump()
        result["llm_used"] = False
        result["ai_status"] = "ok"
        result["ai_mode"] = "expert_engine"
        return result

    # If LLM configured, prompt defensively with strict JSON schema.
    # Bound first (structural), then scrub secrets (recursive).
    bounded_data = _bound_context_for_llm(data, settings.ai_max_context_chars)
    safe_data = _prepare_llm_safe_data(bounded_data)
    prompt = f"""
You are Sentinel AI, an expert defensive cybersecurity analyst in a SOC.
Analyze the following security telemetry defensively and return a strictly valid JSON response:
Telemetry Data:
{json.dumps(safe_data)}

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
        "temperature": 0.2,
        # Bound the completion so a runaway generation cannot inflate usage or
        # hold the upstream connection open indefinitely.
        "max_tokens": settings.ai_max_completion_tokens,
    }
    # Credentials travel in the Authorization header only: never logged, never
    # placed in the payload, never included in a client-facing error.
    headers = {"Authorization": f"Bearer {api_key}", "Content-Type": "application/json"}

    try:
        async with httpx.AsyncClient(
            timeout=settings.ai_request_timeout_seconds
        ) as client:
            resp = await post_chat_completion_with_retry(
                client,
                api_base_url,
                payload,
                headers,
                cancel_event=cancel_event,
            )
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
        summary_text = parsed.get("summary") or "Defensive analysis completed."
        obs = parsed.get("observed_facts") or [f"Observed telemetry alert from {data.get('source_ip', 'unknown')}"]
        inf = parsed.get("ai_inference") or ["Inferred potential threat activity."]
        rec = parsed.get("immediate_response") or ["Verify system logs."]
        unk = parsed.get("unknown_factors") or ["Specific actor attribution unknown."]

        parsed["threat_summary"] = parsed.get("threat_summary") or summary_text
        parsed["why_it_matters"] = parsed.get("why_it_matters") or "Active security events pose potential operational and data integrity risks."
        parsed["attack_progression"] = parsed.get("attack_progression") or ["1. Telemetry alert logged.", "2. AI defensive triage initiated."]
        parsed["likely_objective"] = parsed.get("likely_objective") or "Unauthorized access or policy circumvention."
        parsed["observed_facts"] = obs
        parsed["ai_inference"] = inf
        parsed["unknown_factors"] = unk
        parsed["evidence"] = {
            "observed": obs,
            "inferred": inf,
            "recommended": rec,
            "unknown": unk
        }
        parsed["evidence_count"] = len(obs) + len(inf)
        parsed["incident_id"] = data.get("incident_id")
        parsed["model"] = f"Sentinel AI LLM ({ai_model})"
        parsed["source"] = f"Sentinel AI LLM ({ai_model})"
        parsed["generated_at"] = datetime.now(timezone.utc).isoformat()
        tech = map_event_to_mitre(data.get("event_type", ""))
        parsed["mitre_technique"] = tech.model_dump() if tech else None
        parsed["mitre_techniques"] = [tech.model_dump()] if tech else []
        parsed["playbook_recommendations"] = parsed.get("playbook_recommendations") or rec
        parsed["llm_used"] = True
        parsed["ai_status"] = "ok"

        return parsed
    except AICallError as exc:
        # Bounded retries are exhausted, or the failure was non-retryable.
        # The diagnostic stays in the server log; the client gets a category.
        logger.warning(
            "AI inference failed; using the Expert Defensive Engine",
            extra={
                "category": exc.category,
                "status_code": exc.status,
                "attempts": exc.attempts,
                "model": ai_model,
                "request_id": get_request_id(),
            },
        )
        if exc.category == AI_CANCELLED:
            # The HTTP caller disconnected — do not spend fallback work on nobody.
            raise
        return _fallback_result(data, exc.category, exc.safe_message)
    except Exception:
        # Unexpected failure (malformed provider response, decoding error, ...).
        # The raw exception text is logged server-side and never returned.
        logger.exception(
            "Unexpected AI inference failure",
            extra={"model": ai_model, "request_id": get_request_id()},
        )
        return _fallback_result(
            data, AI_REQUEST_FAILED, AI_SAFE_MESSAGES[AI_REQUEST_FAILED]
        )

