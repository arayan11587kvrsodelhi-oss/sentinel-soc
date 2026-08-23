"""
NVD (National Vulnerability Database) Intelligence Service
Fetches, enriches, caches, and cross-references NIST NVD CVE data with CISA KEV intelligence.
"""
import os
import time
import logging
from typing import Dict, Any, List, Optional
import httpx
from datetime import datetime, timezone, timedelta

from app.services.cisa_service import get_kev_dict
from app.models.schemas import VulnerabilityItem, KevDetails

logger = logging.getLogger("sentinel.nvd")

NVD_URL = "https://services.nvd.nist.gov/rest/json/cves/2.0"
CACHE_TTL_SECONDS = 1800  # 30 minutes cache

_nvd_cache: Dict[str, Any] = {
    "items": [],
    "last_fetched": 0,
    "last_updated": None,
    "data_source": "FALLBACK",
    "source": "NIST NVD + CISA KEV"
}

# Rich baseline CVE intelligence dataset with real CVEs and complete CVSS/CWE metadata
FALLBACK_NVD_DATA: List[Dict[str, Any]] = [
    {
        "id": "CVE-2024-3400",
        "description": "An OS command injection vulnerability in the GlobalProtect feature of Palo Alto Networks PAN-OS software enables an unauthenticated attacker to execute arbitrary code with root privileges on the firewall.",
        "cvss": 10.0,
        "severity": "CRITICAL",
        "published": "2024-04-12T17:15:51.000",
        "modified": "2024-04-16T18:15:08.000",
        "cwe": "CWE-78: OS Command Injection",
        "affected_products": ["Palo Alto Networks PAN-OS 10.2", "PAN-OS 11.0", "PAN-OS 11.1"],
        "references": [
            "https://nvd.nist.gov/vuln/detail/CVE-2024-3400",
            "https://security.paloaltonetworks.com/CVE-2024-3400"
        ],
        "is_kev": True,
        "kev_details": {
            "date_added": "2024-04-12",
            "due_date": "2024-04-19",
            "ransomware_use": "Known",
            "short_description": "Palo Alto Networks PAN-OS contains an OS command injection vulnerability in GlobalProtect."
        },
        "source": "NVD + CISA KEV"
    },
    {
        "id": "CVE-2024-21887",
        "description": "A command injection vulnerability in web components of Ivanti Connect Secure (9.x, 22.x) and Ivanti Policy Secure allows an authenticated administrator to send specially crafted requests and execute arbitrary commands on the appliance.",
        "cvss": 9.1,
        "severity": "CRITICAL",
        "published": "2024-01-12T01:15:09.000",
        "modified": "2024-01-30T19:15:10.000",
        "cwe": "CWE-78: OS Command Injection",
        "affected_products": ["Ivanti Connect Secure 9.x", "Ivanti Connect Secure 22.x", "Ivanti Policy Secure"],
        "references": [
            "https://nvd.nist.gov/vuln/detail/CVE-2024-21887",
            "https://forums.ivanti.com/s/article/KB-CVE-2023-46805-CVE-2024-21887"
        ],
        "is_kev": True,
        "kev_details": {
            "date_added": "2024-01-10",
            "due_date": "2024-01-22",
            "ransomware_use": "Known",
            "short_description": "Ivanti Connect Secure Command Injection Vulnerability"
        },
        "source": "NVD + CISA KEV"
    },
    {
        "id": "CVE-2024-1709",
        "description": "ConnectWise ScreenConnect 23.9.7 and prior are vulnerable to an authentication bypass using an alternate path or channel, which may allow an attacker with network access to the management interface to create admin accounts and execute remote code.",
        "cvss": 10.0,
        "severity": "CRITICAL",
        "published": "2024-02-21T16:15:49.000",
        "modified": "2024-03-01T20:15:08.000",
        "cwe": "CWE-288: Authentication Bypass Using an Alternate Path or Channel",
        "affected_products": ["ConnectWise ScreenConnect <= 23.9.7"],
        "references": [
            "https://nvd.nist.gov/vuln/detail/CVE-2024-1709",
            "https://www.huntress.com/blog/slashandgrab-screenconnect-vulnerability"
        ],
        "is_kev": True,
        "kev_details": {
            "date_added": "2024-02-22",
            "due_date": "2024-02-29",
            "ransomware_use": "Known",
            "short_description": "ConnectWise ScreenConnect Authentication Bypass"
        },
        "source": "NVD + CISA KEV"
    },
    {
        "id": "CVE-2023-46805",
        "description": "An authentication bypass vulnerability in the web components of Ivanti Connect Secure and Policy Secure allows a remote attacker to access restricted resources by bypassing control checks.",
        "cvss": 8.2,
        "severity": "HIGH",
        "published": "2024-01-12T01:15:08.000",
        "modified": "2024-01-30T19:15:09.000",
        "cwe": "CWE-287: Improper Authentication",
        "affected_products": ["Ivanti Connect Secure", "Ivanti Policy Secure"],
        "references": [
            "https://nvd.nist.gov/vuln/detail/CVE-2023-46805"
        ],
        "is_kev": True,
        "kev_details": {
            "date_added": "2024-01-10",
            "due_date": "2024-01-22",
            "ransomware_use": "Known",
            "short_description": "Ivanti Connect Secure Authentication Bypass"
        },
        "source": "NVD + CISA KEV"
    },
    {
        "id": "CVE-2023-34362",
        "description": "In Progress MOVEit Transfer before 2021.0.6, 2021.1.5, 2022.0.4, 2022.1.5, 2023.0.1, a SQL injection vulnerability in the MOVEit Transfer web application could allow an unauthenticated attacker to gain unauthorized access to the database.",
        "cvss": 9.8,
        "severity": "CRITICAL",
        "published": "2023-06-02T14:15:09.000",
        "modified": "2023-06-16T18:15:07.000",
        "cwe": "CWE-89: SQL Injection",
        "affected_products": ["Progress MOVEit Transfer < 2023.0.1"],
        "references": [
            "https://nvd.nist.gov/vuln/detail/CVE-2023-34362"
        ],
        "is_kev": True,
        "kev_details": {
            "date_added": "2023-06-02",
            "due_date": "2023-06-16",
            "ransomware_use": "Known",
            "short_description": "MOVEit Transfer SQL Injection Vulnerability"
        },
        "source": "NVD + CISA KEV"
    },
    {
        "id": "CVE-2023-22515",
        "description": "Atlassian Confluence Data Center and Server contain a broken access control vulnerability in version 8.0.0 through 8.5.1 that allows an unauthenticated attacker to create unauthorized admin accounts and gain access to Confluence instances.",
        "cvss": 10.0,
        "severity": "CRITICAL",
        "published": "2023-10-04T22:15:09.000",
        "modified": "2023-10-18T14:15:11.000",
        "cwe": "CWE-284: Improper Access Control",
        "affected_products": ["Atlassian Confluence Data Center 8.0.0 - 8.5.1"],
        "references": [
            "https://nvd.nist.gov/vuln/detail/CVE-2023-22515"
        ],
        "is_kev": True,
        "kev_details": {
            "date_added": "2023-10-05",
            "due_date": "2023-10-12",
            "ransomware_use": "Known",
            "short_description": "Confluence Broken Access Control Vulnerability"
        },
        "source": "NVD + CISA KEV"
    },
    {
        "id": "CVE-2021-44228",
        "description": "Apache Log4j2 versions 2.0-beta9 to 2.14.1 JNDI features used in configuration, log messages, and parameters do not protect against attacker controlled LDAP and other JNDI related endpoints (Log4Shell).",
        "cvss": 10.0,
        "severity": "CRITICAL",
        "published": "2021-12-10T10:15:08.000",
        "modified": "2023-11-07T03:39:27.000",
        "cwe": "CWE-502: Deserialization of Untrusted Data",
        "affected_products": ["Apache Log4j 2.0-beta9 - 2.14.1"],
        "references": [
            "https://nvd.nist.gov/vuln/detail/CVE-2021-44228"
        ],
        "is_kev": True,
        "kev_details": {
            "date_added": "2021-12-10",
            "due_date": "2021-12-24",
            "ransomware_use": "Known",
            "short_description": "Log4j2 JNDI Remote Code Execution Vulnerability"
        },
        "source": "NVD + CISA KEV"
    },
    {
        "id": "CVE-2023-38606",
        "description": "An issue in Apple macOS and iOS kernel allowed a malicious app to modify sensitive kernel state. Apple addressed this issue with improved state management.",
        "cvss": 7.8,
        "severity": "HIGH",
        "published": "2023-07-24T22:15:12.000",
        "modified": "2023-08-03T16:15:10.000",
        "cwe": "CWE-20: Improper Input Validation",
        "affected_products": ["Apple iOS < 16.6", "macOS Ventura < 13.5"],
        "references": [
            "https://nvd.nist.gov/vuln/detail/CVE-2023-38606"
        ],
        "is_kev": False,
        "kev_details": None,
        "source": "NVD"
    },
    {
        "id": "CVE-2024-27198",
        "description": "JetBrains TeamCity before 2023.11.4 contains an authentication bypass vulnerability allowing unauthenticated remote code execution and administrative takeover.",
        "cvss": 9.8,
        "severity": "CRITICAL",
        "published": "2024-03-04T12:15:10.000",
        "modified": "2024-03-11T14:15:00.000",
        "cwe": "CWE-288: Authentication Bypass",
        "affected_products": ["JetBrains TeamCity < 2023.11.4"],
        "references": ["https://nvd.nist.gov/vuln/detail/CVE-2024-27198"],
        "is_kev": True,
        "kev_details": {
            "date_added": "2024-03-07",
            "due_date": "2024-03-14",
            "ransomware_use": "Known",
            "short_description": "TeamCity Authentication Bypass Vulnerability"
        },
        "source": "NVD + CISA KEV"
    },
    {
        "id": "CVE-2024-23897",
        "description": "Jenkins 2.441 and earlier, LTS 2.426.2 and earlier CLI uses args4j parser which resolves file paths preceded by @ character, allowing unauthenticated attackers to read arbitrary files from the Jenkins controller file system.",
        "cvss": 9.8,
        "severity": "CRITICAL",
        "published": "2024-01-24T18:15:08.000",
        "modified": "2024-02-15T15:15:09.000",
        "cwe": "CWE-22: Path Traversal",
        "affected_products": ["Jenkins core < 2.442", "Jenkins LTS < 2.426.3"],
        "references": ["https://nvd.nist.gov/vuln/detail/CVE-2024-23897"],
        "is_kev": True,
        "kev_details": {
            "date_added": "2024-01-30",
            "due_date": "2024-02-13",
            "ransomware_use": "Known",
            "short_description": "Jenkins CLI Arbitrary File Read Vulnerability"
        },
        "source": "NVD + CISA KEV"
    }
]


def _calculate_severity(score: Optional[float]) -> str:
    if score is None:
        return "MEDIUM"
    if score >= 9.0:
        return "CRITICAL"
    if score >= 7.0:
        return "HIGH"
    if score >= 4.0:
        return "MEDIUM"
    if score > 0.0:
        return "LOW"
    return "INFO"


def _extract_cwe(cve_dict: Dict[str, Any]) -> Optional[str]:
    weaknesses = cve_dict.get("weaknesses", [])
    for w in weaknesses:
        for desc in w.get("description", []):
            val = desc.get("value", "")
            if val and not val.startswith("NVD-"):
                return val
    return None


def _extract_products(cve_dict: Dict[str, Any]) -> List[str]:
    products = []
    configurations = cve_dict.get("configurations", [])
    for config in configurations:
        for node in config.get("nodes", []):
            for cpe_match in node.get("cpeMatch", []):
                criteria = cpe_match.get("criteria", "")
                if criteria:
                    parts = criteria.split(":")
                    if len(parts) >= 5:
                        vendor = parts[3].capitalize()
                        prod = parts[4].replace("_", " ").capitalize()
                        label = f"{vendor} {prod}"
                        if label not in products:
                            products.append(label)
    return products[:5]


def _extract_references(cve_dict: Dict[str, Any]) -> List[str]:
    refs = cve_dict.get("references", [])
    return [r.get("url") for r in refs if r.get("url")][:5]


async def fetch_recent_cves(
    force: bool = False,
    search: Optional[str] = None,
    severity: Optional[str] = None,
    kev_only: bool = False,
    limit: int = 25,
    offset: int = 0
) -> Dict[str, Any]:
    """
    Fetch and return enriched CVE records from NVD + CISA KEV.
    Caches live data and seamlessly falls back to rich dataset on NVD rate limit / outage.
    """
    now = time.time()
    kev_dict = await get_kev_dict()

    if force or not _nvd_cache["items"] or (now - _nvd_cache["last_fetched"]) > CACHE_TTL_SECONDS:
        headers = {}
        if os.getenv("NVD_API_KEY"):
            headers["apiKey"] = os.getenv("NVD_API_KEY")

        try:
            # Query recent CVEs (resultsPerPage 30)
            async with httpx.AsyncClient(timeout=12) as client:
                resp = await client.get(
                    NVD_URL,
                    params={"resultsPerPage": 30},
                    headers=headers
                )
                resp.raise_for_status()
                data = resp.json()

            parsed_items = []
            for item in data.get("vulnerabilities", []):
                cve = item.get("cve", {})
                cve_id = cve.get("id", "")
                if not cve_id:
                    continue

                desc = next((d.get("value", "") for d in cve.get("descriptions", []) if d.get("lang") == "en"), "")
                metrics = cve.get("metrics", {})
                cvss_score = None

                for key in ("cvssMetricV40", "cvssMetricV31", "cvssMetricV30", "cvssMetricV2"):
                    if metrics.get(key) and len(metrics[key]) > 0:
                        cvss_score = metrics[key][0].get("cvssData", {}).get("baseScore")
                        if cvss_score is not None:
                            break

                cwe = _extract_cwe(cve)
                prods = _extract_products(cve)
                refs = _extract_references(cve)
                in_kev = cve_id in kev_dict
                kev_data = kev_dict.get(cve_id)
                kev_meta = None
                if kev_data:
                    kev_meta = {
                        "date_added": kev_data.get("dateAdded"),
                        "due_date": kev_data.get("dueDate"),
                        "ransomware_use": kev_data.get("knownRansomwareCampaignUse", "Known"),
                        "short_description": kev_data.get("shortDescription")
                    }

                parsed_items.append({
                    "id": cve_id,
                    "description": desc or "No description provided by NVD.",
                    "cvss": cvss_score,
                    "severity": _calculate_severity(cvss_score),
                    "published": cve.get("published"),
                    "modified": cve.get("lastModified"),
                    "cwe": cwe,
                    "affected_products": prods,
                    "references": refs,
                    "is_kev": in_kev,
                    "kev_details": kev_meta,
                    "source": "NVD + CISA KEV" if in_kev else "NVD"
                })

            if parsed_items:
                # Merge with fallback high-severity items so critical KEV items are always visible
                cve_ids = {p["id"].strip().upper() for p in parsed_items}
                for fb in FALLBACK_NVD_DATA:
                    if fb["id"].strip().upper() not in cve_ids:
                        parsed_items.append(fb)

                _nvd_cache["items"] = parsed_items
                _nvd_cache["last_fetched"] = now
                _nvd_cache["data_source"] = "LIVE_NVD"
                _nvd_cache["last_updated"] = datetime.now(timezone.utc).isoformat()
                logger.info(f"Updated NVD cache with {len(parsed_items)} CVE records.")

        except Exception as exc:
            logger.warning(f"NVD API request failed ({exc}). Serving resilient baseline intelligence.")
            if not _nvd_cache["items"]:
                _nvd_cache["items"] = list(FALLBACK_NVD_DATA)
                _nvd_cache["last_fetched"] = now
                _nvd_cache["data_source"] = "FALLBACK"
                _nvd_cache["last_updated"] = datetime.now(timezone.utc).isoformat()
            else:
                _nvd_cache["data_source"] = "CACHED_NVD"

    # Apply filters
    records = _nvd_cache["items"] or list(FALLBACK_NVD_DATA)
    current_data_source = _nvd_cache.get("data_source", "CACHED_NVD")
    if not _nvd_cache["last_fetched"]:
        current_data_source = "FALLBACK"

    # Re-verify KEV enrichment on cached items
    for item in records:
        cve_id = item["id"].strip().upper()
        if cve_id in kev_dict:
            item["is_kev"] = True
            k = kev_dict[cve_id]
            item["kev_details"] = {
                "date_added": k.get("dateAdded"),
                "due_date": k.get("dueDate"),
                "ransomware_use": k.get("knownRansomwareCampaignUse", "Known"),
                "short_description": k.get("shortDescription")
            }
            item["source"] = "NVD + CISA KEV"

    if search:
        s = search.lower()
        records = [
            r for r in records
            if s in r.get("id", "").lower()
            or s in r.get("description", "").lower()
            or (r.get("cwe") and s in r.get("cwe", "").lower())
            or any(s in str(p).lower() for p in r.get("affected_products", []))
        ]

    if severity:
        records = [r for r in records if r.get("severity", "").upper() == severity.upper()]

    if kev_only:
        records = [r for r in records if r.get("is_kev") is True]

    # Sort critical / highest CVSS first
    records = sorted(
        records,
        key=lambda x: (
            1 if x.get("is_kev") else 0,
            x.get("cvss") or 0.0,
            x.get("published") or ""
        ),
        reverse=True
    )

    total_count = len(records)
    paginated_records = records[offset: offset + limit]

    return {
        "source": "NIST National Vulnerability Database + CISA KEV",
        "data_source": current_data_source,
        "total": total_count,
        "cached": (time.time() - _nvd_cache["last_fetched"]) < CACHE_TTL_SECONDS,
        "last_updated": _nvd_cache["last_updated"] or datetime.now(timezone.utc).isoformat(),
        "vulnerabilities": paginated_records
    }

