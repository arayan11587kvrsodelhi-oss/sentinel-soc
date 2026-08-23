"""
CISA Known Exploited Vulnerabilities (KEV) Service
Fetches, caches, and indexes the official CISA KEV catalog.
"""
import os
import time
import logging
from typing import Dict, Any, List, Optional
import httpx
from datetime import datetime, timezone

logger = logging.getLogger("sentinel.cisa")

CISA_KEV_URL = "https://www.cisa.gov/sites/default/files/feeds/known_exploited_vulnerabilities.json"
CACHE_TTL_SECONDS = 3600  # 1 hour cache

_kev_cache: Dict[str, Any] = {
    "data": [],
    "dict": {},
    "total": 0,
    "last_fetched": 0,
    "last_updated": None,
    "data_source": "FALLBACK",
    "source": "CISA KEV Catalog"
}

FALLBACK_KEV_DATA = [
    {
        "cveID": "CVE-2024-3400",
        "vendorProject": "Palo Alto Networks",
        "product": "PAN-OS",
        "vulnerabilityName": "PAN-OS GlobalProtect Command Injection Vulnerability",
        "dateAdded": "2024-04-12",
        "shortDescription": "Palo Alto Networks PAN-OS contains an OS command injection vulnerability in GlobalProtect feature.",
        "requiredAction": "Apply mitigations per vendor instructions.",
        "dueDate": "2024-04-19",
        "knownRansomwareCampaignUse": "Known",
        "notes": "https://nvd.nist.gov/vuln/detail/CVE-2024-3400"
    },
    {
        "cveID": "CVE-2024-21887",
        "vendorProject": "Ivanti",
        "product": "Connect Secure and Policy Secure",
        "vulnerabilityName": "Ivanti Connect Secure Command Injection Vulnerability",
        "dateAdded": "2024-01-10",
        "shortDescription": "A command injection vulnerability in web components of Ivanti Connect Secure allows an authenticated administrator to execute arbitrary commands.",
        "requiredAction": "Apply vendor fixes immediately.",
        "dueDate": "2024-01-22",
        "knownRansomwareCampaignUse": "Known",
        "notes": "https://nvd.nist.gov/vuln/detail/CVE-2024-21887"
    },
    {
        "cveID": "CVE-2024-1709",
        "vendorProject": "ConnectWise",
        "product": "ScreenConnect",
        "vulnerabilityName": "ScreenConnect Authentication Bypass Vulnerability",
        "dateAdded": "2024-02-22",
        "shortDescription": "ConnectWise ScreenConnect contains an authentication bypass using an alternate path or channel.",
        "requiredAction": "Apply vendor updates.",
        "dueDate": "2024-02-29",
        "knownRansomwareCampaignUse": "Known",
        "notes": "https://nvd.nist.gov/vuln/detail/CVE-2024-1709"
    },
    {
        "cveID": "CVE-2023-46805",
        "vendorProject": "Ivanti",
        "product": "Connect Secure",
        "vulnerabilityName": "Ivanti Connect Secure Authentication Bypass",
        "dateAdded": "2024-01-10",
        "shortDescription": "An authentication bypass vulnerability in web components of Ivanti ICS allows remote attackers to access restricted resources.",
        "requiredAction": "Apply vendor mitigations.",
        "dueDate": "2024-01-22",
        "knownRansomwareCampaignUse": "Known",
        "notes": "https://nvd.nist.gov/vuln/detail/CVE-2023-46805"
    },
    {
        "cveID": "CVE-2023-34362",
        "vendorProject": "Progress",
        "product": "MOVEit Transfer",
        "vulnerabilityName": "MOVEit Transfer SQL Injection Vulnerability",
        "dateAdded": "2023-06-02",
        "shortDescription": "SQL injection vulnerability in MOVEit Transfer web application could allow an unauthenticated attacker to gain unauthorized access.",
        "requiredAction": "Apply vendor update immediately.",
        "dueDate": "2023-06-16",
        "knownRansomwareCampaignUse": "Known",
        "notes": "https://nvd.nist.gov/vuln/detail/CVE-2023-34362"
    },
    {
        "cveID": "CVE-2023-22515",
        "vendorProject": "Atlassian",
        "product": "Confluence Data Center and Server",
        "vulnerabilityName": "Confluence Data Center and Server Broken Access Control",
        "dateAdded": "2023-10-05",
        "shortDescription": "Atlassian Confluence Data Center and Server contains a broken access control vulnerability that allows an unauthenticated attacker to create unauthorized admin accounts.",
        "requiredAction": "Upgrade to latest fixed version.",
        "dueDate": "2023-10-12",
        "knownRansomwareCampaignUse": "Known",
        "notes": "https://nvd.nist.gov/vuln/detail/CVE-2023-22515"
    },
    {
        "cveID": "CVE-2021-44228",
        "vendorProject": "Apache",
        "product": "Log4j",
        "vulnerabilityName": "Apache Log4j2 JNDI Remote Code Execution Vulnerability (Log4Shell)",
        "dateAdded": "2021-12-10",
        "shortDescription": "Apache Log4j2 JNDI features do not protect against attacker controlled LDAP and other JNDI related endpoints.",
        "requiredAction": "Upgrade to Apache Log4j 2.17.1 or higher.",
        "dueDate": "2021-12-24",
        "knownRansomwareCampaignUse": "Known",
        "notes": "https://nvd.nist.gov/vuln/detail/CVE-2021-44228"
    },
    {
        "cveID": "CVE-2023-27997",
        "vendorProject": "Fortinet",
        "product": "FortiOS and FortiProxy",
        "vulnerabilityName": "Fortinet FortiOS Heap-Based Buffer Overflow Vulnerability",
        "dateAdded": "2023-06-13",
        "shortDescription": "A heap-based buffer overflow vulnerability in FortiOS and FortiProxy SSL-VPN may allow a remote unauthenticated attacker to execute arbitrary code.",
        "requiredAction": "Apply vendor updates.",
        "dueDate": "2023-07-04",
        "knownRansomwareCampaignUse": "Known",
        "notes": "https://nvd.nist.gov/vuln/detail/CVE-2023-27997"
    }
]


def _init_fallback():
    if not _kev_cache["dict"]:
        _kev_cache["data"] = list(FALLBACK_KEV_DATA)
        _kev_cache["dict"] = {item["cveID"].strip().upper(): item for item in FALLBACK_KEV_DATA}
        _kev_cache["total"] = len(FALLBACK_KEV_DATA)
        _kev_cache["data_source"] = "FALLBACK"
        _kev_cache["last_updated"] = datetime.now(timezone.utc).isoformat()


_init_fallback()


async def refresh_kev_cache(force: bool = False) -> Dict[str, Any]:
    """Fetch the latest CISA KEV catalog from official feed and update memory cache."""
    now = time.time()
    if not force and _kev_cache["dict"] and (now - _kev_cache["last_fetched"]) < CACHE_TTL_SECONDS:
        return _kev_cache

    try:
        async with httpx.AsyncClient(timeout=15) as client:
            resp = await client.get(CISA_KEV_URL)
            resp.raise_for_status()
            data = resp.json()

        vulns = data.get("vulnerabilities", [])
        if vulns:
            _kev_cache["data"] = vulns
            _kev_cache["dict"] = {
                item.get("cveID", "").strip().upper(): item
                for item in vulns
                if item.get("cveID")
            }
            _kev_cache["total"] = data.get("count", len(vulns))
            _kev_cache["last_fetched"] = now
            _kev_cache["data_source"] = "LIVE_CISA_KEV"
            _kev_cache["last_updated"] = data.get("dateReleased", datetime.now(timezone.utc).isoformat())
            logger.info(f"Loaded {len(_kev_cache['dict'])} vulnerabilities from CISA KEV feed.")
    except Exception as exc:
        logger.warning(f"Failed to fetch live CISA KEV feed: {exc}. Using cached/fallback catalog.")
        if not _kev_cache["dict"]:
            _init_fallback()
        else:
            _kev_cache["data_source"] = "CACHED_CISA_KEV"

    return _kev_cache


async def get_kev_dict() -> Dict[str, Dict[str, Any]]:
    """Return dictionary of {cve_id: kev_entry} for O(1) enrichment."""
    cache = await refresh_kev_cache()
    return cache["dict"]


async def is_in_kev(cve_id: str) -> bool:
    """Check if normalized CVE ID is listed in the CISA KEV catalog."""
    if not cve_id:
        return False
    kev_map = await get_kev_dict()
    return cve_id.strip().upper() in kev_map


async def fetch_kev_catalog(
    search: Optional[str] = None,
    ransomware_only: bool = False,
    limit: int = 50,
    offset: int = 0
) -> Dict[str, Any]:
    """Fetch paginated, searchable, filtered KEV catalog."""
    cache = await refresh_kev_cache()
    items = cache["data"]

    if search:
        s = search.lower()
        items = [
            v for v in items
            if s in v.get("cveID", "").lower()
            or s in v.get("vendorProject", "").lower()
            or s in v.get("product", "").lower()
            or s in v.get("vulnerabilityName", "").lower()
            or s in v.get("shortDescription", "").lower()
        ]

    if ransomware_only:
        items = [
            v for v in items
            if str(v.get("knownRansomwareCampaignUse", "")).lower() == "known"
        ]

    total_matches = len(items)
    paginated = items[offset: offset + limit]

    return {
        "source": "CISA Known Exploited Vulnerabilities Catalog",
        "data_source": cache.get("data_source", "CACHED_CISA_KEV"),
        "total": total_matches,
        "catalog_size": cache["total"],
        "last_updated": cache["last_updated"] or datetime.now(timezone.utc).isoformat(),
        "cached": (time.time() - cache["last_fetched"]) < CACHE_TTL_SECONDS,
        "vulnerabilities": paginated
    }

