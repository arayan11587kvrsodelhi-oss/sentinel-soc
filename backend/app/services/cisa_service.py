import httpx
CISA_KEV_URL="https://www.cisa.gov/sites/default/files/feeds/known_exploited_vulnerabilities.json"
async def fetch_kev_catalog():
    try:
        async with httpx.AsyncClient(timeout=20) as client:
            r=await client.get(CISA_KEV_URL); r.raise_for_status(); data=r.json()
        return {"source":"CISA KEV","count":data.get("count",0),"vulnerabilities":data.get("vulnerabilities",[])[:50]}
    except Exception as exc:
        return {"source":"CISA KEV","error":str(exc),"vulnerabilities":[]}
