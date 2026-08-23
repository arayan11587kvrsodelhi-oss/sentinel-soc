import os, httpx
NVD_URL="https://services.nvd.nist.gov/rest/json/cves/2.0"
async def fetch_recent_cves():
    headers={}
    if os.getenv("NVD_API_KEY"): headers["apiKey"]=os.getenv("NVD_API_KEY")
    try:
        async with httpx.AsyncClient(timeout=15) as client:
            r=await client.get(NVD_URL,params={"resultsPerPage":10},headers=headers)
            r.raise_for_status(); data=r.json()
        out=[]
        for item in data.get("vulnerabilities",[]):
            cve=item.get("cve",{}); desc=next((d.get("value","") for d in cve.get("descriptions",[]) if d.get("lang")=="en"),"")
            metrics=cve.get("metrics",{}); cvss=None
            for key in ("cvssMetricV40","cvssMetricV31","cvssMetricV30"):
                if metrics.get(key):
                    cvss=metrics[key][0].get("cvssData",{}).get("baseScore"); break
            out.append({"id":cve.get("id"),"description":desc,"cvss":cvss,"published":cve.get("published"),"modified":cve.get("lastModified"),"source":"NVD"})
        return out
    except Exception as exc:
        return [{"source":"NVD","error":str(exc)}]
