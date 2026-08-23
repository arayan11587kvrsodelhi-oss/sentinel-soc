import os, httpx
async def analyze_incident(event):
    # Works without an AI key using a safe local fallback.
    if not os.getenv("AI_API_KEY") or not os.getenv("AI_API_BASE_URL"):
        sev=event.get("severity","MEDIUM").upper()
        score={"CRITICAL":90,"HIGH":75,"MEDIUM":50,"LOW":20}.get(sev,40)
        return {"riskScore":score,"classification":event.get("event_type","Unknown"),"summary":"Local rule-based analysis. Configure an AI provider for LLM analysis.","recommendations":["Review related logs.","Confirm whether the event is expected.","Apply your incident-response policy."]}
    prompt=f"Analyze this security event defensively. Return JSON with riskScore, classification, summary and recommendations. Event: {event}"
    payload={"model":os.getenv("AI_MODEL","default"),"messages":[{"role":"system","content":"You are a defensive cybersecurity analyst. Do not provide offensive instructions."},{"role":"user","content":prompt}]}
    headers={"Authorization":f"Bearer {os.environ['AI_API_KEY']}"}
    async with httpx.AsyncClient(timeout=30) as client:
        r=await client.post(os.environ["AI_API_BASE_URL"],json=payload,headers=headers); r.raise_for_status(); return r.json()
