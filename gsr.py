
import json
import time
import httpx
from crypto import extract_domain

async def check_google_safe_browsing(url: str):
    start = time.time()
    try:
        domain = extract_domain(url)
        
        async with httpx.AsyncClient(timeout=10.0, follow_redirects=True) as client:
            response = await client.get(
                "https://transparencyreport.google.com/transparencyreport/api/v3/safebrowsing/status",
                params={"site": domain}
            )
        
        text = response.text
        if text.startswith(")]}'"):
            text = text[4:]
        
        if not text or text.strip() == "":
            return {
                "url": url,
                "true_count": 0,
                "score": 51,
                "severity": "low",
                "time_ms": int((time.time() - start) * 1000)
            }
        
        data = json.loads(text)
        true_count = 0
        
        if isinstance(data, list) and len(data) > 0:
            for item in data:
                if isinstance(item, list) and len(item) > 2:
                    for i in range(2, min(6, len(item))):
                        if item[i] == True:
                            true_count += 1
        
        score = 50 - (true_count * 5)
        
        return {
            "url": url,
            "domain": domain,
            "true_count": true_count,
            "score": max(0, min(100, score)),
            "severity": "high" if true_count > 0 else "low",
            "time_ms": int((time.time() - start) * 1000)
        }
    except Exception as e:
        return {
            "url": url,
            "true_count": 0,
            "score": 50,
            "severity": "unknown",
            "error": str(e),
            "time_ms": int((time.time() - start) * 1000)
        }