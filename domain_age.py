
import json
import time
import httpx
from crypto import encrypt, decrypt, HEADERS, REAL_API_URL, extract_domain

async def check_domain_age(url: str):
    start = time.time()
    try:
        domain = extract_domain(url)
        
        body = {
            "event_type": "domain_age",
            "event_data": [{"domain": domain, "date": int(time.time() * 1000)}],
            "extension_version": "2.0.0.1",
            "user_info": {"user_id": "test", "type": "1"}
        }
        
        encrypted = encrypt(json.dumps(body))
        
        async with httpx.AsyncClient(timeout=10.0) as client:
            response = await client.post(
                REAL_API_URL,
                json={"encryptMSG": encrypted},
                headers=HEADERS
            )
        
        result = response.json()
        if "body" in result:
            decrypted = decrypt(result["body"])
            return {**json.loads(decrypted), "time_ms": int((time.time() - start) * 1000)}
        return {"error": "No response", "time_ms": int((time.time() - start) * 1000)}
    except Exception as e:
        return {"error": str(e), "time_ms": int((time.time() - start) * 1000)}