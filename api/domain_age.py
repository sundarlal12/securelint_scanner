# # domain_age.py
# import json
# import time
# import httpx
# from typing import Dict, Any
# from crypto import encrypt, decrypt, HEADERS, REAL_API_URL, extract_domain_from_url

# def build_domain_age_request(url: str) -> Dict[str, Any]:
#     """Builds the complete domain_age request body"""
#     current_time = int(time.time() * 1000)
#     domain = extract_domain_from_url(url)
    
#     return {
#         "event_type": "domain_age",
#         "event_data": [
#             {
#                 "domain": domain,
#                 "date": current_time
#             }
#         ],
#         "browser_info": {
#             "language": ["en-GB", "en-US", "en"],
#             "name": "Chrome",
#             "version": "148.0.0.0"
#         },
#         "extension_version": "2.0.0.1",
#         "user_country": "unknown",
#         "user_fortect_cookies": [
#             {
#                 "domain": ".fortect.com",
#                 "expirationDate": 1779626826.601353,
#                 "hostOnly": False,
#                 "httpOnly": False,
#                 "name": "_srcid",
#                 "path": "/",
#                 "sameSite": "unspecified",
#                 "secure": False,
#                 "session": False,
#                 "storeId": "0",
#                 "value": "122"
#             }
#         ],
#         "user_info": {
#             "user_id": "local-premium-001",
#             "email": "user@fortect.com",
#             "date": current_time,
#             "type": "1"
#         }
#     }

# async def check_domain_age(url: str) -> Dict[str, Any]:
#     """
#     Check URL against Fortect domain age API
#     Returns: {
#         "type": str,
#         "action": str,
#         "trigger_next_request": int,
#         "trigger_notification": bool,
#         "cloud_detection": list
#     }
#     """
#     try:
#         request_body = build_domain_age_request(url)
#         encrypted_request = encrypt(json.dumps(request_body))
        
#         async with httpx.AsyncClient(timeout=30.0) as client:
#             response = await client.post(
#                 REAL_API_URL,
#                 json={"encryptMSG": encrypted_request},
#                 headers=HEADERS
#             )
        
#         response_data = response.json()
#         encrypted_response = response_data.get("body")
        
#         if not encrypted_response:
#             return {"error": "No response from Fortect API"}
        
#         decrypted_response = decrypt(encrypted_response)
#         result = json.loads(decrypted_response)
        
#         return result
    
#     except Exception as e:
#         print(f"[ERROR] Fortect domain age check failed: {str(e)}")
#         return {"error": str(e)}


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