# # gsr.py
# import json
# import httpx
# from typing import Dict, Any

# GOOGLE_SAFE_BROWSING_URL = "https://transparencyreport.google.com/transparencyreport/api/v3/safebrowsing/status"

# GOOGLE_HEADERS = {
#     "accept": "application/json,*/*",
#     "accept-language": "en-GB,en-US;q=0.9,en;q=0.8",
#     "cache-control": "no-cache",
#     "pragma": "no-cache",
#     "sec-fetch-dest": "empty",
#     "sec-fetch-mode": "cors",
#     "sec-fetch-site": "none",
#     "user-agent": "Mozilla/5.0 (Macintosh; Intel Mac OS X 10_15_7) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/148.0.0.0 Safari/537.36",
# }



# async def check_google_safe_browsing(url: str) -> Dict[str, Any]:
#     """
#     Check URL against Google Safe Browsing
#     Returns: {
#         "url": str,
#         "true_count": int,
#         "base_score": int,
#         "severity": str,
#         "severity_level": int,
#         "threat_details": list,
#         "raw_response": list
#     }
#     """
#     try:
#         async with httpx.AsyncClient(timeout=30.0, follow_redirects=True) as client:
#             response = await client.get(
#                 GOOGLE_SAFE_BROWSING_URL,
#                 params={"site": url},
#                 headers=GOOGLE_HEADERS
#             )
        
#         response_text = response.text
#         if response_text.startswith(")]}'"):
#             response_text = response_text[4:]
        
#         parsed_data = json.loads(response_text)
        
#         true_count = 0
#         threat_details = []
        
#         if isinstance(parsed_data, list) and len(parsed_data) > 0:
#             for item in parsed_data:
#                 if isinstance(item, list) and len(item) > 2:
#                     # Check each boolean value (positions 2,3,4,5)
#                     threat_types = ["phishing", "malware", "unwanted_software", "dangerous"]
#                     for i in range(2, min(6, len(item))):
#                         if item[i] == True:
#                             true_count += 1
#                             if i-2 < len(threat_types):
#                                 threat_details.append(threat_types[i-2])
        
#         # Calculate base score: 50 - (true_count * 5)
#         base_score = 50 - (true_count * 5)
        
#         # Determine severity based on true_count
#         if true_count >= 3:
#             severity = "critical"
#             severity_level = 4
#         elif true_count >= 1:
#             severity = "high"
#             severity_level = 3
#         else:
#             severity = "low"
#             severity_level = 1
        
#         return {
#             "url": url,
#             "true_count": true_count,
#             "base_score": base_score,
#             "severity": severity,
#             "severity_level": severity_level,
#             "threat_details": threat_details,
#             "raw_response": parsed_data
#         }
    
#     except Exception as e:
#         print(f"[ERROR] Google Safe Browsing check failed: {str(e)}")
#         return {
#             "url": url,
#             "true_count": 0,
#             "base_score": 50,
#             "severity": "unknown",
#             "severity_level": 0,
#             "threat_details": [],
#             "error": str(e)
#         }



# # gsr.py
# import json
# import httpx
# from urllib.parse import urlparse

# async def check_google_safe_browsing(url: str):
#     try:
#         # Extract domain for Google check (Google works better with domain only)
#         parsed = urlparse(url)
#         domain = parsed.netloc or url
#         domain = domain.replace("www.", "").split(":")[0]
        
#         # Use domain for Google check (more reliable)
#         check_url = domain if domain else url
        
#         async with httpx.AsyncClient(timeout=10.0, follow_redirects=True) as client:
#             response = await client.get(
#                 "https://transparencyreport.google.com/transparencyreport/api/v3/safebrowsing/status",
#                 params={"site": check_url}
#             )
        
#         text = response.text
#         if text.startswith(")]}'"):
#             text = text[4:]
        
#         if not text or text.strip() == "":
#             return {
#                 "url": url,
#                 "domain": domain,
#                 "true_count": 0,
#                 "score": 50,
#                 "severity": "low",
#                 "error": "Empty response from Google"
#             }
        
#         data = json.loads(text)
#         true_count = 0
#         threat_details = []
        
#         if isinstance(data, list) and len(data) > 0:
#             for item in data:
#                 if isinstance(item, list) and len(item) > 2:
#                     threat_types = ["phishing", "malware", "unwanted_software", "dangerous"]
#                     for i in range(2, min(6, len(item))):
#                         if item[i] == True:
#                             true_count += 1
#                             if i-2 < len(threat_types):
#                                 threat_details.append(threat_types[i-2])
        
#         # Calculate base score: 50 - (true_count * 5)
#         score = 50 - (true_count * 5)
        
#         # Determine severity
#         if true_count >= 3:
#             severity = "critical"
#         elif true_count >= 1:
#             severity = "high"
#         else:
#             severity = "low"
        
#         return {
#             "url": url,
#             "domain": domain,
#             "true_count": true_count,
#             "score": score,
#             "severity": severity,
#             "threat_details": threat_details
#         }
    
#     except json.JSONDecodeError as e:
#         print(f"[ERROR] JSON decode error for {url}: {str(e)}")
#         return {
#             "url": url,
#             "true_count": 0,
#             "score": 50,
#             "severity": "unknown",
#             "error": f"JSON decode error: {str(e)[:50]}"
#         }
#     except Exception as e:
#         print(f"[ERROR] Google Safe Browsing check failed for {url}: {str(e)}")
#         return {
#             "url": url,
#             "true_count": 0,
#             "score": 50,
#             "severity": "unknown",
#             "error": str(e)
#         }
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
                "score": 50,
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