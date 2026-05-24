# # # enhanced.py
# # from typing import Dict, Any
# # from gsr import check_google_safe_browsing
# # from malware import check_malware

# # async def check_enhanced(url: str) -> Dict[str, Any]:
# #     """
# #     Enhanced malware check with exact scoring logic:
# #     1. Google Safe Browsing - count 'true' values (each = -5 from base 50)
# #     2. Fortect malware check - clean: +5 | malicious: -25
# #     """
# #     try:
# #         # Step 1: Google Safe Browsing check
# #         google_result = await check_google_safe_browsing(url)
# #         current_score = google_result["base_score"]
# #         true_count = google_result["true_count"]
        
# #         # Step 2: Fortect malware check
# #         fortect_result = await check_malware(url)
        
# #         fortect_type = fortect_result.get("type")
# #         fortect_action = fortect_result.get("action")
# #         score_adjustment = 0
        
# #         # Apply Fortect scoring logic
# #         if fortect_type == "clean" and fortect_action == "allow":
# #             current_score += 5
# #             score_adjustment = "+5"
# #         elif fortect_type in ["malware", "phishing"] and fortect_action == "block":
# #             current_score -= 25
# #             score_adjustment = "-25"
        
# #         # Ensure score stays within 0-100 range
# #         final_score = max(0, min(100, current_score))
        
# #         # Determine severity based on final score (lower = more severe)
# #         if final_score <= 30:
# #             severity = "critical"
# #             severity_level = 4
# #             final_action = "block"
# #             recommendation = "Immediately block this URL - Critical threat detected"
# #         elif final_score <= 45:
# #             severity = "high"
# #             severity_level = 3
# #             final_action = "block"
# #             recommendation = "Block this URL - High severity threat"
# #         elif final_score <= 55:
# #             severity = "medium"
# #             severity_level = 2
# #             final_action = "warn"
# #             recommendation = "Warn user - Medium risk detected"
# #         else:
# #             severity = "low"
# #             severity_level = 1
# #             final_action = "allow"
# #             recommendation = "Site appears safe - Low risk"
        
# #         return {
# #             "url": url,
# #             "final_score": final_score,
# #             "severity": severity,
# #             "severity_level": severity_level,
# #             "final_action": final_action,
# #             "recommendation": recommendation,
# #             "analysis": {
# #                 "google_safe_browsing": {
# #                     "true_values_count": google_result["true_count"],
# #                     "base_score": google_result["base_score"],
# #                     "threats_detected": google_result["threat_details"],
# #                     "severity": google_result["severity"]
# #                 },
# #                 "fortect_malware": {
# #                     "type": fortect_type,
# #                     "action": fortect_action,
# #                     "score_adjustment": score_adjustment
# #                 }
# #             },
# #             "scoring_logic": {
# #                 "base_score": 50,
# #                 "google_deduction": f"-{true_count * 5} (each true = -5)",
# #                 "fortect_adjustment": score_adjustment,
# #                 "final_calculation": f"{google_result['base_score']} + adjustment = {final_score}"
# #             }
# #         }
    
# #     except Exception as e:
# #         print(f"[ERROR] Enhanced check failed: {str(e)}")
# #         return {
# #             "url": url,
# #             "error": str(e),
# #             "final_score": 50,
# #             "severity": "unknown",
# #             "final_action": "error"
# #         }

# # gsr.py - WITH CACHING
# import json
# import httpx
# import time
# from typing import Dict, Any
# from functools import lru_cache
# from datetime import datetime, timedelta

# # Simple in-memory cache
# cache = {}
# CACHE_TTL = 300  # Cache for 5 minutes

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



# # enhanced.py
# import asyncio
# import time
# from typing import Dict, Any
# from gsr import check_google_safe_browsing
# from malware import check_malware

# async def check_enhanced(url: str) -> Dict[str, Any]:
#     """
#     Enhanced malware check with CONCURRENT requests (faster)
#     Runs Google and Fortect checks simultaneously
#     """
#     start_time = time.time()
    
#     try:
#         # Run both checks concurrently (REDUCES TIME by 50-70%)
#         google_task = asyncio.create_task(check_google_safe_browsing(url))
#         fortect_task = asyncio.create_task(check_malware(url))
        
#         # Wait for both to complete
#         google_result, fortect_result = await asyncio.gather(google_task, fortect_task)
        
#         current_score = google_result.get("base_score", 50)
#         true_count = google_result.get("true_count", 0)
        
#         fortect_type = fortect_result.get("type")
#         fortect_action = fortect_result.get("action")
#         score_adjustment = 0
        
#         # Apply Fortect scoring logic
#         if fortect_type == "clean" and fortect_action == "allow":
#             current_score += 5
#             score_adjustment = "+5"
#         elif fortect_type in ["malware", "phishing"] and fortect_action == "block":
#             current_score -= 25
#             score_adjustment = "-25"
        
#         # Ensure score stays within 0-100 range
#         final_score = max(0, min(100, current_score))
        
#         # Determine severity based on final score (lower = more severe)
#         if final_score <= 30:
#             severity = "critical"
#             severity_level = 4
#             final_action = "block"
#             recommendation = "Immediately block this URL - Critical threat detected"
#         elif final_score <= 45:
#             severity = "high"
#             severity_level = 3
#             final_action = "block"
#             recommendation = "Block this URL - High severity threat"
#         elif final_score <= 55:
#             severity = "medium"
#             severity_level = 2
#             final_action = "warn"
#             recommendation = "Warn user - Medium risk detected"
#         else:
#             severity = "low"
#             severity_level = 1
#             final_action = "allow"
#             recommendation = "Site appears safe - Low risk"
        
#         response_time = int((time.time() - start_time) * 1000)
        
#         return {
#             "url": url,
#             "final_score": final_score,
#             "severity": severity,
#             "severity_level": severity_level,
#             "final_action": final_action,
#             "recommendation": recommendation,
#             "response_time_ms": response_time,
#             "analysis": {
#                 "google_safe_browsing": {
#                     "true_values_count": google_result.get("true_count", 0),
#                     "base_score": google_result.get("base_score", 50),
#                     "threats_detected": google_result.get("threat_details", []),
#                     "severity": google_result.get("severity", "unknown")
#                 },
#                 "fortect_malware": {
#                     "type": fortect_type,
#                     "action": fortect_action,
#                     "score_adjustment": score_adjustment
#                 }
#             },
#             "scoring_logic": {
#                 "base_score": 50,
#                 "google_deduction": f"-{true_count * 5} (each true = -5)",
#                 "fortect_adjustment": score_adjustment,
#                 "final_calculation": f"{google_result.get('base_score', 50)} + adjustment = {final_score}"
#             }
#         }
    
#     except Exception as e:
#         print(f"[ERROR] Enhanced check failed: {str(e)}")
#         return {
#             "url": url,
#             "error": str(e),
#             "final_score": 50,
#             "severity": "unknown",
#             "final_action": "error",
#             "response_time_ms": int((time.time() - start_time) * 1000)
#         }

# async def check_google_safe_browsing(url: str, use_cache: bool = True) -> Dict[str, Any]:
#     """
#     Check URL against Google Safe Browsing with caching
#     """
#     # Check cache first
#     if use_cache and url in cache:
#         cached_data = cache[url]
#         if time.time() - cached_data["timestamp"] < CACHE_TTL:
#             print(f"[CACHE HIT] Returning cached result for {url}")
#             return cached_data["result"]
    
#     start_time = time.time()
    
#     try:
#         async with httpx.AsyncClient(timeout=30.0, follow_redirects=True) as client:
#             response = await client.get(
#                 GOOGLE_SAFE_BROWSING_URL,
#                 params={"site": url},
#                 headers=GOOGLE_HEADERS
#             )
        
#         response_time = int((time.time() - start_time) * 1000)
        
#         response_text = response.text
#         if response_text.startswith(")]}'"):
#             response_text = response_text[4:]
        
#         parsed_data = json.loads(response_text)
        
#         true_count = 0
#         threat_details = []
        
#         if isinstance(parsed_data, list) and len(parsed_data) > 0:
#             for item in parsed_data:
#                 if isinstance(item, list) and len(item) > 2:
#                     threat_types = ["phishing", "malware", "unwanted_software", "dangerous"]
#                     for i in range(2, min(6, len(item))):
#                         if item[i] == True:
#                             true_count += 1
#                             if i-2 < len(threat_types):
#                                 threat_details.append(threat_types[i-2])
        
#         base_score = 50 - (true_count * 5)
        
#         if true_count >= 3:
#             severity = "critical"
#             severity_level = 4
#         elif true_count >= 1:
#             severity = "high"
#             severity_level = 3
#         else:
#             severity = "low"
#             severity_level = 1
        
#         result = {
#             "url": url,
#             "true_count": true_count,
#             "base_score": base_score,
#             "severity": severity,
#             "severity_level": severity_level,
#             "threat_details": threat_details,
#             "response_time_ms": response_time,
#             "cached": False,
#             "raw_response": parsed_data
#         }
        
#         # Store in cache
#         if use_cache:
#             cache[url] = {
#                 "timestamp": time.time(),
#                 "result": result
#             }
        
#         return result
    
#     except Exception as e:
#         print(f"[ERROR] Google Safe Browsing check failed: {str(e)}")
#         return {
#             "url": url,
#             "true_count": 0,
#             "base_score": 50,
#             "severity": "unknown",
#             "severity_level": 0,
#             "threat_details": [],
#             "response_time_ms": int((time.time() - start_time) * 1000),
#             "error": str(e)
#         }

# # Function to clear cache
# def clear_cache():
#     global cache
#     cache = {}
#     print("[CACHE] Cache cleared")

# # Function to get cache stats
# def get_cache_stats():
#     return {
#         "cache_size": len(cache),
#         "cache_ttl_seconds": CACHE_TTL
# #     }

# import asyncio
# from gsr import check_google_safe_browsing
# from malware import check_malware

# async def check_enhanced(url: str):
#     try:
#         # Run both checks at the same time
#         google_task = asyncio.create_task(check_google_safe_browsing(url))
#         fortect_task = asyncio.create_task(check_malware(url))
        
#         google_result, fortect_result = await asyncio.gather(google_task, fortect_task)
        
#         score = google_result.get("score", 50)
        
#         # Adjust score based on Fortect result
#         if fortect_result.get("type") == "clean":
#             score += 5
#         elif fortect_result.get("type") in ["malware", "phishing"]:
#             score -= 25
        
#         score = max(0, min(100, score))
        
#         if score <= 30:
#             action = "block"
#             severity = "critical"
#         elif score <= 45:
#             action = "block"
#             severity = "high"
#         elif score <= 55:
#             action = "warn"
#             severity = "medium"
#         else:
#             action = "allow"
#             severity = "low"
        
#         return {
#             "url": url,
#             "score": score,
#             "action": action,
#             "severity": severity,
#             "google": google_result,
#             "fortect": fortect_result
#         }
#     except Exception as e:
#         return {"url": url, "error": str(e)}


import asyncio
import time
from gsr import check_google_safe_browsing
from malware import check_malware
from domain_age import check_domain_age

async def check_enhanced(url: str):
    """2 checks in parallel (Google + Malware)"""
    overall_start = time.time()
    
    google_task = asyncio.create_task(check_google_safe_browsing(url))
    malware_task = asyncio.create_task(check_malware(url))
    
    google_result, malware_result = await asyncio.gather(google_task, malware_task)
    
    score = google_result.get("score", 50)
    
    if malware_result.get("type") == "clean":
        score += 5
    elif malware_result.get("type") in ["malware", "phishing"]:
        score -= 25
    
    score = max(0, min(100, score))
    
    if score <= 30:
        action = "block"
        severity = "critical"
    elif score <= 45:
        action = "block"
        severity = "high"
    elif score <= 55:
        action = "warn"
        severity = "medium"
    else:
        action = "allow"
        severity = "low"
    
    return {
        "url": url,
        "total_time_ms": int((time.time() - overall_start) * 1000),
        "score": score,
        "action": action,
        "severity": severity,
        "google": google_result,
        "malware": malware_result
    }

async def check_super_fast(url: str):
    """ALL 3 checks in parallel (Google + Malware + Domain Age)"""
    overall_start = time.time()
    
    google_task = asyncio.create_task(check_google_safe_browsing(url))
    malware_task = asyncio.create_task(check_malware(url))
    domain_task = asyncio.create_task(check_domain_age(url))
    
    google_result, malware_result, domain_result = await asyncio.gather(
        google_task, malware_task, domain_task
    )
    
    score = google_result.get("score", 50)
    
    if malware_result.get("type") == "clean":
        score += 5
    elif malware_result.get("type") in ["malware", "phishing"]:
        score -= 25
    
    score = max(0, min(100, score))
    
    if score <= 30:
        action = "block"
        severity = "critical"
    elif score <= 45:
        action = "block"
        severity = "high"
    elif score <= 55:
        action = "warn"
        severity = "medium"
    else:
        action = "allow"
        severity = "low"
    
    return {
        "url": url,
        "total_time_ms": int((time.time() - overall_start) * 1000),
        "score": score,
        "action": action,
        "severity": severity,
        "google": google_result,
        "malware": malware_result,
        "domain_age": domain_result
    }