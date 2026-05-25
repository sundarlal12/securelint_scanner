
import asyncio
import time
from gsr import check_google_safe_browsing
from malware import check_malware
from domain_age import check_domain_age

def calculate_score_from_cloud_detection(cloud_detection_list):
    """
    Calculate score impact from cloud_detection results.
    Returns score adjustment and final action recommendation.
    """
    if not cloud_detection_list:
        return 0, None
    
    score_adjustment = 0
    final_action = None
    
    for detection in cloud_detection_list:
        detection_type = detection.get("type", "").lower()
        detection_action = detection.get("action", "").lower()
        
        # Score adjustments based on type
        if detection_type == "clean":
            score_adjustment += 5
        elif detection_type == "malware":
            score_adjustment -= 30
        elif detection_type == "phishing":
            score_adjustment -= 30
        elif detection_type == "suspicious":
            score_adjustment -= 15
        
        # Action-based overrides
        if detection_action == "block" and final_action != "block":
            final_action = "block"
        elif detection_action == "warn" and final_action is None:
            final_action = "warn"
        elif detection_action == "allow" and final_action is None:
            final_action = "allow"
    
    return score_adjustment, final_action

async def check_enhanced(url: str, securelint_data=None):
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
    
    # Add cloud detection scoring if data provided
    if securelint_data:
        cloud_adjustment, cloud_action = calculate_score_from_cloud_detection(
            securelint_data.get("cloud_detection", [])
        )
        score += cloud_adjustment
    
    score = max(0, min(100, score))
    
    # Check if cloud action overrides
    cloud_override_action = None
    if securelint_data:
        _, cloud_override_action = calculate_score_from_cloud_detection(
            securelint_data.get("cloud_detection", [])
        )
    
    if cloud_override_action:
        action = cloud_override_action
        if action == "block":
            severity = "critical" if score <= 30 else "high"
        elif action == "warn":
            severity = "medium"
        else:
            severity = "low"
    else:
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
    
    result = {
        "url": url,
        "total_time_ms": int((time.time() - overall_start) * 1000),
        "score": score,
        "action": action,
        "severity": severity,
        "google": google_result,
        "malware": malware_result
    }
    
    # Include cloud detection in result if provided
    if securelint_data:
        result["cloud_detection"] = securelint_data.get("cloud_detection", [])
    
    return result

async def check_super_fast(url: str, securelint_data=None):
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
    
    # Add cloud detection scoring if data provided
    if securelint_data:
        cloud_adjustment, cloud_action = calculate_score_from_cloud_detection(
            securelint_data.get("cloud_detection", [])
        )
        score += cloud_adjustment
    
    score = max(0, min(100, score))
    
    # Check if cloud action overrides
    cloud_override_action = None
    if securelint_data:
        _, cloud_override_action = calculate_score_from_cloud_detection(
            securelint_data.get("cloud_detection", [])
        )
    
    if cloud_override_action:
        action = cloud_override_action
        if action == "block":
            severity = "critical" if score <= 30 else "high"
        elif action == "warn":
            severity = "medium"
        else:
            severity = "low"
    else:
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
    
    result = {
        "url": url,
        "total_time_ms": int((time.time() - overall_start) * 1000),
        "score": score,
        "action": action,
        "severity": severity,
        "google": google_result,
        "malware": malware_result,
        "domain_age": domain_result
    }
    
    # Include cloud detection in result if provided
    if securelint_data:
        result["cloud_detection"] = securelint_data.get("cloud_detection", [])
    
    return result