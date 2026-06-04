
import asyncio
import time
from gsr import check_google_safe_browsing
from malware import check_malware
from domain_age import check_domain_age
from blacklist import is_domain_blacklisted, build_blacklisted_response, BLACKLIST_SCORE
from phishtank import check_phishtank

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
        
        # Score adjustment: malware/phishing only penalised when action=block
        if detection_type in ["malware", "phishing"] and detection_action == "block":
            score_adjustment -= 10
        
        # Action-based overrides
        if detection_action == "block" and final_action != "block":
            final_action = "block"
        elif detection_action == "warn" and final_action is None:
            final_action = "warn"
        elif detection_action == "allow" and final_action is None:
            final_action = "allow"
    
    return score_adjustment, final_action

async def check_enhanced(url: str, securelint_data=None):
    """2 checks in parallel (Google + Malware), with blacklist pre-check."""
    overall_start = time.time()

    blacklisted, domain = await is_domain_blacklisted(url)
    if blacklisted:
        return build_blacklisted_response(url, domain, int((time.time() - overall_start) * 1000))

    google_task = asyncio.create_task(check_google_safe_browsing(url))
    malware_task = asyncio.create_task(check_malware(url))
    phishtank_task = asyncio.create_task(check_phishtank(url))

    google_result, malware_result, tankphish_result = await asyncio.gather(
        google_task, malware_task, phishtank_task
    )

    score = google_result.get("score", 50)

    # Cloud detection score adjustment
    cloud_detection_list = malware_result.get("cloud_detection", [])
    for detection in cloud_detection_list:
        detection_type = detection.get("type", "").lower()
        detection_action = detection.get("action", "").lower()
        if detection_type in ["malware", "phishing"] and detection_action == "block":
            score -= 10

    # PhishTank deduction (-5 only when confirmed phish: in_database+verified+valid)
    score -= tankphish_result.get("score_deduction", 0)

    # Additional adjustment from optional extra securelint_data
    if securelint_data:
        extra_adjustment, _ = calculate_score_from_cloud_detection(
            securelint_data.get("cloud_detection", [])
        )
        score += extra_adjustment

    score = max(0, min(100, score))

    # Action driven by cloud_detection action field first
    action = None
    severity = "low"
    for detection in cloud_detection_list:
        det_action = detection.get("action", "").lower()
        if det_action == "block":
            action = "block"
            severity = "critical" if score <= 30 else "high"
            break
        elif det_action == "warn" and action is None:
            action = "warn"
            severity = "medium"
        elif det_action == "allow" and action is None:
            action = "allow"
            severity = "low"

    # Also check extra securelint_data for action override
    if securelint_data and not action:
        _, extra_action = calculate_score_from_cloud_detection(
            securelint_data.get("cloud_detection", [])
        )
        if extra_action:
            action = extra_action
            if action == "block":
                severity = "critical" if score <= 30 else "high"
            elif action == "warn":
                severity = "medium"

    # Fallback to score-based action when cloud_detection has no action
    if not action:
        if score <= 30:
            action, severity = "block", "critical"
        elif score <= 45:
            action, severity = "block", "high"
        elif score <= 55:
            action, severity = "warn", "medium"
        else:
            action, severity = "allow", "low"

    result = {
        "url": url,
        "total_time_ms": int((time.time() - overall_start) * 1000),
        "score": score,
        "action": action,
        "severity": severity,
        "google": google_result,
        "malware": malware_result,
        "tankphish": tankphish_result,
    }

    if securelint_data:
        result["cloud_detection"] = securelint_data.get("cloud_detection", [])

    return result

async def check_super_fast(url: str, securelint_data=None):
    """ALL 3 checks in parallel (Google + Malware + Domain Age), with blacklist pre-check."""
    overall_start = time.time()

    blacklisted, domain = await is_domain_blacklisted(url)
    if blacklisted:
        return build_blacklisted_response(url, domain, int((time.time() - overall_start) * 1000))

    google_task = asyncio.create_task(check_google_safe_browsing(url))
    malware_task = asyncio.create_task(check_malware(url))
    domain_task = asyncio.create_task(check_domain_age(url))
    phishtank_task = asyncio.create_task(check_phishtank(url))

    google_result, malware_result, domain_result, tankphish_result = await asyncio.gather(
        google_task, malware_task, domain_task, phishtank_task
    )

    score = google_result.get("score", 50)

    # Cloud detection score adjustment
    cloud_detection_list = malware_result.get("cloud_detection", [])
    for detection in cloud_detection_list:
        detection_type = detection.get("type", "").lower()
        detection_action = detection.get("action", "").lower()
        if detection_type in ["malware", "phishing"] and detection_action == "block":
            score -= 10

    # PhishTank deduction (-5 only when confirmed phish: in_database+verified+valid)
    score -= tankphish_result.get("score_deduction", 0)

    # Additional adjustment from optional extra securelint_data
    if securelint_data:
        extra_adjustment, _ = calculate_score_from_cloud_detection(
            securelint_data.get("cloud_detection", [])
        )
        score += extra_adjustment

    score = max(0, min(100, score))

    # Action driven by cloud_detection action field first
    action = None
    severity = "low"
    for detection in cloud_detection_list:
        det_action = detection.get("action", "").lower()
        if det_action == "block":
            action = "block"
            severity = "critical" if score <= 30 else "high"
            break
        elif det_action == "warn" and action is None:
            action = "warn"
            severity = "medium"
        elif det_action == "allow" and action is None:
            action = "allow"
            severity = "low"

    # Also check extra securelint_data for action override
    if securelint_data and not action:
        _, extra_action = calculate_score_from_cloud_detection(
            securelint_data.get("cloud_detection", [])
        )
        if extra_action:
            action = extra_action
            if action == "block":
                severity = "critical" if score <= 30 else "high"
            elif action == "warn":
                severity = "medium"

    # Fallback to score-based action when cloud_detection has no action
    if not action:
        if score <= 30:
            action, severity = "block", "critical"
        elif score <= 45:
            action, severity = "block", "high"
        elif score <= 55:
            action, severity = "warn", "medium"
        else:
            action, severity = "allow", "low"

    result = {
        "url": url,
        "total_time_ms": int((time.time() - overall_start) * 1000),
        "score": score,
        "action": action,
        "severity": severity,
        "google": google_result,
        "malware": malware_result,
        "domain_age": domain_result,
        "tankphish": tankphish_result,
    }

    if securelint_data:
        result["cloud_detection"] = securelint_data.get("cloud_detection", [])

    return result