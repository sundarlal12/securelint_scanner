
# main.py - COMPLETE WITH ALL ENDPOINTS + EMAIL LEAK CHECK (VERCEL READY)
from fastapi import FastAPI, Query, HTTPException
from fastapi.responses import JSONResponse
import httpx
import asyncio
import time
import re
import requests
import json
import os
from bs4 import BeautifulSoup

# Import custom modules with proper error handling for Vercel
try:
    from crypto import HEADERS, REAL_API_URL
    from gsr import check_google_safe_browsing
    from malware import check_malware
    from domain_age import check_domain_age
    from enhanced import check_enhanced, check_super_fast
    from extension_scraper import fetch_extension_details
except ImportError as e:
    print(f"Import warning: {e}")
    # Fallback for missing modules
    HEADERS = {}
    REAL_API_URL = ""
    
    async def check_google_safe_browsing(url):
        return {"score": 50, "time_ms": 0, "status": "unknown"}
    
    async def check_malware(url):
        return {"type": "clean", "time_ms": 0}
    
    async def check_domain_age(url):
        return {"domain_age_days": 0, "time_ms": 0}
    
    async def check_enhanced(url):
        return {"score": 50, "time_ms": 0}
    
    async def check_super_fast(url):
        return {"score": 50, "time_ms": 0}
    
    async def fetch_extension_details(extension_id):
        return {"error": "Extension scraper not available"}

app = FastAPI(title="Fortect API + Extension Scraper + Email Leak Check")

# ============ CONFIGURATION ============

WID = os.getenv("EMAIL_LEAK_WID")
EMAIL_LEAK_API_BASE = os.getenv("EMAIL_LEAK_API_BASE")

# ============ SECURITY CHECK ENDPOINTS ============

@app.get("/")
async def root():
    return {
        "status": "running",
        "version": "2.2.0"
   
      
    }

@app.get("/gsrcheck/")
async def google_check(url: str = Query(...)):
    result = await check_google_safe_browsing(url)
    return JSONResponse(content=result)

@app.get("/malware/")
async def malware_check(url: str = Query(...)):
    result = await check_malware(url)
    return JSONResponse(content=result)

@app.get("/domain_age/")
async def domain_age_check(url: str = Query(...)):
    result = await check_domain_age(url)
    return JSONResponse(content=result)

@app.get("/enhanced/")
async def enhanced_check(url: str = Query(...)):
    result = await check_enhanced(url)
    return JSONResponse(content=result)

@app.get("/malware/enhanced/")
async def malware_enhanced_check(url: str = Query(...)):
    overall_start = time.time()
    google_task = asyncio.create_task(check_google_safe_browsing(url))
    fortect_task = asyncio.create_task(check_malware(url))
    google_result, fortect_result = await asyncio.gather(google_task, fortect_task)
    
    score = google_result.get("score", 50)
    if fortect_result.get("type") == "clean":
        score += 5
    elif fortect_result.get("type") in ["malware", "phishing"]:
        score -= 25
    score = max(0, min(100, score))
    
    if score <= 30:
        action, severity = "block", "critical"
    elif score <= 45:
        action, severity = "block", "high"
    elif score <= 55:
        action, severity = "warn", "medium"
    else:
        action, severity = "allow", "low"
    
    total_time = int((time.time() - overall_start) * 1000)
    
    return JSONResponse(content={
        "url": url,
        "total_time_ms": total_time,
        "score": score,
        "action": action,
        "severity": severity,
        "google_time_ms": google_result.get("time_ms", 0),
        "fortect_time_ms": fortect_result.get("time_ms", 0),
        "google": google_result,
        "fortect": fortect_result
    })

@app.get("/super_fast/")
async def super_fast_check(url: str = Query(...)):
    result = await check_super_fast(url)
    return JSONResponse(content=result)

# ============ EMAIL LEAK CHECK ENDPOINTS ============

@app.get("/email-leak/")
async def email_leak_check(
    email: str = Query(..., description="Email address to check for data leaks"),
    from_date: int = Query(1, description="Days to look back (default: 1)"),
    wid: str = Query(None, description="Widget ID parameter")
):
    start_time = time.time()
    final_wid = wid if wid else WID
    
    email_pattern = r'^[a-zA-Z0-9._%+-]+@[a-zA-Z0-9.-]+\.[a-zA-Z]{2,}$'
    if not re.match(email_pattern, email):
        raise HTTPException(status_code=400, detail="Invalid email format")
    
    gb_data = {
        "attributes": {
            "wid": final_wid,
            "firstRunDate": int(time.time() * 1000)
        }
    }
    
    api_url = f"{EMAIL_LEAK_API_BASE}/scanEmails"
    params = {
        "fromDate": from_date,
        "gbData": json.dumps(gb_data),
        "mails": email
    }
    
    headers = {
        "User-Agent": "Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36",
        "Accept": "application/json, text/plain, */*"
      
    }
    
    try:
        async with httpx.AsyncClient(timeout=30.0, follow_redirects=True) as client:
            response = await client.get(api_url, params=params, headers=headers)
            response.raise_for_status()
            result = response.json()
            response_time_ms = int((time.time() - start_time) * 1000)
            
            if isinstance(result, list):
                leak_data = result
                enhanced_result = {
                    "email": email, "status": "success", "response_time_ms": response_time_ms,
                    "wid_used": final_wid, "data": leak_data,
                    "is_compromised": len(leak_data) > 0, "leak_count": len(leak_data)
                }
            elif isinstance(result, dict):
                leak_data = result.get("data", [])
                enhanced_result = {
                    "email": email, "status": "success", "response_time_ms": response_time_ms,
                    "wid_used": final_wid, "data": result,
                    "is_compromised": bool(leak_data and len(leak_data) > 0),
                    "leak_count": len(leak_data) if leak_data else 0
                }
            else:
                return JSONResponse(content={"email": email, "status": "error", "error": "Unexpected response type"}, status_code=500)
            
            if enhanced_result["is_compromised"]:
                actual_leaks = leak_data if isinstance(result, list) else result.get("data", [])
                if actual_leaks:
                    leak_sources, breach_dates = [], []
                    for leak in actual_leaks:
                        if isinstance(leak, dict):
                            source = leak.get("source", "Unknown")
                            if source and source != "Unknown":
                                leak_sources.append(source)
                            breach_date = leak.get("breachDate") or leak.get("date")
                            if breach_date and breach_date not in ["Unknown", ""]:
                                breach_dates.append(breach_date)
                    summary = {"total_leaks": len(actual_leaks), "leak_sources": list(set(leak_sources)) if leak_sources else ["Unknown"]}
                    if breach_dates:
                        summary["earliest_leak"] = min(breach_dates)
                        summary["latest_leak"] = max(breach_dates)
                    else:
                        summary["earliest_leak"] = summary["latest_leak"] = "Date unknown"
                    enhanced_result["summary"] = summary
                else:
                    enhanced_result["summary"] = {"total_leaks": 0, "message": "No leak details available"}
            else:
                enhanced_result["summary"] = {"total_leaks": 0, "message": "No leaks found for this email address"}
            
            return JSONResponse(content=enhanced_result)
    except httpx.TimeoutException:
        return JSONResponse(status_code=504, content={"email": email, "status": "error", "error": "Request timeout"})
    except Exception as e:
        return JSONResponse(status_code=500, content={"email": email, "status": "error", "message": str(e)})

@app.post("/email-leak/batch")
async def email_leak_batch(
    request: dict,
    from_date: int = Query(1),
    wid: str = Query(None)
):
    start_time = time.time()
    emails = request.get("emails", [])
    final_wid = wid if wid else WID
    
    if not emails:
        raise HTTPException(status_code=400, detail="Please provide a list of emails")
    if len(emails) > 10:
        raise HTTPException(status_code=400, detail="Maximum 10 emails per batch request")
    
    email_pattern = r'^[a-zA-Z0-9._%+-]+@[a-zA-Z0-9.-]+\.[a-zA-Z]{2,}$'
    invalid_emails = [email for email in emails if not re.match(email_pattern, email)]
    if invalid_emails:
        raise HTTPException(status_code=400, detail=f"Invalid email formats: {', '.join(invalid_emails)}")
    
    headers = {
        "User-Agent": "Mozilla/5.0",
        "Accept": "application/json"

    }
    
    async def check_single_email(email: str):
        gb_data = {"attributes": {"wid": final_wid, "firstRunDate": int(time.time() * 1000)}}
        params = {"fromDate": from_date, "gbData": json.dumps(gb_data), "mails": email}
        api_url = f"{EMAIL_LEAK_API_BASE}/scanEmails"
        
        try:
            async with httpx.AsyncClient(timeout=30.0) as client:
                response = await client.get(api_url, params=params, headers=headers)
                response.raise_for_status()
                result = response.json()
                
                if isinstance(result, list):
                    return {"email": email, "status": "success", "is_compromised": len(result) > 0, "leak_count": len(result)}
                elif isinstance(result, dict):
                    leak_data = result.get("data", [])
                    return {"email": email, "status": "success", "is_compromised": len(leak_data) > 0, "leak_count": len(leak_data)}
                else:
                    return {"email": email, "status": "error", "error": "Unexpected response type"}
        except Exception as e:
            return {"email": email, "status": "error", "error": str(e)}
    
    tasks = [check_single_email(email) for email in emails]
    results = await asyncio.gather(*tasks)
    total_time_ms = int((time.time() - start_time) * 1000)
    
    return JSONResponse(content={
        "batch_status": "completed",
        "total_emails": len(emails),
        "total_time_ms": total_time_ms,
        "wid_used": final_wid,
        "results": results,
        "summary": {
            "compromised_count": sum(1 for r in results if r.get("is_compromised")),
            "clean_count": sum(1 for r in results if r.get("status") == "success" and not r.get("is_compromised")),
            "error_count": sum(1 for r in results if r.get("status") == "error")
        }
    })

# ============ EXTENSION SCRAPER ENDPOINTS ============

@app.get("/extension/{extension_id}")
async def get_extension_info(extension_id: str):
    result = await fetch_extension_details(extension_id)
    if "error" in result:
        raise HTTPException(status_code=404, detail=result["error"])
    return JSONResponse(content=result)

@app.get("/extension/{extension_id}/basic")
async def get_extension_basic(extension_id: str):
    start_time = time.time()
    main_url = f"https://chromewebstore.google.com/detail/{extension_id}"
    headers = {
        "User-Agent": "Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36",
        "Accept": "text/html,application/xhtml+xml,application/xml;q=0.9",
    }
    
    try:
        response = requests.get(main_url, headers=headers, timeout=10)
        response.raise_for_status()
        soup = BeautifulSoup(response.text, 'html.parser')
        
        name_elem = soup.select_one('h1.Pa2dE, h1[itemprop="name"], .VgVgxc h1')
        logo_img = soup.select_one('img[alt*="Item logo"], img.rBxtY, .VgVgxc img')
        rating_elem = soup.select_one('.Vq0ZA')
        users_elem = soup.select_one('.F9iKBc')
        
        version = None
        details_section = soup.select_one('.TKAMQe, .im4wIf')
        if details_section:
            for item in details_section.select('.MqICNe'):
                label_elem = item.select_one('.QDHp8e')
                if label_elem and 'version' in label_elem.text.strip().lower():
                    value_elem = item.select_one('.nBZElf')
                    if value_elem:
                        version = value_elem.text.strip()
                        break
        
        result = {
            "id": extension_id,
            "name": name_elem.text.strip() if name_elem else None,
            "logo_url": logo_img.get('src', '').split('=')[0] if logo_img else None,
            "star_rating": float(rating_elem.text.strip()) if rating_elem else None,
            "users": None,
            "version": version,
            "response_time_ms": round((time.time() - start_time) * 1000, 2)
        }
        
        if users_elem:
            users_text = users_elem.get_text()
            match = re.search(r'([\d,]+\s*users?)', users_text, re.I)
            if match:
                result['users'] = match.group(1)
        
        return JSONResponse(content=result)
    except Exception as e:
        raise HTTPException(status_code=404, detail=f"Extension {extension_id} not found")

@app.get("/extension/{extension_id}/privacy")
async def get_extension_privacy(extension_id: str):
    start_time = time.time()
    privacy_url = f"https://chromewebstore.google.com/detail/{extension_id}/privacy"
    headers = {
        "User-Agent": "Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36",
        "Accept": "text/html,application/xhtml+xml,application/xml;q=0.9",
    }
    
    try:
        response = requests.get(privacy_url, headers=headers, timeout=10)
        response.raise_for_status()
        soup = BeautifulSoup(response.text, 'html.parser')
        
        result = {
            "id": extension_id,
            "privacy_policy_url": None,
            "data_handled": [],
            "data_usage_policy": [],
            "response_time_ms": round((time.time() - start_time) * 1000, 2)
        }
        
        policy_link = soup.select_one('.S7w4Mb a.SYhWge')
        if policy_link:
            result['privacy_policy_url'] = policy_link.get('href')
        
        data_items = soup.select('.IbuSnc, .BeFehc')
        for item in data_items:
            h4 = item.select_one('h4.FNNqG, .jnapE')
            if h4:
                result['data_handled'].append(h4.text.strip())
        
        policy_items = soup.select('.LH0qne')
        if policy_items:
            result['data_usage_policy'] = [item.text.strip() for item in policy_items]
        
        return JSONResponse(content=result)
    except Exception as e:
        raise HTTPException(status_code=404, detail=f"Privacy info for {extension_id} not found")

@app.get("/extension/{extension_id}/developer")
async def get_extension_developer(extension_id: str):
    start_time = time.time()
    main_url = f"https://chromewebstore.google.com/detail/{extension_id}"
    headers = {
        "User-Agent": "Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36",
        "Accept": "text/html,application/xhtml+xml,application/xml;q=0.9",
    }
    
    try:
        response = requests.get(main_url, headers=headers, timeout=10)
        response.raise_for_status()
        soup = BeautifulSoup(response.text, 'html.parser')
        
        result = {
            "id": extension_id,
            "name": None,
            "developer_name": None,
            "developer_email": None,
            "developer_phone": None,
            "developer_address": None,
            "developer_website": None,
            "support_website": None,
            "response_time_ms": round((time.time() - start_time) * 1000, 2)
        }
        
        name_elem = soup.select_one('h1.Pa2dE, h1[itemprop="name"], .VgVgxc h1')
        if name_elem:
            result['name'] = name_elem.text.strip()
        
        details_section = soup.select_one('.TKAMQe, .im4wIf')
        if details_section:
            for item in details_section.select('.MqICNe'):
                label_elem = item.select_one('.QDHp8e')
                if label_elem and 'developer' in label_elem.text.strip().lower():
                    dev_div = item.select_one('.yyjN4, .mdSapd')
                    if dev_div:
                        result['developer_address'] = dev_div.text.strip()
                        lines = dev_div.text.strip().split('\n')
                        if lines:
                            result['developer_name'] = lines[0].strip()
                    
                    website_link = item.select_one('a.Qk4pd, a[href*="http"]')
                    if website_link:
                        result['developer_website'] = website_link.get('href')
                    
                    email_elem = item.select_one('.NnJuub')
                    if email_elem:
                        result['developer_email'] = email_elem.text.strip()
                    
                    phone_elem = item.select_one('.sQlfnf')
                    if phone_elem:
                        result['developer_phone'] = phone_elem.text.strip()
                    break
        
        support_link = soup.select_one('.kcASRe a.YeLZxd')
        if support_link:
            result['support_website'] = support_link.get('href')
        
        return JSONResponse(content=result)
    except Exception as e:
        raise HTTPException(status_code=404, detail=f"Developer info for {extension_id} not found")

@app.post("/extensions/batch")
async def get_multiple_extensions(ids: dict):
    import concurrent.futures
    
    start_time = time.time()
    extension_ids = ids.get("ids", [])[:5]
    
    if not extension_ids:
        raise HTTPException(status_code=400, detail="Please provide a list of extension IDs")
    
    results = []
    with concurrent.futures.ThreadPoolExecutor(max_workers=5) as executor:
        futures = {executor.submit(lambda eid: fetch_extension_details(eid), ext_id): ext_id for ext_id in extension_ids}
        for future in concurrent.futures.as_completed(futures):
            ext_id = futures[future]
            try:
                result = future.result()
                results.append(result)
            except Exception as e:
                results.append({"id": ext_id, "error": str(e)})
    
    return JSONResponse(content={
        "results": results,
        "count": len(results),
        "total_time_ms": round((time.time() - start_time) * 1000, 2)
    })

@app.post("/v1/cloud")
async def proxy(request: dict):
    async with httpx.AsyncClient() as client:
        response = await client.post(REAL_API_URL, json=request, headers=HEADERS)
    return JSONResponse(content=response.json())

# For local development
if __name__ == "__main__":
    import uvicorn
    print("\n" + "="*70)
    print("🚀 FORTECT API - RUNNING LOCALLY")
    print("="*70)
    print("\n📧 Email Leak Check: /email-leak/?email=test@example.com")
    print("="*70 + "\n")
    uvicorn.run(app, host="0.0.0.0", port=8000)