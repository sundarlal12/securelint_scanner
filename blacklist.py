
import os
import time
import httpx
from urllib.parse import urlparse
from pathlib import Path
from dotenv import load_dotenv

# Load .env from the project root regardless of working directory
_env_path = Path(__file__).resolve().parent / ".env"
load_dotenv(dotenv_path=_env_path)

SUPABASE_URL = os.getenv("NEXT_PUBLIC_SUPABASE_URL")
SUPABASE_ANON_KEY = os.getenv("NEXT_PUBLIC_SUPABASE_ANON_KEY")

BLACKLIST_SCORE = 52


def extract_domain(url: str) -> str:
    """Extract bare domain (no www, no path, no port) from a URL."""
    url = url.strip()
    if not url.startswith(("http://", "https://")):
        url = "https://" + url
    parsed = urlparse(url)
    hostname = parsed.hostname or ""
    if hostname.startswith("www."):
        hostname = hostname[4:]
    return hostname.lower()


async def is_domain_blacklisted(url: str) -> tuple[bool, str]:
    """
    Check scanner_blacklist_domains table for status=1.
    Returns (is_blacklisted: bool, domain: str).
    """
    domain = extract_domain(url)
    if not domain:
        return False, domain

    if not SUPABASE_URL or not SUPABASE_ANON_KEY:
        print(f"[blacklist] WARN: DB env vars missing. URL={SUPABASE_URL!r}")
        return False, domain

    endpoint = (
        f"{SUPABASE_URL}/rest/v1/scanner_blacklist_domains"
        f"?domain=eq.{domain}&status=eq.1&select=domain,status&limit=1"
    )
    headers = {
        "apikey": SUPABASE_ANON_KEY,
        "Authorization": f"Bearer {SUPABASE_ANON_KEY}",
        "Accept": "application/json",
    }

    try:
        async with httpx.AsyncClient(timeout=8.0) as client:
            response = await client.get(endpoint, headers=headers)
            print(f"[blacklist] domain={domain!r} status={response.status_code} body={response.text[:200]}")
            if response.status_code == 200:
                data = response.json()
                return len(data) > 0, domain
            return False, domain
    except Exception as e:
        print(f"[blacklist] ERROR for domain={domain!r}: {e}")
        return False, domain




def build_blacklisted_response(url: str, domain: str, elapsed_ms: int) -> dict:
    """Return a response matching the normal scan structure, with score=52 for blacklisted domains."""
    return {
        "url": url,
        "total_time_ms": elapsed_ms,
        "score": BLACKLIST_SCORE,
        "action": "warn",
        "severity": "medium",
        "google_time_ms": 0,
        "securelint_time_ms": 0,
        "google": {
            "url": url,
            "domain": domain,
            "true_count": 0,
            "score": BLACKLIST_SCORE,
            "severity": "medium",
            "time_ms": 0,
        },
        "securelint": {
            "type": "blacklisted",
            "action": "warn",
            "trigger_next_request": 0,
            "trigger_notification": True,
            "cloud_detection": [
                {
                    "url": url,
                    "type": "blacklisted",
                    "action": "warn",
                    "cAction": "warn",
                }
            ],
            "time_ms": 0,
        },
        "decision_logic": {
            "google_threat_detected": False,
            "google_score": BLACKLIST_SCORE,
            "google_true_count": 0,
            "cloud_type": "blacklisted",
            "cloud_action": "warn",
            "cloud_deduction": 0,
            "final_score_calculation": f"{BLACKLIST_SCORE} - 0 = {BLACKLIST_SCORE}",
            "priority": "blacklist_check",
            "blacklisted_domain": domain,
        },
    }
