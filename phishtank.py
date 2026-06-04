
import os
import time
import httpx
from pathlib import Path
from dotenv import load_dotenv

_env_path = Path(__file__).resolve().parent / ".env"
load_dotenv(dotenv_path=_env_path)

PHISHTANK_APP_KEY = os.getenv("PHISHTANK_APP_KEY")
PHISHTANK_ENDPOINT = "https://checkurl.phishtank.com/checkurl/"

_HEADERS = {
    "User-Agent": "phishtank/mahmoudabdelmobdy",
    "Accept": "*/*",
    "Accept-Language": "en-GB,en-US;q=0.9,en;q=0.8",
    "Cache-Control": "no-cache",
    "Content-Type": "application/x-www-form-urlencoded;charset=UTF-8"
}


async def check_phishtank(url: str) -> dict:
    """
    Check a URL against the PhishTank database.

    Score deduction rules:
      in_database=True  + verified=True  + valid=True  → -5 (confirmed phish)
      anything else                                     →  0 (no deduction)

    Returns a dict with 'score_deduction' and 'tankphish' metadata.
    """
    start = time.time()

    base = {
        "url": url,
        "score_deduction": 0,
        "is_phish": False,
        "in_database": False,
        "verified": False,
        "valid": False,
        "phish_id": None,
        # "phish_detail_page": None,
        "verified_at": None,
        "time_ms": 0,
    }

    if not PHISHTANK_APP_KEY:
        base["error"] = "PHISHTANK_APP_KEY not configured"
        base["time_ms"] = int((time.time() - start) * 1000)
        return base

    try:
        async with httpx.AsyncClient(timeout=10.0) as client:
            response = await client.post(
                PHISHTANK_ENDPOINT,
                data={
                    "url": url,
                    "format": "json",
                    "app_key": PHISHTANK_APP_KEY,
                },
                headers=_HEADERS,
            )
            data = response.json()
            results = data.get("results", {})

            in_database = results.get("in_database", False)
            verified = results.get("verified", False)
            valid = results.get("valid", False)

            is_phish = bool(in_database and verified and valid)
            score_deduction = 5 if is_phish else 0

            return {
                "url": url,
                "score_deduction": score_deduction,
                "is_phish": is_phish,
                "in_database": in_database,
                "verified": verified,
                "valid": valid,
                #"phish_id": results.get("phish_id"),
                #"phish_detail_page": results.get("phish_detail_page"),
                "verified_at": results.get("verified_at"),
                "time_ms": int((time.time() - start) * 1000),
            }

    except Exception as e:
        base["error"] = str(e)
        base["time_ms"] = int((time.time() - start) * 1000)
        return base
