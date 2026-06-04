
import base64
import json
import os
import httpx
from pathlib import Path
from dotenv import load_dotenv
from fastapi import Header, HTTPException

_env_path = Path(__file__).resolve().parent / ".env"
load_dotenv(dotenv_path=_env_path)

SUPABASE_URL = os.getenv("NEXT_PUBLIC_SUPABASE_URL")
SUPABASE_ANON_KEY = os.getenv("NEXT_PUBLIC_SUPABASE_ANON_KEY")

ALLOWED_PLANS = ["pro", "enterprise"]


def _decode_jwt_payload(token: str) -> dict:
    """Base64-decode the JWT payload section without signature verification."""
    try:
        parts = token.split(".")
        if len(parts) != 3:
            return {}
        payload = parts[1]
        padding = (4 - len(payload) % 4) % 4
        payload += "=" * padding
        decoded = base64.urlsafe_b64decode(payload)
        return json.loads(decoded)
    except Exception:
        return {}


async def _check_subscription(user_id: str, user_token: str) -> dict:
    """
    Query user_subscriptions for an active pro/enterprise row.
    Uses the user's own Bearer token for row-level access enforcement.
    """
    if not SUPABASE_URL or not SUPABASE_ANON_KEY:
        return {"allowed": False, "reason": "Server configuration error"}

    plans_filter = ",".join(ALLOWED_PLANS)
    endpoint = (
        f"{SUPABASE_URL}/rest/v1/user_subscriptions"
        f"?user_id=eq.{user_id}"
        f"&plan_id=in.({plans_filter})"
        f"&status=eq.active"
        f"&select=user_id,plan_id,status"
        f"&limit=1"
    )
    headers = {
        "apikey": SUPABASE_ANON_KEY,
        "Authorization": f"Bearer {user_token}",
        "Accept": "application/json",
    }

    try:
        async with httpx.AsyncClient(timeout=8.0) as client:
            response = await client.get(endpoint, headers=headers)
            if response.status_code == 200:
                data = response.json()
                if data:
                    return {"allowed": True, "plan": data[0].get("plan_id"), "user_id": user_id}
                return {"allowed": False, "reason": "No active Pro or Enterprise subscription found"}
            return {"allowed": False, "reason": f"Subscription lookup failed (HTTP {response.status_code})"}
    except Exception as e:
        return {"allowed": False, "reason": f"Subscription check error: {e}"}


async def require_active_subscription(authorization: str = Header(default=None)):
    """
    FastAPI dependency. Attach to any endpoint with Depends(require_active_subscription).
    Raises HTTP 401 for missing/invalid tokens, HTTP 403 for inactive/missing subscription.
    Returns the authenticated user context on success.
    """
    if not authorization:
        raise HTTPException(
            status_code=401,
            detail={
                "error": "missing_token",
                "message": "Authorization token is required.",
                "action": "Provide a valid auth token in the Authorization header (Bearer <token>).",
            },
        )

    if not authorization.startswith("Bearer "):
        raise HTTPException(
            status_code=401,
            detail={
                "error": "invalid_token_format",
                "message": "Authorization header must be: Bearer <token>",
            },
        )

    token = authorization[len("Bearer "):].strip()
    payload = _decode_jwt_payload(token)
    user_id = payload.get("sub")
    email = payload.get("email", "")

    if not user_id:
        raise HTTPException(
            status_code=401,
            detail={
                "error": "invalid_token",
                "message": "Could not extract user identity from token. Token may be expired or malformed.",
            },
        )

    sub = await _check_subscription(user_id, token)

    if not sub.get("allowed"):
        raise HTTPException(
            status_code=403,
            detail={
                "error": "subscription_required",
                "message": "This feature requires an active Pro or Enterprise plan.",
                "reason": sub.get("reason"),
                "action": "upgrade",
                "contact_admin": "Please contact admin or upgrade your plan to access this feature.",
                "user_id": user_id,
                "email": email,
            },
        )

    return {"user_id": user_id, "email": email, "plan": sub.get("plan")}
