import os
from typing import Optional

import stripe
from fastapi import FastAPI, Request, Header
from fastapi.middleware.cors import CORSMiddleware
from pydantic import BaseModel, Field
from pydantic_settings import BaseSettings, SettingsConfigDict
# auth.py
from fastapi import HTTPException, status
from jose import jwt
from jose.utils import base64url_decode
from typing import Dict, Any
import httpx
from cachetools import TTLCache
import time
import json
import os

PROJECT_REF = os.getenv("SUPABASE_PROJECT_REF")         # e.g. abcd1234
SUPABASE_URL = f"https://{PROJECT_REF}.supabase.co"
JWKS_URL = f"{SUPABASE_URL}/auth/v1/.well-known/jwks.json"
ISSUER = f"{SUPABASE_URL}/auth/v1"
EXPECTED_AUD = "authenticated"  # Supabase's default audience for access tokens

_jwks_cache = TTLCache(maxsize=1, ttl=3600)  # 1-hour cache

async def _get_jwks() -> Dict[str, Any]:
    if "jwks" in _jwks_cache:
        return _jwks_cache["jwks"]
    async with httpx.AsyncClient(timeout=5.0) as client:
        r = await client.get(JWKS_URL)
        r.raise_for_status()
        data = r.json()
        _jwks_cache["jwks"] = data
        return data

def _get_key_for_kid(jwks: Dict[str, Any], kid: str) -> Dict[str, str]:
    for key in jwks.get("keys", []):
        if key.get("kid") == kid:
            return key
    raise HTTPException(status_code=status.HTTP_401_UNAUTHORIZED, detail="Unknown signing key")

async def verify_bearer_token(authorization: str | None) -> Dict[str, Any]:
    if not authorization or not authorization.lower().startswith("bearer "):
        raise HTTPException(status_code=status.HTTP_401_UNAUTHORIZED, detail="Missing bearer token")

    token = authorization.split(" ", 1)[1].strip()

    # Parse header to get kid
    try:
        header_b64, payload_b64, signature_b64 = token.split(".")
        header = json.loads(base64url_decode(header_b64 + "==").decode())
        kid = header.get("kid")
    except Exception:
        raise HTTPException(status_code=status.HTTP_401_UNAUTHORIZED, detail="Invalid token format")

    jwks = await _get_jwks()
    key_dict = _get_key_for_kid(jwks, kid)

    # Build public key and verify signature/claims
    try:
        # Let jose handle verification and claims
        claims = jwt.decode(
            token,
            key=key_dict,  # jose accepts jwk dict
            algorithms=[key_dict.get("alg", "RS256")],
            audience=EXPECTED_AUD,
            issuer=ISSUER,
            options={
                "verify_aud": True,
                "verify_signature": True,
                "verify_exp": True,
                "require_exp": True,
                "require_iat": True,
                "require_nbf": False,
            }
        )
    except Exception as e:
        raise HTTPException(status_code=status.HTTP_401_UNAUTHORIZED, detail=f"Token verification failed: {e}")

    # Optional: additional checks (clock skew, etc.)
    now = int(time.time())
    if "exp" in claims and claims["exp"] < now:
        raise HTTPException(status_code=status.HTTP_401_UNAUTHORIZED, detail="Token expired")

    return claims

class Settings(BaseSettings):
    stripesecretkey: str = Field(..., alias="STRIPESECRETKEY")
    stripewebhooksecret: Optional[str] = Field(None, alias="STRIPEWEBHOOKSECRET")
    allowedorigins: str = Field("http://localhost:3000", alias="ALLOWEDORIGINS")
    model_config = SettingsConfigDict(env_file=".env", extra="ignore")


settings = Settings()

# Configure Stripe SDK with your secret key
stripe.apikey = settings.stripesecretkey

app = FastAPI(title="Stripe Terminal Backend (FastAPI)")


# Optional CORS (helpful if you have web tooling; Android usually doesn't need this)
origins = [o.strip() for o in settings.allowedorigins.split(",") if o.strip()]
app.add_middleware(
    CORSMiddleware,
    alloworigins=origins,
    allowcredentials=False,
    allowmethods=[""],
    allowheaders=[""],
)

class CreatePaymentIntentRequest(BaseModel):
    # amount in the smallest currency unit (e.g., cents)
    amount: int = Field(..., gt=0)
    currency: str = Field(..., minlength=3, maxlength=3)
    metadata: Optional[Dict[str, str]] = None


@app.get("/health")
def health():
    return {"ok": True}


@app.post("/connectiontoken")
async def connectiontoken(header: Optional[str] = Header(None)):
    """
    Stripe Terminal SDK must fetch a short-lived connection token via your backend.
    Stripe creates it via POST /v1/terminal/connectiontokens.
    """
    await verify_bearer_token(header)

    try:
        token = stripe.terminal.ConnectionToken.create()
        return {"secret": token.secret}
    except Exception as e:
        raise HTTPException(statuscode=500, detail=str(e))


@app.post("/paymentintents")
async def createpaymentintent(body: CreatePaymentIntentRequest, header: Optional[str] = Header(None)):
    """
    Create a PaymentIntent server-side to prevent client tampering and keep secret key off-device.
    """
    await verify_bearer_token(header)

    try:
        pi = stripe.PaymentIntent.create(
            amount=body.amount,
            currency=body.currency.lower(),
            metadata=body.metadata or {},
            # For Terminal flows you typically use cardpresent.
            paymentmethodtypes=["cardpresent"],
            capturemethod="automatic",
        )
        return {"id": pi.id, "clientsecret": pi.clientsecret}
    except Exception as e:
        raise HTTPException(statuscode=500, detail=str(e))


@app.post("/webhook")
async def webhook(request: Request):
    """
    Stripe webhook endpoint (recommended).
    Verifies the signature (STRIPEWEBHOOKSECRET) and then handles events.
    """
    if not settings.stripewebhooksecret:
        raise HTTPException(statuscode=500, detail="STRIPEWEBHOOKSECRET not configured")

    payload = await request.body()
    sigheader = request.headers.get("Stripe-Signature")

    try:
        event = stripe.Webhook.constructevent(
            payload=payload,
            sigheader=sigheader,
            secret=settings.stripewebhooksecret,
        )
    except Exception as e:
        raise HTTPException(statuscode=400, detail=f"Webhook error: {str(e)}")

    # Handle only what you need
    eventtype = event["type"]

    if eventtype == "paymentintent.succeeded":
        # Persist fulfillment / receipt / audit logs here
        pass
    elif eventtype == "paymentintent.paymentfailed":
        pass

    return {"received": True, "type": eventtype}