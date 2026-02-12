import os
from typing import Optional

import stripe
from fastapi import FastAPI, Request, Header, APIRouter, Depends
from pydantic import BaseModel, Field
from pydantic_settings import BaseSettings, SettingsConfigDict
# auth.py
from fastapi import HTTPException, status
from jose import jwt
from jose.utils import base64url_decode
from typing import Dict, Any, Annotated
import httpx
from cachetools import TTLCache
import time
import json
import os
from fastapi.security import HTTPBearer

PROJECT_REF = os.getenv("SUPABASE_PROJECT_REF")         # e.g. abcd1234
SUPABASE_URL = f"https://{PROJECT_REF}.supabase.co"
JWKS_URL = f"{SUPABASE_URL}/auth/v1/.well-known/jwks.json"
ISSUER = f"{SUPABASE_URL}/auth/v1"
EXPECTED_AUD = "authenticated"  # Supabase's default audience for access tokens

_jwks_cache = TTLCache(maxsize=1, ttl=3600)  # 1-hour cache

async def _get_jwks() -> Dict[str, Any]:
    print(f'_get_jwks:{JWKS_URL}')
    if "jwks" in _jwks_cache:
        return _jwks_cache["jwks"]
    async with httpx.AsyncClient(timeout=5.0) as client:
        r = await client.get(JWKS_URL)
        r.raise_for_status()
        data = r.json()
        _jwks_cache["jwks"] = data
        return data

def _get_key_for_kid(jwks: Dict[str, Any], kid: str) -> Dict[str, str]:
    print(f'_get_key_for_kid:{jwks}')
    for key in jwks.get("keys", []):
        if key.get("kid") == kid:
            return key
    raise HTTPException(status_code=status.HTTP_401_UNAUTHORIZED, detail="Unknown signing key")

async def verify_bearer_token(token: str) -> Dict[str, Any]:
    print(f'token:{token}')

    # Parse header to get kid
    try:
        header_b64, payload_b64, signature_b64 = token.split(".")
        header = json.loads(base64url_decode(header_b64 + "==").decode())
        kid = header.get("kid")
    except Exception:
        print('Invalid format')
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
    stripesecretkey: str = Field(..., alias="STRIPE_SECRET_KEY")
    stripewebhooksecret: Optional[str] = Field(None, alias="STRIPE_WEBHOOK_SECRET")
    #allowedorigins: str = Field("http://localhost:3000", alias="ALLOWED_ORIGINS")
    model_config = SettingsConfigDict(env_file=".env", extra="ignore")


settings = Settings()

# Configure Stripe SDK with your secret key
stripe.api_key = settings.stripesecretkey

app = FastAPI(title="Stripe Terminal Backend (FastAPI)")

class CreatePaymentIntentRequest(BaseModel):
    # amount in the smallest currency unit (e.g., cents)
    amount: int = Field(..., gt=0)
    currency: str = Field(..., minlength=3, maxlength=3)
    metadata: Optional[Dict[str, str]] = None

oauth2_scheme = HTTPBearer()

async def get_current_identity(request: Request, token: Annotated[str, Depends(oauth2_scheme)]):
    print(f'token:{token.credentials}')
    print(f'headers:{request.headers}')
    identity = await verify_bearer_token(token.credentials)
    request.state.identity = identity
    return identity

secure_router = APIRouter(
    tags=["secure"],
    dependencies=[Depends(get_current_identity)])

@app.get("/health-check")
def health_check():
    return {"status": True}


@secure_router.post("/connectiontoken")
async def connectiontoken():
    """
    Stripe Terminal SDK must fetch a short-lived connection token via your backend.
    Stripe creates it via POST /v1/terminal/connectiontokens.
    """

    try:
        print('I got here')
        token = stripe.terminal.ConnectionToken.create()
        return {"secret": token.secret}
    except Exception as e:
        raise HTTPException(statuscode=500, detail=str(e))


@secure_router.post("/paymentintents")
async def createpaymentintent(body: CreatePaymentIntentRequest):
    """
    Create a PaymentIntent server-side to prevent client tampering and keep secret key off-device.
    """
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

app.include_router(secure_router)