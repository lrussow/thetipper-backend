import os
import json
import time
from typing import Optional, Dict, Any, Annotated

import stripe
from fastapi import FastAPI, Request, APIRouter, Depends, HTTPException, status
from fastapi.security import HTTPBearer
from pydantic import BaseModel, Field
from pydantic_settings import BaseSettings, SettingsConfigDict
from jose import jwt
from jose.utils import base64url_decode

# ----------------------
# Settings / Environment
# ----------------------
class Settings(BaseSettings):
    stripesecretkey: str = Field(..., alias="STRIPE_SECRET_KEY")
    stripewebhooksecret: Optional[str] = Field(None, alias="STRIPE_WEBHOOK_SECRET")
    supabase_project_ref: str = Field(..., alias="SUPABASE_PROJECT_REF")
    supabase_jwt_secret: str = Field(..., alias="SUPABASE_JWT_SECRET")

    model_config = SettingsConfigDict(env_file=".env", extra="ignore")

settings = Settings()

# Stripe SDK
stripe.api_key = settings.stripesecretkey

# Supabase constants
SUPABASE_URL = f"https://{settings.supabase_project_ref}.supabase.co"
ISSUER = f"{SUPABASE_URL}/auth/v1"
EXPECTED_AUD = "authenticated"

# -------------
# FastAPI setup
# -------------
app = FastAPI(title="Stripe Terminal Backend (FastAPI)")
oauth2_scheme = HTTPBearer()

# Optional: quick path logger to diagnose proxy/prefix issues
# Comment out if not needed
@app.middleware("http")
async def log_request(request: Request, call_next):
    print("INCOMING PATH:", request.url.path)
    return await call_next(request)

# -------------
# Auth (HS256)
# -------------
async def verify_bearer_token_raw(token: str) -> Dict[str, Any]:
    """
    Verify a Supabase access token using HS256 with SUPABASE_JWT_SECRET.
    Expects the raw JWT (no 'Bearer ' prefix).
    Validates signature, issuer, audience, and exp.
    """
    # Decode header to confirm HS256 and basic format
    try:
        header_b64, payload_b64, signature_b64 = token.split(".")
        header = json.loads(base64url_decode(header_b64 + "==").decode())
        alg = header.get("alg")
        if alg != "HS256":
            raise HTTPException(
                status_code=status.HTTP_401_UNAUTHORIZED,
                detail=f"Unsupported alg: {alg}; this server is HS256-only"
            )
    except Exception:
        raise HTTPException(status_code=status.HTTP_401_UNAUTHORIZED, detail="Invalid token format")

    # Verify signature and claims
    try:
        claims = jwt.decode(
            token,
            key=settings.supabase_jwt_secret,
            algorithms=["HS256"],
            audience=EXPECTED_AUD,
            issuer=ISSUER,
            options={
                "verify_aud": True,
                "verify_signature": True,
                "verify_exp": True,
                "require_exp": True,
                "require_iat": True,
                "require_nbf": False,
            },
        )
    except Exception as e:
        raise HTTPException(status_code=status.HTTP_401_UNAUTHORIZED, detail=f"Token verification failed: {e}")

    # Extra clock check (defensive)
    now = int(time.time())
    if "exp" in claims and claims["exp"] < now:
        raise HTTPException(status_code=status.HTTP_401_UNAUTHORIZED, detail="Token expired")

    return claims

async def get_current_identity(
    request: Request,
    token: Annotated[str, Depends(oauth2_scheme)]  # token.credentials is the raw JWT
):
    identity = await verify_bearer_token_raw(token.credentials)
    request.state.identity = identity
    return identity

# ------------
# API Routers
# ------------
secure_router = APIRouter(
    tags=["secure"],
    dependencies=[Depends(get_current_identity)]
)

@app.get("/health-check")
def health_check():
    return {"status": True}

# ---- Stripe Terminal ----
@secure_router.post("/connectiontoken")
async def connectiontoken():
    """
    Stripe Terminal SDK must fetch a short-lived connection token via your backend.
    """
    try:
        token = stripe.terminal.ConnectionToken.create()
        return {"secret": token.secret}
    except Exception as e:
        raise HTTPException(status_code=500, detail=str(e))

class CreatePaymentIntentRequest(BaseModel):
    amount: int = Field(..., gt=0)  # smallest unit (cents)
    currency: str = Field(..., min_length=3, max_length=3)
    metadata: Optional[Dict[str, str]] = None

@secure_router.post("/paymentintents")
async def createpaymentintent(body: CreatePaymentIntentRequest):
    """
    Create a PaymentIntent server-side for Terminal.
    """
    try:
        pi = stripe.PaymentIntent.create(
            amount=body.amount,
            currency=body.currency.lower(),
            metadata=body.metadata or {},
            payment_method_types=["card_present"],
            capture_method="automatic",
        )
        return {"id": pi.id, "client_secret": pi.client_secret}
    except Exception as e:
        raise HTTPException(status_code=500, detail=str(e))

# ---- Stripe Webhook (optional) ----
@app.post("/webhook")
async def webhook(request: Request):
    if not settings.stripewebhooksecret:
        raise HTTPException(status_code=500, detail="STRIPE_WEBHOOK_SECRET not configured")

    payload = await request.body()
    sigheader = request.headers.get("Stripe-Signature")

    try:
        event = stripe.Webhook.construct_event(
            payload=payload,
            sig_header=sigheader,
            secret=settings.stripewebhooksecret,
        )
    except Exception as e:
        raise HTTPException(status_code=400, detail=f"Webhook error: {str(e)}")

    eventtype = event["type"]

    if eventtype == "payment_intent.succeeded":
        pass
    elif eventtype == "payment_intent.payment_failed":
        pass

    return {"received": True, "type": eventtype}

# IMPORTANT: include router AFTER defining routes
app.include_router(secure_router)