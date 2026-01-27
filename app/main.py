import os
from typing import Optional, Dict

import stripe
from fastapi import FastAPI, HTTPException, Request, Header
from fastapi.middleware.cors import CORSMiddleware
from pydantic import BaseModel, Field
from pydanticsettings import BaseSettings, SettingsConfigDict


class Settings(BaseSettings):
    stripesecretkey: str = Field(..., alias="STRIPESECRETKEY")
    stripewebhooksecret: Optional[str] = Field(None, alias="STRIPEWEBHOOKSECRET")
    allowedorigins: str = Field("http://localhost:3000", alias="ALLOWEDORIGINS")
    apiauthtoken: Optional[str] = Field(None, alias="APIAUTHTOKEN")

    modelconfig = SettingsConfigDict(envfile=".env", extra="ignore")


settings = Settings()

# Configure Stripe SDK with your secret key
stripe.apikey = settings.stripesecretkey

app = FastAPI(title="Stripe Terminal Backend (FastAPI)")


# Optional CORS (helpful if you have web tooling; Android usually doesn't need this)
origins = [o.strip() for o in settings.allowedorigins.split(",") if o.strip()]
app.addmiddleware(
    CORSMiddleware,
    alloworigins=origins,
    allowcredentials=False,
    allowmethods=[""],
    allowheaders=[""],
)


def requireauth(xapitoken: Optional[str]):
    """Simple shared-token auth for demo/dev.
    In production, use OAuth/JWT/session auth and merchant scoping."""
    if settings.apiauthtoken:
        if not xapitoken or xapitoken != settings.apiauthtoken:
            raise HTTPException(statuscode=401, detail="Unauthorized")


class CreatePaymentIntentRequest(BaseModel):
    # amount in the smallest currency unit (e.g., cents)
    amount: int = Field(..., gt=0)
    currency: str = Field(..., minlength=3, maxlength=3)
    metadata: Optional[Dict[str, str]] = None


@app.get("/health")
def health():
    return {"ok": True}


@app.post("/connectiontoken")
def connectiontoken(xapitoken: Optional[str] = Header(None)):
    """
    Stripe Terminal SDK must fetch a short-lived connection token via your backend.
    Stripe creates it via POST /v1/terminal/connectiontokens.
    """
    requireauth(xapitoken)

    try:
        token = stripe.terminal.ConnectionToken.create()
        return {"secret": token.secret}
    except Exception as e:
        raise HTTPException(statuscode=500, detail=str(e))


@app.post("/paymentintents")
def createpaymentintent(body: CreatePaymentIntentRequest, xapitoken: Optional[str] = Header(None)):
    """
    Create a PaymentIntent server-side to prevent client tampering and keep secret key off-device.
    """
    requireauth(xapitoken)

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