from fastapi import FastAPI, HTTPException, Depends, Request
from fastapi.security import OAuth2AuthorizationCodeBearer
from fastapi.responses import RedirectResponse, JSONResponse
from pydantic import BaseModel, EmailStr
import httpx
import os
from dotenv import load_dotenv
from supabase import create_client, Client
import requests
from datetime import datetime
import base64
import json

# Load environment variables
load_dotenv()

# Environment variables
DERIV_APP_ID = os.getenv("DERIV_APP_ID")
DERIV_APP_SECRET = os.getenv("DERIV_APP_SECRET")
DERIV_OAUTH_URL = "https://oauth.deriv.com/oauth2/authorize"
DERIV_TOKEN_URL = "https://oauth.deriv.com/oauth2/token"
REDIRECT_URI = os.getenv("REDIRECT_URI")
USD_TO_KES_RATE = float(os.getenv("USD_TO_KES_RATE"))
KES_TO_USD_RATE = float(os.getenv("KES_TO_USD_RATE"))

# Supabase configuration
SUPABASE_URL = os.getenv("SUPABASE_URL")
SUPABASE_KEY = os.getenv("SUPABASE_KEY")
supabase: Client = create_client(SUPABASE_URL, SUPABASE_KEY)

# M-Pesa configuration
MPESA_CONSUMER_KEY = os.getenv("MPESA_CONSUMER_KEY")
MPESA_CONSUMER_SECRET = os.getenv("MPESA_CONSUMER_SECRET")
MPESA_PASSKEY = os.getenv("MPESA_PASSKEY")
MPESA_SHORTCODE = os.getenv("MPESA_SHORTCODE")
MPESA_ENV = os.getenv("MPESA_ENV", "sandbox")

app = FastAPI()

# Pydantic models
class PhoneNumber(BaseModel):
    phone_number: str

class DepositRequest(BaseModel):
    amount: float
    phone_number: str

class WithdrawalRequest(BaseModel):
    amount: float
    phone_number: str
    email: EmailStr

# OAuth2 scheme
oauth2_scheme = OAuth2AuthorizationCodeBearer(
    authorizationUrl=DERIV_OAUTH_URL,
    tokenUrl=DERIV_TOKEN_URL,
)

# Store user sessions
user_sessions = {}

@app.get("/login")
async def login():
    """Redirect users to Deriv OAuth login page"""
    auth_url = f"{DERIV_OAUTH_URL}?app_id={DERIV_APP_ID}&l=EN&brand=deriv&redirect_uri={REDIRECT_URI}"
    return RedirectResponse(url=auth_url)

@app.get("/oauth/callback")
async def oauth_callback(code: str):
    """Handle OAuth callback from Deriv"""
    async with httpx.AsyncClient() as client:
        # Exchange code for access token
        token_response = await client.post(
            DERIV_TOKEN_URL,
            data={
                "grant_type": "authorization_code",
                "code": code,
                "app_id": DERIV_APP_ID,
                "app_secret": DERIV_APP_SECRET,
            },
        )
        
        if token_response.status_code != 200:
            raise HTTPException(status_code=400, detail="Failed to get access token")
        
        token_data = token_response.json()
        access_token = token_data["access_token"]
        
        # Get user info from Deriv API
        user_info_response = await client.get(
            "https://api.deriv.com/api/v1/get_account_status",
            headers={"Authorization": f"Bearer {access_token}"}
        )
        
        if user_info_response.status_code != 200:
            raise HTTPException(status_code=400, detail="Failed to get user info")
        
        user_info = user_info_response.json()
        
        # Store user session
        user_sessions[access_token] = {
            "user_info": user_info,
            "access_token": access_token
        }
        
        return RedirectResponse(url="/dashboard")

@app.post("/phone-number")
async def add_phone_number(
    phone_data: PhoneNumber,
    token: str = Depends(oauth2_scheme)
):
    """Add or update user's phone number"""
    if token not in user_sessions:
        raise HTTPException(status_code=401, detail="Invalid or expired session")
    
    user_info = user_sessions[token]["user_info"]
    
    # Store phone number in Supabase
    try:
        supabase.table("users").upsert({
            "deriv_user_id": user_info["user_id"],
            "phone_number": phone_data.phone_number
        }).execute()
        return {"message": "Phone number added successfully"}
    except Exception as e:
        raise HTTPException(status_code=500, detail="Failed to store phone number")

@app.get("/logout")
async def logout(token: str = Depends(oauth2_scheme)):
    """Handle user logout"""
    if token not in user_sessions:
        raise HTTPException(status_code=401, detail="Invalid or expired session")
    
    try:
        # Get user info
        user_info = user_sessions[token]["user_info"]
        
        # Delete phone number from Supabase
        supabase.table("users").delete().eq("deriv_user_id", user_info["user_id"]).execute()
        
        # Revoke Deriv token
        async with httpx.AsyncClient() as client:
            await client.post(
                "https://api.deriv.com/oauth2/revoke",
                data={
                    "token": token,
                    "app_id": DERIV_APP_ID,
                    "app_secret": DERIV_APP_SECRET,
                },
            )
        
        # Remove session
        del user_sessions[token]
        
        return {"message": "Logged out successfully"}
    except Exception as e:
        raise HTTPException(status_code=500, detail="Failed to complete logout process")

async def get_mpesa_access_token():
    """Get M-Pesa access token"""
    credentials = base64.b64encode(f"{MPESA_CONSUMER_KEY}:{MPESA_CONSUMER_SECRET}".encode()).decode()
    response = requests.get(
        "https://sandbox.safaricom.co.ke/oauth/v1/generate?grant_type=client_credentials" if MPESA_ENV == "sandbox"
        else "https://api.safaricom.co.ke/oauth/v1/generate?grant_type=client_credentials",
        headers={"Authorization": f"Basic {credentials}"}
    )
    return response.json()["access_token"]

@app.post("/deposit")
async def initiate_deposit(
    deposit_request: DepositRequest,
    token: str = Depends(oauth2_scheme)
):
    """Handle deposit via M-Pesa"""
    if token not in user_sessions:
        raise HTTPException(status_code=401, detail="Invalid or expired session")
    
    # Convert KES to USD
    usd_amount = deposit_request.amount / USD_TO_KES_RATE
    
    # Check minimum and maximum deposit limits
    if usd_amount < 2 or usd_amount > 1000:
        raise HTTPException(
            status_code=400,
            detail="Deposit amount must be between 2 USD and 1000 USD"
        )
    
    try:
        # Get M-Pesa access token
        access_token = await get_mpesa_access_token()
        
        # Generate timestamp
        timestamp = datetime.now().strftime("%Y%m%d%H%M%S")
        password = base64.b64encode(
            f"{MPESA_SHORTCODE}{MPESA_PASSKEY}{timestamp}".encode()
        ).decode()
        
        # Initiate STK Push
        stk_push_url = "https://sandbox.safaricom.co.ke/mpesa/stkpush/v1/processrequest" if MPESA_ENV == "sandbox" \
            else "https://api.safaricom.co.ke/mpesa/stkpush/v1/processrequest"
        
        response = requests.post(
            stk_push_url,
            headers={
                "Authorization": f"Bearer {access_token}",
                "Content-Type": "application/json",
            },
            json={
                "BusinessShortCode": MPESA_SHORTCODE,
                "Password": password,
                "Timestamp": timestamp,
                "TransactionType": "CustomerPayBillOnline",
                "Amount": int(deposit_request.amount),
                "PartyA": deposit_request.phone_number,
                "PartyB": MPESA_SHORTCODE,
                "PhoneNumber": deposit_request.phone_number,
                "CallBackURL": f"{REDIRECT_URI}/mpesa/callback",
                "AccountReference": "DerivDeposit",
                "TransactionDesc": "Deposit to Deriv Account"
            }
        )
        
        if response.status_code != 200:
            raise HTTPException(status_code=400, detail="Failed to initiate deposit")
        
        # Store transaction details in Supabase
        supabase.table("transactions").insert({
            "deriv_user_id": user_sessions[token]["user_info"]["user_id"],
            "type": "deposit",
            "amount_kes": deposit_request.amount,
            "amount_usd": usd_amount,
            "status": "pending",
            "phone_number": deposit_request.phone_number
        }).execute()
        
        return response.json()
    except Exception as e:
        raise HTTPException(status_code=500, detail="Failed to process deposit")

@app.post("/withdrawal")
async def initiate_withdrawal(
    withdrawal_request: WithdrawalRequest,
    token: str = Depends(oauth2_scheme)
):
    """Handle withdrawal via M-Pesa B2C"""
    if token not in user_sessions:
        raise HTTPException(status_code=401, detail="Invalid or expired session")
    
    # Convert USD to KES
    kes_amount = withdrawal_request.amount * KES_TO_USD_RATE
    
    # Check minimum and maximum withdrawal limits
    if withdrawal_request.amount < 2 or withdrawal_request.amount > 2000:
        raise HTTPException(
            status_code=400,
            detail="Withdrawal amount must be between 2 USD and 2000 USD"
        )
    
    try:
        # Verify user's balance through Deriv API
        async with httpx.AsyncClient() as client:
            balance_response = await client.get(
                "https://api.deriv.com/api/v1/balance",
                headers={"Authorization": f"Bearer {token}"}
            )
            
            if balance_response.status_code != 200:
                raise HTTPException(status_code=400, detail="Failed to verify balance")
            
            balance = balance_response.json()["balance"]
            if balance < withdrawal_request.amount:
                raise HTTPException(status_code=400, detail="Insufficient balance")
        
        # Get M-Pesa access token
        access_token = await get_mpesa_access_token()
        
        # Initiate B2C transaction
        b2c_url = "https://sandbox.safaricom.co.ke/mpesa/b2c/v1/paymentrequest" if MPESA_ENV == "sandbox" \
            else "https://api.safaricom.co.ke/mpesa/b2c/v1/paymentrequest"
        
        response = requests.post(
            b2c_url,
            headers={
                "Authorization": f"Bearer {access_token}",
                "Content-Type": "application/json",
            },
            json={
                "InitiatorName": os.getenv("MPESA_INITIATOR_NAME"),
                "SecurityCredential": os.getenv("MPESA_SECURITY_CREDENTIAL"),
                "CommandID": "BusinessPayment",
                "Amount": int(kes_amount),
                "PartyA": MPESA_SHORTCODE,
                "PartyB": withdrawal_request.phone_number,
                "Remarks": "Withdrawal from Deriv Account",
                "QueueTimeOutURL": f"{REDIRECT_URI}/mpesa/timeout",
                "ResultURL": f"{REDIRECT_URI}/mpesa/result",
                "Occasion": "Withdrawal"
            }
        )
        
        if response.status_code != 200:
            raise HTTPException(status_code=400, detail="Failed to initiate withdrawal")
        
        # Store transaction details in Supabase
        supabase.table("transactions").insert({
            "deriv_user_id": user_sessions[token]["user_info"]["user_id"],
            "type": "withdrawal",
            "amount_kes": kes_amount,
            "amount_usd": withdrawal_request.amount,
            "status": "pending",
            "phone_number": withdrawal_request.phone_number,
            "email": withdrawal_request.email
        }).execute()
        
        return response.json()
    except Exception as e:
        raise HTTPException(status_code=500, detail="Failed to process withdrawal")

@app.post("/mpesa/callback")
async def mpesa_callback(request: Request):
    """Handle M-Pesa STK Push callback"""
    callback_data = await request.json()
    
    try:
        # Update transaction status in Supabase
        result = callback_data["Body"]["stkCallback"]["ResultDesc"]
        merchant_request_id = callback_data["Body"]["stkCallback"]["MerchantRequestID"]
        
        transaction = supabase.table("transactions").select("*").eq(
            "merchant_request_id", merchant_request_id
        ).execute()
        
        if result == "The service request is processed successfully.":
            # Update transaction status
            supabase.table("transactions").update({
                "status": "completed"
            }).eq("merchant_request_id", merchant_request_id).execute()
            
            # Transfer funds to user's Deriv account
            # Implement Deriv transfer API call here
            
        else:
            supabase.table("transactions").update({
                "status": "failed",
                "failure_reason": result
            }).eq("merchant_request_id", merchant_request_id).execute()
        
        return {"status": "success"}
    except Exception as e:
        return {"status": "error", "message": str(e)}

@app.post("/mpesa/result")
async def mpesa_result(request: Request):
    """Handle M-Pesa B2C result"""
    result_data = await request.json()
    
    try:
        # Update transaction status in Supabase
        conversation_id = result_data["ConversationID"]
        result = result_data["Result"]["ResultDesc"]
        
        transaction = supabase.table("transactions").select("*").eq(
            "conversation_id", conversation_id
        ).execute()
        
        if result == "The service request is processed successfully.":
            supabase.table("transactions").update({
                "status": "completed"
            }).eq("conversation_id", conversation_id).execute()
        else:
            supabase.table("transactions").update({
                "status": "failed",
                "failure_reason": result
            }).eq("conversation_id", conversation_id).execute()
        
        return {"status": "success"}
    except Exception as e:
        return {"status": "error", "message": str(e)}