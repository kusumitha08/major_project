from functools import wraps
from datetime import datetime
import hmac
import json
import os
import re
import secrets
import sys

from fastapi import FastAPI, Request
from fastapi.middleware.cors import CORSMiddleware
from fastapi.responses import JSONResponse
from starlette.middleware.sessions import SessionMiddleware
from web3 import AsyncWeb3
from web3.providers import AsyncHTTPProvider

sys.path.append(os.path.join(os.path.dirname(__file__), '..', 'crypto_core'))
from crypto_utils import generate_identity_hash, generate_name_hash, sign_identity, verify_signature
from keys import load_or_generate_keys

try:
    from .auth_store import (
        DEVELOPER_USNS,
        hash_aadhaar_pin,
        hash_password,
        load_accounts,
        load_aadhaar_pins,
        save_accounts,
        save_aadhaar_pins,
        verify_aadhaar_pin,
        verify_developer_password,
        verify_password,
    )
except ImportError:
    from auth_store import (
        DEVELOPER_USNS,
        hash_aadhaar_pin,
        hash_password,
        load_accounts,
        load_aadhaar_pins,
        save_accounts,
        save_aadhaar_pins,
        verify_aadhaar_pin,
        verify_developer_password,
        verify_password,
    )

app = FastAPI(title="Cross-Blockchain Middleware")

SESSION_SECRET_FILE = os.path.join(os.path.dirname(__file__), ".session_secret")
if not os.path.exists(SESSION_SECRET_FILE):
    with open(SESSION_SECRET_FILE, "x", encoding="utf-8") as secret_file:
        secret_file.write(secrets.token_hex(32))
with open(SESSION_SECRET_FILE, "r", encoding="utf-8") as secret_file:
    session_secret = secret_file.read().strip()

app.add_middleware(
    SessionMiddleware,
    secret_key=session_secret,
    session_cookie="session",
    max_age=60 * 60 * 24 * 30,
    same_site="lax",
    https_only=False,
)
app.add_middleware(
    CORSMiddleware,
    allow_origin_regex=r"https?://(?:localhost|127\.0\.0\.1)(?::\d+)?",
    allow_credentials=True,
    allow_methods=["*"],
    allow_headers=["*"],
)


def require_roles(*allowed_roles):
    def decorator(view):
        @wraps(view)
        async def wrapped(request: Request, *args, **kwargs):
            user = request.session.get("user")
            if not user:
                return JSONResponse({"error": "Please sign in to continue"}, status_code=401)
            if user.get("role") not in allowed_roles:
                return JSONResponse({"error": "You do not have permission to access this service"}, status_code=403)
            return await view(request, *args, **kwargs)

        return wrapped

    return decorator


async def establish_session(request: Request, role, username, email, name=None):
    request.session.clear()
    user = {
        "role": role,
        "username": username,
        "email": email,
        "name": name or username,
    }
    request.session["user"] = user
    return JSONResponse({"success": True, "user": user})


# ─────────────────────────────────────────
# Connect to Ganache
# ─────────────────────────────────────────
w3 = AsyncWeb3(AsyncHTTPProvider("http://127.0.0.1:8545"))
ganache_connected = False
default_account = None


async def initialize_blockchain():
    global ganache_connected, default_account
    ganache_connected = await w3.is_connected()
    if ganache_connected:
        print("   ✅ Connected to Ganache blockchain!")
        accounts = await w3.eth.accounts
        if accounts:
            default_account = accounts[0]
            w3.eth.default_account = default_account
    else:
        print("   ❌ Could not connect to Ganache!")


@app.on_event("startup")
async def startup_event():
    await initialize_blockchain()


# ─────────────────────────────────────────
# Load contract addresses
# ─────────────────────────────────────────
ADDRESSES_FILE = os.path.join(
    os.path.dirname(__file__), '..', 'crypto_core', 'contract_addresses.json'
)
with open(ADDRESSES_FILE, encoding="utf-8") as f:
    addresses = json.load(f)

AADHAAR_ADDRESS = addresses["AadhaarRegistry"]
PASSPORT_ADDRESS = addresses["PassportRegistry"]

# ─────────────────────────────────────────
# Load contract ABIs from build folder
# ─────────────────────────────────────────
BUILD_DIR = os.path.join(os.path.dirname(__file__), '..', 'build', 'contracts')

with open(os.path.join(BUILD_DIR, 'AadhaarRegistry.json'), encoding="utf-8") as f:
    AADHAAR_ABI = json.load(f)["abi"]

with open(os.path.join(BUILD_DIR, 'PassportRegistry.json'), encoding="utf-8") as f:
    PASSPORT_ABI = json.load(f)["abi"]

# ─────────────────────────────────────────
# Create contract instances
# ─────────────────────────────────────────
aadhaar_contract = w3.eth.contract(
    address=AsyncWeb3.to_checksum_address(AADHAAR_ADDRESS),
    abi=AADHAAR_ABI,
)
passport_contract = w3.eth.contract(
    address=AsyncWeb3.to_checksum_address(PASSPORT_ADDRESS),
    abi=PASSPORT_ABI,
)

# ─────────────────────────────────────────
# Load shared ECDSA keys
# ─────────────────────────────────────────
private_key, public_key = load_or_generate_keys()


async def send_transaction(func):
    tx_hash = await func.transact({"from": default_account})
    tx_receipt = await w3.eth.wait_for_transaction_receipt(tx_hash)
    return tx_receipt


async def find_approved_application(aadhaar_id):
    total = await passport_contract.functions.getTotalApplications().call()
    for application_id in range(total, 0, -1):
        application = await passport_contract.functions.getApplication(application_id).call()
        if application[1] == aadhaar_id and application[2].strip().upper() == "APPROVED":
            return {
                "app_id": application_id,
                "applicant_name": application[0],
                "aadhaar_id": application[1],
                "status": application[2],
                "timestamp": application[3],
            }
    return None


@app.post("/auth/applicant/signup")
async def applicant_signup(request: Request):
    data = await request.json() or {}
    name = str(data.get("name", "")).strip()
    email = str(data.get("email", "")).strip().lower()
    password = str(data.get("password", ""))
    if not name or not re.fullmatch(r"[^\s@]+@[^\s@]+\.[^\s@]+", email) or len(password) < 8:
        return JSONResponse({"error": "Enter your name, a valid email, and a password with at least 8 characters"}, status_code=400)

    accounts = load_accounts()
    if email in accounts["applicants"]:
        return JSONResponse({"error": "An account already exists for this email. Please sign in."}, status_code=409)

    accounts["applicants"][email] = {
        "name": name,
        "email": email,
        **hash_password(password),
    }
    save_accounts(accounts)
    return await establish_session(request, "applicant", email, email, name)


@app.post("/auth/applicant/login")
async def applicant_login(request: Request):
    data = await request.json() or {}
    email = str(data.get("email", "")).strip().lower()
    password = str(data.get("password", ""))
    account = load_accounts()["applicants"].get(email)
    if not account or not verify_password(password, account):
        return JSONResponse({"error": "Email or password is incorrect"}, status_code=401)
    return await establish_session(request, "applicant", email, email, account["name"])


@app.post("/auth/developer/login")
async def developer_login(request: Request):
    data = await request.json() or {}
    usn = str(data.get("usn", "")).strip().lower()
    password = str(data.get("password", ""))
    if usn not in DEVELOPER_USNS:
        return JSONResponse({"error": "This USN is not authorized for developer access"}, status_code=403)

    if not verify_developer_password(password):
        return JSONResponse({"error": "USN or password is incorrect"}, status_code=401)
    return await establish_session(request, "developer", usn, "")


@app.get("/auth/session")
async def auth_session(request: Request):
    user = request.session.get("user")
    return JSONResponse({"authenticated": bool(user), "user": user})


@app.post("/auth/logout")
async def auth_logout(request: Request):
    request.session.clear()
    return JSONResponse({"success": True})


@app.get("/")
async def home():
    return JSONResponse({
        "message": "Cross-Blockchain Middleware running on Ganache!",
        "status": "online",
        "ganache": "connected" if ganache_connected else "disconnected",
        "aadhaar_contract": AADHAAR_ADDRESS,
        "passport_contract": PASSPORT_ADDRESS,
        "routes": [
            "GET  /health",
            "GET  /stats",
            "POST /auth/applicant/signup",
            "POST /auth/applicant/login",
            "POST /auth/developer/login",
            "GET  /auth/session",
            "POST /auth/logout",
            "POST /aadhaar/register",
            "GET  /aadhaar/citizens",
            "GET  /aadhaar/proof/<aadhaar_id>",
            "POST /aadhaar/verify/<aadhaar_id>",
            "POST /passport/apply",
            "GET  /passport/progress/<aadhaar_id>",
            "GET  /passport/applications",
            "GET  /passport/validate",
        ],
    })


@app.get("/health")
async def health():
    try:
        aadhaar_count = await aadhaar_contract.functions.getTotalRegistered().call()
        passport_count = await passport_contract.functions.getTotalApplications().call()
        return JSONResponse({
            "middleware": "online",
            "ganache": "connected",
            "aadhaar_registered": aadhaar_count,
            "passport_applications": passport_count,
            "block_number": await w3.eth.block_number,
            "network_id": await w3.net.version,
        })
    except Exception as e:
        return JSONResponse({"error": str(e)}, status_code=500)


@app.get("/stats")
async def public_stats():
    try:
        total = await passport_contract.functions.getTotalApplications().call()
        approved = 0
        rejected = 0
        for application_id in range(1, total + 1):
            status = (await passport_contract.functions.getApplication(application_id).call())[2]
            approved += status == "APPROVED"
            rejected += status == "REJECTED"
        return JSONResponse({
            "aadhaar_registered": await aadhaar_contract.functions.getTotalRegistered().call(),
            "passport_applications": total,
            "approved": approved,
            "rejected": rejected,
        })
    except Exception as e:
        return JSONResponse({"error": str(e)}, status_code=500)


@app.post("/aadhaar/register")
@require_roles("applicant")
async def register_citizen(request: Request):
    data = await request.json() or {}
    name = data.get("name")
    dob = data.get("dob")
    aadhaar_id = data.get("aadhaar_id")
    pin = str(data.get("pin", ""))

    if not name or not dob or not aadhaar_id or not re.fullmatch(r"\d{4}", pin):
        return JSONResponse({"error": "name, dob, aadhaar_id and a 4-digit pin are required"}, status_code=400)

    try:
        already = await aadhaar_contract.functions.isRegistered(aadhaar_id).call()
        if already:
            return JSONResponse({"error": "Aadhaar ID already registered on blockchain"}, status_code=400)

        identity_hash = generate_identity_hash(name, dob, aadhaar_id)
        name_hash = generate_name_hash(name)
        signature = sign_identity(private_key, identity_hash)

        receipt = await send_transaction(
            aadhaar_contract.functions.registerIdentity(
                aadhaar_id,
                name_hash,
                identity_hash,
                signature,
            )
        )

        pin_records = load_aadhaar_pins()
        pin_records[aadhaar_id] = {"name": name, **hash_aadhaar_pin(pin)}
        save_aadhaar_pins(pin_records)

        return JSONResponse({
            "success": True,
            "name": name,
            "aadhaar_id": aadhaar_id,
            "identity_hash": identity_hash,
            "transaction_hash": receipt.transactionHash.hex(),
            "block_number": receipt.blockNumber,
            "gas_used": receipt.gasUsed,
        })
    except Exception as e:
        return JSONResponse({"error": str(e)}, status_code=500)


@app.get("/aadhaar/citizens")
@require_roles("developer")
async def get_citizens(request: Request):
    try:
        total = await aadhaar_contract.functions.getTotalRegistered().call()
        citizens = []
        for i in range(total):
            aadhaar_id = await aadhaar_contract.functions.registeredIds(i).call()
            proof = await aadhaar_contract.functions.getIdentityProof(aadhaar_id).call()
            citizens.append({
                "aadhaar_id": aadhaar_id,
                "identity_hash": proof[0][:30] + "...",
                "timestamp": proof[3],
            })
        return JSONResponse({
            "total": total,
            "citizens": citizens,
        })
    except Exception as e:
        return JSONResponse({"error": str(e)}, status_code=500)


@app.get("/aadhaar/proof/{aadhaar_id}")
@require_roles("applicant")
async def get_identity_proof(request: Request, aadhaar_id: str):
    try:
        proof = await aadhaar_contract.functions.getIdentityProof(aadhaar_id).call()
        identity_hash = proof[0]
        signature = proof[1]
        name_hash = proof[2]
        timestamp = proof[3]
        exists = proof[4]

        if not exists:
            return JSONResponse({"found": False, "error": "Aadhaar ID not found"}, status_code=404)

        return JSONResponse({
            "found": True,
            "aadhaar_id": aadhaar_id,
            "identity_hash": identity_hash,
            "signature": signature,
            "name_hash": name_hash,
            "timestamp": timestamp,
            "block_number": await w3.eth.block_number,
        })
    except Exception as e:
        return JSONResponse({"error": str(e)}, status_code=500)


@app.post("/aadhaar/verify/{aadhaar_id}")
@require_roles("applicant")
async def verify_identity_proof(request: Request, aadhaar_id: str):
    try:
        data = await request.json() or {}
        applicant_name = str(data.get("name", "")).strip()
        pin = str(data.get("pin", ""))
        if not applicant_name or not re.fullmatch(r"\d{4}", pin):
            return JSONResponse({"authenticated": False, "error": "Name and a 4-digit PIN are required for identity verification"}, status_code=400)

        proof = await aadhaar_contract.functions.getIdentityProof(aadhaar_id).call()
        identity_hash = proof[0]
        signature = proof[1]
        name_hash = proof[2]
        timestamp = proof[3]
        exists = proof[4]

        if not exists:
            return JSONResponse({"authenticated": False, "error": "Aadhaar ID not found"}, status_code=404)

        authenticated = verify_signature(public_key, identity_hash, signature)
        if not authenticated:
            return JSONResponse({"authenticated": False, "error": "Identity proof could not be authenticated"}, status_code=401)
        if not hmac.compare_digest(generate_name_hash(applicant_name), name_hash):
            return JSONResponse({"authenticated": False, "error": "Name does not match the registered identity"}, status_code=401)
        pin_record = load_aadhaar_pins().get(aadhaar_id)
        if not pin_record or not verify_aadhaar_pin(pin, pin_record):
            return JSONResponse({"authenticated": False, "error": "PIN does not match the registered Aadhaar identity"}, status_code=401)

        approved_application = await find_approved_application(aadhaar_id)

        return JSONResponse({
            "authenticated": True,
            "already_applied": approved_application is not None,
            "previous_application": approved_application,
            "aadhaar_id": aadhaar_id,
            "identity_hash": identity_hash,
            "signature": signature,
            "name_hash": name_hash,
            "timestamp": timestamp,
            "block_number": await w3.eth.block_number,
        })
    except Exception as e:
        return JSONResponse({"error": str(e)}, status_code=500)


@app.post("/passport/apply")
@require_roles("applicant")
async def apply_for_passport(request: Request):
    data = await request.json() or {}
    applicant_name = data.get("name")
    aadhaar_id = data.get("aadhaar_id")
    pin = str(data.get("pin", ""))

    if not applicant_name or not aadhaar_id or not re.fullmatch(r"\d{4}", pin):
        return JSONResponse({"error": "name, aadhaar_id and a 4-digit pin are required"}, status_code=400)

    try:
        approved_application = await find_approved_application(aadhaar_id)
        if approved_application:
            return JSONResponse({
                "already_applied": True,
                "application": approved_application,
                "error": "A passport application for this Aadhaar ID has already been approved. You cannot apply again.",
            }, status_code=409)

        proof = await aadhaar_contract.functions.getIdentityProof(aadhaar_id).call()
        identity_hash = proof[0]
        signature = proof[1]
        name_hash = proof[2]
        exists = proof[4]

        if not exists:
            status = "REJECTED"
            reason = "Aadhaar ID not found on blockchain"
            verified = False
            identity_hash = "0" * 64
        else:
            pin_record = load_aadhaar_pins().get(aadhaar_id)
            pin_matches = bool(pin_record and verify_aadhaar_pin(pin, pin_record))
            identity_matches = verify_signature(public_key, identity_hash, signature) and hmac.compare_digest(generate_name_hash(applicant_name), name_hash)
            verified = identity_matches and pin_matches
            if verified:
                status = "APPROVED"
                reason = "Identity and PIN verified successfully"
            else:
                status = "REJECTED"
                reason = "PIN mismatch" if identity_matches else "Name mismatch or invalid identity proof"

        receipt = await send_transaction(
            passport_contract.functions.submitApplication(
                aadhaar_id,
                applicant_name,
                status,
                identity_hash,
            )
        )

        return JSONResponse({
            "applicant": applicant_name,
            "aadhaar_id": aadhaar_id,
            "status": status,
            "reason": reason,
            "verified": verified,
            "transaction_hash": receipt.transactionHash.hex(),
            "block_number": receipt.blockNumber,
            "gas_used": receipt.gasUsed,
            "timestamp": datetime.now().strftime("%Y-%m-%d %H:%M:%S"),
            "identity_hash": identity_hash[:30] + "...",
        })
    except Exception as e:
        return JSONResponse({"error": str(e)}, status_code=500)


@app.get("/passport/applications")
@require_roles("developer")
async def get_applications(request: Request):
    try:
        total = await passport_contract.functions.getTotalApplications().call()
        applications = []
        for i in range(1, total + 1):
            app_data = await passport_contract.functions.getApplication(i).call()
            applications.append({
                "app_id": i,
                "applicant_name": app_data[0],
                "aadhaar_id": app_data[1],
                "status": app_data[2],
                "timestamp": app_data[3],
            })
        return JSONResponse({
            "total": total,
            "applications": applications,
        })
    except Exception as e:
        return JSONResponse({"error": str(e)}, status_code=500)


@app.get("/passport/progress/{aadhaar_id}")
@require_roles("applicant")
async def get_applicant_progress(request: Request, aadhaar_id: str):
    try:
        total = await passport_contract.functions.getTotalApplications().call()
        applications = []
        for application_id in range(1, total + 1):
            app_data = await passport_contract.functions.getApplication(application_id).call()
            if app_data[1] == aadhaar_id:
                applications.append({
                    "app_id": application_id,
                    "applicant_name": app_data[0],
                    "aadhaar_id": app_data[1],
                    "status": app_data[2],
                    "timestamp": app_data[3],
                })
        proof = await aadhaar_contract.functions.getIdentityProof(aadhaar_id).call()
        return JSONResponse({
            "applications": applications,
            "registration_found": proof[4],
            "registration": ({"aadhaar_id": aadhaar_id} if proof[4] else None),
        })
    except Exception as e:
        return JSONResponse({"error": str(e)}, status_code=500)


@app.get("/passport/validate")
@require_roles("developer")
async def validate(request: Request):
    try:
        return JSONResponse({
            "valid": True,
            "block_number": await w3.eth.block_number,
            "total_registered": await aadhaar_contract.functions.getTotalRegistered().call(),
            "total_applications": await passport_contract.functions.getTotalApplications().call(),
            "aadhaar_contract": AADHAAR_ADDRESS,
            "passport_contract": PASSPORT_ADDRESS,
            "message": "Blockchain is valid and running on Ganache!",
        })
    except Exception as e:
        return JSONResponse({"error": str(e)}, status_code=500)


if __name__ == "__main__":
    import uvicorn

    print("\n✅ Cross-Blockchain Middleware Starting...")
    print(f"   Ganache              : http://127.0.0.1:8545")
    print(f"   Aadhaar Contract     : {AADHAAR_ADDRESS}")
    print(f"   Passport Contract    : {PASSPORT_ADDRESS}")
    print(f"   Server running at    : http://localhost:5000\n")
    uvicorn.run(app, host="127.0.0.1", port=5000, reload=False)