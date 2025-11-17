import os
from typing import List, Optional
from fastapi import FastAPI, HTTPException, Depends
from fastapi.middleware.cors import CORSMiddleware
from fastapi.security import OAuth2PasswordBearer, OAuth2PasswordRequestForm
from pydantic import BaseModel, EmailStr
from passlib.context import CryptContext
import jwt
from datetime import datetime, timedelta, timezone
from bson import ObjectId

from database import db, create_document, get_documents
from schemas import User, Listing, Application, Payment, Receipt

JWT_SECRET = os.getenv("JWT_SECRET", "devsecret")
JWT_ALG = "HS256"

pwd_context = CryptContext(schemes=["bcrypt"], deprecated="auto")
oauth2_scheme = OAuth2PasswordBearer(tokenUrl="/auth/login")

app = FastAPI(title="Takuezy Housing API")

app.add_middleware(
    CORSMiddleware,
    allow_origins=["*"],
    allow_credentials=True,
    allow_methods=["*"],
    allow_headers=["*"],
)

# Helpers
class Token(BaseModel):
    access_token: str
    token_type: str = "bearer"

class RegisterRequest(BaseModel):
    full_name: str
    role: str
    email: Optional[EmailStr] = None
    phone: Optional[str] = None
    national_id: str
    password: str

class ListingCreate(BaseModel):
    title: str
    description: Optional[str] = None
    price: float
    pricing_type: str
    property_type: str
    facilities: List[str] = []
    media_urls: List[str] = []
    location: dict
    is_available: bool = True

class ApplicationCreate(BaseModel):
    listing_id: str
    message: Optional[str] = None
    national_id: str

class PaymentInit(BaseModel):
    listing_id: str
    method: str

# Auth utils

def hash_password(password: str) -> str:
    return pwd_context.hash(password)

def verify_password(password: str, password_hash: str) -> bool:
    return pwd_context.verify(password, password_hash)

def create_token(data: dict, expires_minutes: int = 60 * 24):
    to_encode = data.copy()
    expire = datetime.now(timezone.utc) + timedelta(minutes=expires_minutes)
    to_encode.update({"exp": expire})
    return jwt.encode(to_encode, JWT_SECRET, algorithm=JWT_ALG)

def get_current_user(token: str = Depends(oauth2_scheme)):
    try:
        payload = jwt.decode(token, JWT_SECRET, algorithms=[JWT_ALG])
        user_id = payload.get("sub")
        if not user_id:
            raise HTTPException(status_code=401, detail="Invalid token")
        user = db["user"].find_one({"_id": ObjectId(user_id)})
        if not user:
            raise HTTPException(status_code=401, detail="User not found")
        return user
    except Exception:
        raise HTTPException(status_code=401, detail="Could not validate credentials")

@app.get("/")
def root():
    return {"message": "Hello from FastAPI Backend!"}

@app.get("/api/hello")
def hello():
    return {"message": "Hello from the backend API!"}

@app.get("/test")
def test_database():
    response = {
        "backend": "✅ Running",
        "database": "❌ Not Available",
        "database_url": None,
        "database_name": None,
        "connection_status": "Not Connected",
        "collections": []
    }

    try:
        if db is not None:
            response["database"] = "✅ Available"
            response["database_url"] = "✅ Configured"
            response["database_name"] = db.name if hasattr(db, 'name') else "✅ Connected"
            response["connection_status"] = "Connected"
            try:
                collections = db.list_collection_names()
                response["collections"] = collections[:10]
                response["database"] = "✅ Connected & Working"
            except Exception as e:
                response["database"] = f"⚠️  Connected but Error: {str(e)[:50]}"
        else:
            response["database"] = "⚠️  Available but not initialized"
    except Exception as e:
        response["database"] = f"❌ Error: {str(e)[:50]}"

    response["database_url"] = "✅ Set" if os.getenv("DATABASE_URL") else "❌ Not Set"
    response["database_name"] = "✅ Set" if os.getenv("DATABASE_NAME") else "❌ Not Set"
    return response

# Auth endpoints
@app.post("/auth/register", response_model=Token)
def register(body: RegisterRequest):
    if not body.email and not body.phone:
        raise HTTPException(status_code=400, detail="Email or phone required")
    existing = db["user"].find_one({
        "$or": [
            {"email": body.email} if body.email else {},
            {"phone": body.phone} if body.phone else {},
            {"national_id": body.national_id}
        ]
    })
    if existing:
        raise HTTPException(status_code=400, detail="User already exists")

    user_doc = User(
        full_name=body.full_name,
        role=body.role,
        email=body.email,
        phone=body.phone,
        national_id=body.national_id,
        password_hash=hash_password(body.password),
    ).model_dump()

    user_id = create_document("user", user_doc)
    token = create_token({"sub": user_id})
    return Token(access_token=token)

@app.post("/auth/login", response_model=Token)
def login(form_data: OAuth2PasswordRequestForm = Depends()):
    identifier = form_data.username
    password = form_data.password
    user = db["user"].find_one({
        "$or": [
            {"email": identifier},
            {"phone": identifier},
            {"national_id": identifier}
        ]
    })
    if not user or not verify_password(password, user.get("password_hash", "")):
        raise HTTPException(status_code=401, detail="Invalid credentials")
    token = create_token({"sub": str(user["_id"])})
    return Token(access_token=token)

# Listings
@app.post("/listings")
def create_listing(body: ListingCreate, current=Depends(get_current_user)):
    if current.get("role") not in ["landlord", "lodge_owner", "admin"]:
        raise HTTPException(status_code=403, detail="Only owners can create listings")
    listing = Listing(
        owner_id=str(current["_id"]),
        title=body.title,
        description=body.description,
        price=body.price,
        pricing_type=body.pricing_type,
        property_type=body.property_type,
        facilities=body.facilities,
        media_urls=body.media_urls,
        location=body.location,  # validated as dict here
        is_available=body.is_available
    ).model_dump()
    listing_id = create_document("listing", listing)
    return {"id": listing_id}

@app.get("/listings")
def search_listings(
    q: Optional[str] = None,
    property_type: Optional[str] = None,
    min_price: Optional[float] = None,
    max_price: Optional[float] = None,
    is_available: Optional[bool] = True,
):
    filters = {}
    if property_type:
        filters["property_type"] = property_type
    if is_available is not None:
        filters["is_available"] = is_available
    if min_price is not None or max_price is not None:
        price_filter = {}
        if min_price is not None:
            price_filter["$gte"] = min_price
        if max_price is not None:
            price_filter["$lte"] = max_price
        filters["price"] = price_filter
    if q:
        filters["$or"] = [
            {"title": {"$regex": q, "$options": "i"}},
            {"description": {"$regex": q, "$options": "i"}},
            {"facilities": {"$elemMatch": {"$regex": q, "$options": "i"}}}
        ]
    results = get_documents("listing", filters, limit=100)
    for r in results:
        r["_id"] = str(r["_id"])
    return {"items": results}

@app.patch("/listings/{listing_id}/availability")
def update_availability(listing_id: str, is_available: bool, current=Depends(get_current_user)):
    listing = db["listing"].find_one({"_id": ObjectId(listing_id)})
    if not listing:
        raise HTTPException(status_code=404, detail="Listing not found")
    if str(listing["owner_id"]) != str(current["_id"]) and current.get("role") != "admin":
        raise HTTPException(status_code=403, detail="Not allowed")
    db["listing"].update_one({"_id": ObjectId(listing_id)}, {"$set": {"is_available": is_available, "updated_at": datetime.now(timezone.utc)}})
    return {"success": True}

# Applications
@app.post("/applications")
def apply(body: ApplicationCreate, current=Depends(get_current_user)):
    if current.get("role") not in ["tenant", "admin"]:
        raise HTTPException(status_code=403, detail="Only tenants can apply")
    listing = db["listing"].find_one({"_id": ObjectId(body.listing_id)})
    if not listing:
        raise HTTPException(status_code=404, detail="Listing not found")
    app_doc = Application(
        listing_id=body.listing_id,
        tenant_id=str(current["_id"]),
        message=body.message,
        national_id=body.national_id,
    ).model_dump()
    app_id = create_document("application", app_doc)
    return {"id": app_id}

@app.post("/applications/{application_id}/approve")
def approve_application(application_id: str, approve: bool = True, current=Depends(get_current_user)):
    application = db["application"].find_one({"_id": ObjectId(application_id)})
    if not application:
        raise HTTPException(status_code=404, detail="Application not found")
    listing = db["listing"].find_one({"_id": ObjectId(application["listing_id"])})
    if not listing:
        raise HTTPException(status_code=404, detail="Listing not found")
    if str(listing["owner_id"]) != str(current["_id"]) and current.get("role") != "admin":
        raise HTTPException(status_code=403, detail="Not allowed")
    db["application"].update_one({"_id": ObjectId(application_id)}, {"$set": {"status": "approved" if approve else "rejected", "updated_at": datetime.now(timezone.utc)}})
    return {"success": True}

# Convenience lists for dashboards
@app.get("/applications/me")
def my_applications(current=Depends(get_current_user)):
    cur_id = str(current["_id"])
    items = get_documents("application", {"tenant_id": cur_id}, limit=200)
    for it in items:
        it["_id"] = str(it["_id"])
    return {"items": items}

@app.get("/applications/for-me")
def applications_for_me(current=Depends(get_current_user)):
    cur_id = str(current["_id"])  # owner
    # Find listings by this owner, then applications referencing them
    listing_ids = [str(l["_id"]) for l in get_documents("listing", {"owner_id": cur_id}, limit=500)]
    items = get_documents("application", {"listing_id": {"$in": listing_ids}}, limit=200)
    for it in items:
        it["_id"] = str(it["_id"])
    return {"items": items}

# Payments (mock integration with 95/5 split)
@app.post("/payments/init")
def init_payment(body: PaymentInit, current=Depends(get_current_user)):
    if current.get("role") not in ["tenant", "admin"]:
        raise HTTPException(status_code=403, detail="Only tenants can pay")
    listing = db["listing"].find_one({"_id": ObjectId(body.listing_id)})
    if not listing:
        raise HTTPException(status_code=404, detail="Listing not found")
    owner_id = listing["owner_id"]

    # Calculate split
    amount = float(listing["price"])  # for demo use price as payment amount
    platform_fee = round(amount * 0.05, 2)
    owner_amount = round(amount - platform_fee, 2)

    payment = Payment(
        listing_id=str(listing["_id"]),
        tenant_id=str(current["_id"]),
        owner_id=str(owner_id),
        amount=amount,
        method=body.method,
        platform_fee=platform_fee,
        owner_amount=owner_amount,
        status="successful",  # mock success
        receipt_id=None,
    ).model_dump()
    payment_id = create_document("payment", payment)

    receipt = {"payment_id": payment_id, "total": amount, "owner_amount": owner_amount, "platform_fee": platform_fee, "payee_phone": os.getenv("PLATFORM_PHONE", "+263 778 864 239"), "reference": f"TAK-{payment_id[:6].upper()}"}
    receipt_id = create_document("receipt", receipt)

    # Link receipt to payment
    db["payment"].update_one({"_id": ObjectId(payment_id)}, {"$set": {"receipt_id": receipt_id}})

    return {"payment_id": payment_id, "receipt_id": receipt_id, "owner_amount": owner_amount, "platform_fee": platform_fee}

@app.get("/payments/me")
def my_payments(current=Depends(get_current_user)):
    cur_id = str(current["_id"])  # tenant
    items = get_documents("payment", {"tenant_id": cur_id}, limit=200)
    for it in items:
        it["_id"] = str(it["_id"])        
    return {"items": items}

@app.get("/payments/for-me")
def payments_for_me(current=Depends(get_current_user)):
    cur_id = str(current["_id"])  # owner
    items = get_documents("payment", {"owner_id": cur_id}, limit=200)
    for it in items:
        it["_id"] = str(it["_id"])        
    return {"items": items}

# Admin actions
@app.get("/admin/users")
def list_users(current=Depends(get_current_user)):
    if current.get("role") != "admin":
        raise HTTPException(status_code=403, detail="Admin only")
    users = get_documents("user", {}, limit=200)
    for u in users:
        u["_id"] = str(u["_id"])        
    return {"items": users}

@app.post("/admin/users/{user_id}/approve")
def approve_user(user_id: str, approve: bool = True, current=Depends(get_current_user)):
    if current.get("role") != "admin":
        raise HTTPException(status_code=403, detail="Admin only")
    db["user"].update_one({"_id": ObjectId(user_id)}, {"$set": {"is_approved": bool(approve), "updated_at": datetime.now(timezone.utc)}})
    return {"success": True}

@app.post("/admin/users/{user_id}/verify-id")
def verify_id(user_id: str, verified: bool = True, current=Depends(get_current_user)):
    if current.get("role") != "admin":
        raise HTTPException(status_code=403, detail="Admin only")
    db["user"].update_one({"_id": ObjectId(user_id)}, {"$set": {"id_verified": bool(verified), "updated_at": datetime.now(timezone.utc)}})
    return {"success": True}

if __name__ == "__main__":
    import uvicorn
    port = int(os.getenv("PORT", 8000))
    uvicorn.run(app, host="0.0.0.0", port=port)
