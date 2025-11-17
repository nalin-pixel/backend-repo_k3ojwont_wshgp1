"""
Takuezy Housing - Database Schemas

Each Pydantic model represents a MongoDB collection.
Collection name is the lowercase of the class name (e.g., User -> "user").
"""
from typing import Optional, List, Literal
from pydantic import BaseModel, Field, EmailStr

# Shared
class Location(BaseModel):
    lat: float = Field(..., description="Latitude")
    lng: float = Field(..., description="Longitude")
    address: Optional[str] = Field(None, description="Human-readable address")

# Users
class User(BaseModel):
    full_name: str
    role: Literal["tenant", "landlord", "lodge_owner", "admin"]
    email: Optional[EmailStr] = None
    phone: Optional[str] = None
    national_id: str = Field(..., description="Zimbabwe National ID number")
    password_hash: str
    is_approved: bool = False
    id_verified: bool = False

# Listings
class Listing(BaseModel):
    owner_id: str = Field(..., description="Owner user _id as string")
    title: str
    description: Optional[str] = None
    price: float = Field(..., ge=0)
    pricing_type: Literal["monthly", "daily", "hourly"] = "monthly"
    property_type: Literal["house", "room", "apartment", "lodge_room", "other"] = "room"
    facilities: List[str] = []
    media_urls: List[str] = []
    location: Location
    is_available: bool = True

# Applications
class Application(BaseModel):
    listing_id: str
    tenant_id: str
    message: Optional[str] = None
    national_id: str
    status: Literal["pending", "approved", "rejected"] = "pending"

# Payments
class Payment(BaseModel):
    listing_id: str
    tenant_id: str
    owner_id: str
    amount: float = Field(..., ge=0)
    method: Literal["ecocash", "paynow"]
    platform_fee: float = 0.0
    owner_amount: float = 0.0
    status: Literal["initiated", "successful", "failed"] = "initiated"
    receipt_id: Optional[str] = None

class Receipt(BaseModel):
    payment_id: str
    total: float
    owner_amount: float
    platform_fee: float
    payee_phone: Optional[str] = None
    reference: str

# Notifications (optional for future)
class Notification(BaseModel):
    user_id: str
    type: str
    title: str
    body: str
    read: bool = False
