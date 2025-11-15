import os
import re
from typing import List, Optional
from fastapi import FastAPI, HTTPException, Header, Depends
from fastapi.middleware.cors import CORSMiddleware
from pydantic import BaseModel, EmailStr
from database import db, create_document
from schemas import User as UserSchema, Game as GameSchema, Order as OrderSchema, Coupon as CouponSchema, Review as ReviewSchema
from bson.objectid import ObjectId
import hashlib
import secrets
import smtplib
from email.mime.text import MIMEText
from datetime import datetime

app = FastAPI(title="Game Store API")

app.add_middleware(
    CORSMiddleware,
    allow_origins=["*"],
    allow_credentials=True,
    allow_methods=["*"],
    allow_headers=["*"],
)


# ------------ Helpers ------------ #

def hash_password(password: str, salt: str) -> str:
    return hashlib.sha256((password + salt).encode()).hexdigest()


def require_admin(x_auth_token: Optional[str] = Header(None)):
    if not x_auth_token:
        raise HTTPException(status_code=401, detail="Auth token missing")
    user = db["user"].find_one({"api_token": x_auth_token})
    if not user:
        raise HTTPException(status_code=401, detail="Invalid token")
    if user.get("role") != "admin":
        raise HTTPException(status_code=403, detail="Admin access required")
    return user


def optional_user(x_auth_token: Optional[str] = Header(None)):
    if not x_auth_token:
        return None
    return db["user"].find_one({"api_token": x_auth_token})


def send_email(to_email: str, subject: str, body: str) -> bool:
    host = os.getenv("SMTP_HOST")
    port = int(os.getenv("SMTP_PORT", "0") or 0)
    user = os.getenv("SMTP_USER")
    password = os.getenv("SMTP_PASS")
    sender = os.getenv("STORE_SENDER", user or "noreply@example.com")
    if not host or not port or not user or not password:
        # Email not configured
        return False
    try:
        msg = MIMEText(body, "plain", "utf-8")
        msg["Subject"] = subject
        msg["From"] = sender
        msg["To"] = to_email
        with smtplib.SMTP_SSL(host, port, timeout=10) as server:
            server.login(user, password)
            server.sendmail(sender, [to_email], msg.as_string())
        return True
    except Exception:
        return False


# ------------ Startup: Seed Admin ------------ #

@app.on_event("startup")
def seed_admin_user():
    try:
        admin_email = (os.getenv("ADMIN_EMAIL", "replikaai512@gmail.com") or "").strip().lower()
        admin_password = os.getenv("ADMIN_PASSWORD", "RsGhor#2025")
        # Ensure DB is available
        if db is None:
            return
        existing = db["user"].find_one({"email": admin_email})
        salt = secrets.token_hex(16)
        password_hash = hash_password(admin_password, salt)
        if not existing:
            user_doc = UserSchema(
                name="RS Game Ghor Admin",
                email=admin_email,
                password_hash=password_hash,
                salt=salt,
                role="admin",
                is_active=True,
            )
            user_id = create_document("user", user_doc)
            token = secrets.token_hex(24)
            db["user"].update_one({"_id": ObjectId(user_id)}, {"$set": {"api_token": token}})
        else:
            # Ensure role admin and password matches the configured one
            updates = {
                "role": "admin",
                "is_active": True,
                "password_hash": password_hash,
                "salt": salt,
            }
            if not existing.get("api_token"):
                updates["api_token"] = secrets.token_hex(24)
            db["user"].update_one({"_id": existing["_id"]}, {"$set": updates})
    except Exception:
        # Best-effort seeding; don't crash app on failure
        pass


# ------------ Root & Health ------------ #

@app.get("/")
def read_root():
    return {"message": "Game Store Backend Running"}


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
            response["database_url"] = "✅ Set" if os.getenv("DATABASE_URL") else "❌ Not Set"
            response["database_name"] = db.name if hasattr(db, 'name') else "❌ Unknown"
            response["connection_status"] = "Connected"
            try:
                collections = db.list_collection_names()
                response["collections"] = collections[:10]
                response["database"] = "✅ Connected & Working"
            except Exception as e:
                response["database"] = f"⚠️ Connected but Error: {str(e)[:80]}"
        else:
            response["database"] = "⚠️ Available but not initialized"
    except Exception as e:
        response["database"] = f"❌ Error: {str(e)[:80]}"
    return response


# ------------ Auth ------------ #

class RegisterRequest(BaseModel):
    name: str
    email: EmailStr
    password: str
    admin_code: Optional[str] = None


class AuthResponse(BaseModel):
    token: str
    role: str
    name: str
    email: EmailStr


@app.post("/auth/register", response_model=AuthResponse)
def register(req: RegisterRequest):
    # Normalize inputs
    name_raw = (req.name or "").strip()
    email_norm = (req.email or "").strip().lower()

    # Disallow duplicate email (case-insensitive) or name (case-insensitive)
    by_email = db["user"].find_one({"email": email_norm})
    if by_email:
        raise HTTPException(status_code=400, detail="Email already registered")

    name_regex = {"$regex": f"^{re.escape(name_raw)}$", "$options": "i"}
    by_name = db["user"].find_one({"name": name_regex})
    if by_name:
        raise HTTPException(status_code=400, detail="Name already taken")

    salt = secrets.token_hex(16)
    password_hash = hash_password(req.password, salt)
    role = "admin" if (req.admin_code and req.admin_code == os.getenv("ADMIN_CODE", "admin123")) else "user"

    user_doc = UserSchema(
        name=name_raw,
        email=email_norm,
        password_hash=password_hash,
        salt=salt,
        role=role,
        is_active=True,
    )
    user_id = create_document("user", user_doc)
    token = secrets.token_hex(24)
    db["user"].update_one({"_id": ObjectId(user_id)}, {"$set": {"api_token": token}})
    return {"token": token, "role": role, "name": name_raw, "email": email_norm}


class LoginRequest(BaseModel):
    email: EmailStr
    password: str


@app.post("/auth/login", response_model=AuthResponse)
def login(req: LoginRequest):
    email_norm = (req.email or "").strip().lower()
    user = db["user"].find_one({"email": email_norm})
    if not user:
        raise HTTPException(status_code=400, detail="Invalid credentials")
    hashed = hash_password(req.password, user.get("salt", ""))
    if hashed != user.get("password_hash"):
        raise HTTPException(status_code=400, detail="Invalid credentials")
    token = user.get("api_token") or secrets.token_hex(24)
    if not user.get("api_token"):
        db["user"].update_one({"_id": user["_id"]}, {"$set": {"api_token": token}})
    return {"token": token, "role": user.get("role", "user"), "name": user.get("name"), "email": user.get("email")}


# ------------ Games Public ------------ #

class GameCreateRequest(BaseModel):
    title: str
    description: Optional[str] = None
    price: float
    platform: str
    category: Optional[str] = None
    images: Optional[List[str]] = []
    in_stock: bool = True
    stock_count: int = 0
    featured: bool = False


class GamePublic(BaseModel):
    id: str
    title: str
    description: Optional[str] = None
    price: float
    platform: str
    category: Optional[str] = None
    images: List[str] = []
    in_stock: bool
    stock_count: int
    featured: bool


def map_game(doc) -> 'GamePublic':
    return GamePublic(
        id=str(doc["_id"]),
        title=doc.get("title"),
        description=doc.get("description"),
        price=float(doc.get("price", 0)),
        platform=doc.get("platform"),
        category=doc.get("category"),
        images=doc.get("images", []),
        in_stock=bool(doc.get("in_stock", True)),
        stock_count=int(doc.get("stock_count", 0)),
        featured=bool(doc.get("featured", False)),
    )


@app.get("/games", response_model=List['GamePublic'])
def list_games(platform: Optional[str] = None, q: Optional[str] = None, category: Optional[str] = None, featured: Optional[bool] = None):
    filt = {}
    if platform:
        filt["platform"] = platform
    if category:
        filt["category"] = category
    if featured is not None:
        filt["featured"] = bool(featured)
    if q:
        filt["title"] = {"$regex": q, "$options": "i"}
    docs = db["game"].find(filt).sort("created_at", -1)
    return [map_game(d) for d in docs]


@app.get("/games/{game_id}", response_model='GamePublic')
def get_game(game_id: str):
    try:
        doc = db["game"].find_one({"_id": ObjectId(game_id)})
    except Exception:
        raise HTTPException(status_code=400, detail="Invalid game id")
    if not doc:
        raise HTTPException(status_code=404, detail="Game not found")
    return map_game(doc)


# ------------ Reviews ------------ #

class ReviewCreateRequest(BaseModel):
    rating: int
    comment: Optional[str] = None
    author: Optional[str] = None


class ReviewPublic(BaseModel):
    id: str
    game_id: str
    rating: int
    comment: Optional[str] = None
    author: Optional[str] = None
    created_at: Optional[str] = None


def map_review(doc) -> 'ReviewPublic':
    return ReviewPublic(
        id=str(doc["_id"]),
        game_id=str(doc.get("game_id")),
        rating=int(doc.get("rating", 5)),
        comment=doc.get("comment"),
        author=doc.get("author"),
        created_at=(doc.get("created_at") or datetime.utcnow()).isoformat(),
    )


@app.get("/games/{game_id}/reviews", response_model=List['ReviewPublic'])
def list_reviews(game_id: str):
    docs = db["review"].find({"game_id": game_id}).sort("created_at", -1)
    return [map_review(d) for d in docs]


@app.post("/games/{game_id}/reviews", response_model='ReviewPublic')
def create_review(game_id: str, req: ReviewCreateRequest):
    # check game exists
    try:
        exists = db["game"].find_one({"_id": ObjectId(game_id)})
    except Exception:
        raise HTTPException(status_code=400, detail="Invalid game id")
    if not exists:
        raise HTTPException(status_code=404, detail="Game not found")
    review_doc = ReviewSchema(game_id=game_id, rating=req.rating, comment=req.comment, author=req.author)
    review_id = create_document("review", review_doc)
    created = db["review"].find_one({"_id": ObjectId(review_id)})
    return map_review(created)


# ------------ Coupons ------------ #

class CouponCreateRequest(BaseModel):
    code: str
    discount_percent: float
    active: bool = True
    expires_at: Optional[str] = None


class CouponPublic(BaseModel):
    id: str
    code: str
    discount_percent: float
    active: bool
    expires_at: Optional[str] = None


def map_coupon(doc) -> 'CouponPublic':
    return CouponPublic(
        id=str(doc["_id"]),
        code=doc.get("code"),
        discount_percent=float(doc.get("discount_percent", 0)),
        active=bool(doc.get("active", True)),
        expires_at=doc.get("expires_at"),
    )


@app.get("/admin/coupons", response_model=List['CouponPublic'])
def admin_list_coupons(user=Depends(require_admin)):
    docs = db["coupon"].find({}).sort("created_at", -1)
    return [map_coupon(d) for d in docs]


@app.post("/admin/coupons", response_model='CouponPublic')
def admin_create_coupon(req: CouponCreateRequest, user=Depends(require_admin)):
    existing = db["coupon"].find_one({"code": req.code})
    if existing:
        raise HTTPException(status_code=400, detail="Coupon code already exists")
    doc = CouponSchema(code=req.code.upper(), discount_percent=req.discount_percent, active=req.active, expires_at=req.expires_at)
    cid = create_document("coupon", doc)
    created = db["coupon"].find_one({"_id": ObjectId(cid)})
    return map_coupon(created)


class CouponUpdateRequest(BaseModel):
    discount_percent: Optional[float] = None
    active: Optional[bool] = None
    expires_at: Optional[str] = None


@app.put("/admin/coupons/{coupon_id}", response_model='CouponPublic')
def admin_update_coupon(coupon_id: str, req: CouponUpdateRequest, user=Depends(require_admin)):
    try:
        oid = ObjectId(coupon_id)
    except Exception:
        raise HTTPException(status_code=400, detail="Invalid coupon id")
    update = {k: v for k, v in req.model_dump().items() if v is not None}
    if not update:
        raise HTTPException(status_code=400, detail="Nothing to update")
    db["coupon"].update_one({"_id": oid}, {"$set": update})
    doc = db["coupon"].find_one({"_id": oid})
    if not doc:
        raise HTTPException(status_code=404, detail="Coupon not found")
    return map_coupon(doc)


@app.delete("/admin/coupons/{coupon_id}")
def admin_delete_coupon(coupon_id: str, user=Depends(require_admin)):
    try:
        oid = ObjectId(coupon_id)
    except Exception:
        raise HTTPException(status_code=400, detail="Invalid coupon id")
    res = db["coupon"].delete_one({"_id": oid})
    if res.deleted_count == 0:
        raise HTTPException(status_code=404, detail="Coupon not found")
    return {"success": True}


class CouponValidateRequest(BaseModel):
    code: str
    game_id: Optional[str] = None


class CouponValidateResult(BaseModel):
    valid: bool
    discount_percent: float
    reason: Optional[str] = None


@app.post("/coupons/validate", response_model=CouponValidateResult)
def validate_coupon(req: CouponValidateRequest):
    code = (req.code or "").upper().strip()
    if not code:
        return {"valid": False, "discount_percent": 0.0, "reason": "No code"}
    c = db["coupon"].find_one({"code": code})
    if not c:
        return {"valid": False, "discount_percent": 0.0, "reason": "Invalid code"}
    # expiry check (simple string ISO format compare)
    exp = c.get("expires_at")
    if exp:
        try:
            if datetime.fromisoformat(exp) < datetime.utcnow():
                return {"valid": False, "discount_percent": 0.0, "reason": "Expired"}
        except Exception:
            pass
    if not c.get("active", True):
        return {"valid": False, "discount_percent": 0.0, "reason": "Inactive"}
    return {"valid": True, "discount_percent": float(c.get("discount_percent", 0.0))}


# ------------ Orders (Public create) ------------ #

class OrderCreateRequest(BaseModel):
    game_id: str
    buyer_email: EmailStr
    nagad_number: str
    transaction_id: str
    note: Optional[str] = None
    coupon_code: Optional[str] = None


class OrderPublic(BaseModel):
    id: str
    game_id: str
    buyer_email: EmailStr
    nagad_number: str
    transaction_id: str
    status: str
    note: Optional[str] = None
    coupon_code: Optional[str] = None
    total_price: Optional[float] = None


def map_order(doc) -> 'OrderPublic':
    return OrderPublic(
        id=str(doc["_id"]),
        game_id=str(doc.get("game_id")),
        buyer_email=doc.get("buyer_email"),
        nagad_number=doc.get("nagad_number"),
        transaction_id=doc.get("transaction_id"),
        status=doc.get("status", "pending"),
        note=doc.get("note"),
        coupon_code=doc.get("coupon_code"),
        total_price=float(doc.get("total_price", 0)) if doc.get("total_price") is not None else None,
    )


@app.post("/orders", response_model='OrderPublic')
def create_order(req: OrderCreateRequest):
    # validate game exists
    try:
        game = db["game"].find_one({"_id": ObjectId(req.game_id)})
    except Exception:
        raise HTTPException(status_code=400, detail="Invalid game id")
    if not game:
        raise HTTPException(status_code=404, detail="Game not found")
    if not game.get("in_stock", True) or int(game.get("stock_count", 0)) <= 0:
        raise HTTPException(status_code=400, detail="Out of stock")

    # coupon logic
    total_price = float(game.get("price", 0))
    applied_code = None
    if req.coupon_code:
        v = validate_coupon(CouponValidateRequest(code=req.coupon_code))
        if v["valid"]:
            applied_code = req.coupon_code.upper()
            total_price = round(total_price * (1 - v["discount_percent"]/100.0), 2)

    order_doc = OrderSchema(
        game_id=req.game_id,
        buyer_email=req.buyer_email.strip().lower(),
        nagad_number=req.nagad_number,
        transaction_id=req.transaction_id,
        status="pending",
        note=req.note,
        coupon_code=applied_code,
        total_price=total_price,
    )
    order_id = create_document("order", order_doc)
    created = db["order"].find_one({"_id": ObjectId(order_id)})
    return map_order(created)


# ------------ Admin: Games CRUD ------------ #

@app.post("/admin/games", response_model='GamePublic')
def admin_create_game(req: GameCreateRequest, user=Depends(require_admin)):
    game_doc = GameSchema(
        title=req.title,
        description=req.description,
        price=req.price,
        platform=req.platform,
        category=req.category,
        images=req.images or [],
        in_stock=req.in_stock,
        stock_count=req.stock_count,
        featured=req.featured,
    )
    game_id = create_document("game", game_doc)
    created = db["game"].find_one({"_id": ObjectId(game_id)})
    return map_game(created)


class GameUpdateRequest(BaseModel):
    title: Optional[str] = None
    description: Optional[str] = None
    price: Optional[float] = None
    platform: Optional[str] = None
    category: Optional[str] = None
    images: Optional[List[str]] = None
    in_stock: Optional[bool] = None
    stock_count: Optional[int] = None
    featured: Optional[bool] = None


@app.put("/admin/games/{game_id}", response_model='GamePublic')
def admin_update_game(game_id: str, req: GameUpdateRequest, user=Depends(require_admin)):
    try:
        oid = ObjectId(game_id)
    except Exception:
        raise HTTPException(status_code=400, detail="Invalid game id")
    update = {k: v for k, v in req.model_dump().items() if v is not None}
    if not update:
        raise HTTPException(status_code=400, detail="Nothing to update")
    db["game"].update_one({"_id": oid}, {"$set": update})
    doc = db["game"].find_one({"_id": oid})
    if not doc:
        raise HTTPException(status_code=404, detail="Game not found")
    return map_game(doc)


@app.delete("/admin/games/{game_id}")
def admin_delete_game(game_id: str, user=Depends(require_admin)):
    try:
        oid = ObjectId(game_id)
    except Exception:
        raise HTTPException(status_code=400, detail="Invalid game id")
    res = db["game"].delete_one({"_id": oid})
    if res.deleted_count == 0:
        raise HTTPException(status_code=404, detail="Game not found")
    return {"success": True}


# ------------ Admin: Orders Management ------------ #

@app.get("/admin/orders", response_model=List['OrderPublic'])
def admin_list_orders(user=Depends(require_admin)):
    docs = db["order"].find({}).sort("created_at", -1)
    return [map_order(d) for d in docs]


class OrderUpdateRequest(BaseModel):
    status: Optional[str] = None
    note: Optional[str] = None


@app.put("/admin/orders/{order_id}", response_model='OrderPublic')
def admin_update_order(order_id: str, req: OrderUpdateRequest, user=Depends(require_admin)):
    try:
        oid = ObjectId(order_id)
    except Exception:
        raise HTTPException(status_code=400, detail="Invalid order id")
    update = {k: v for k, v in req.model_dump().items() if v is not None}
    if not update:
        raise HTTPException(status_code=400, detail="Nothing to update")

    # Fetch order & game for stock/email logic
    order = db["order"].find_one({"_id": oid})
    if not order:
        raise HTTPException(status_code=404, detail="Order not found")

    # Update order first
    db["order"].update_one({"_id": oid}, {"$set": update})
    doc = db["order"].find_one({"_id": oid})

    # On completed: decrement stock and send email
    try:
        if update.get("status") == "completed":
            game = db["game"].find_one({"_id": ObjectId(order.get("game_id"))}) if order else None
            if game:
                current = int(game.get("stock_count", 0))
                if current > 0:
                    db["game"].update_one({"_id": game["_id"]}, {"$set": {"stock_count": current - 1, "in_stock": current - 1 > 0}})
            # Send email (best-effort)
            subject = f"Your Game Order is Completed: {game.get('title') if game else ''}"
            body = (
                f"Hello,\n\nYour order is completed. Thanks for purchasing {game.get('title') if game else 'the game'}.\n"
                f"Transaction: {order.get('transaction_id')}\n"
                f"We will send download/activation details shortly if not attached.\n\n"
                f"Regards,\nGameStore"
            )
            send_email(order.get("buyer_email"), subject, body)
    except Exception:
        pass

    return map_order(doc)


# ------------ Payments: Nagad Verification (Stub) ------------ #

class NagadVerifyRequest(BaseModel):
    nagad_number: str
    transaction_id: str
    amount: Optional[float] = None


class NagadVerifyResult(BaseModel):
    verified: bool
    reason: Optional[str] = None


@app.post("/verify/nagad", response_model=NagadVerifyResult)
def verify_nagad(req: NagadVerifyRequest):
    # Stub verification: if TRX seems valid pattern, mark as probable true
    trx = (req.transaction_id or "").upper()
    if len(trx) >= 8 and trx[0].isalpha() and trx[1:].isalnum():
        return {"verified": True}
    return {"verified": False, "reason": "Pattern not recognized"}
