import os
from typing import List, Optional
from fastapi import FastAPI, HTTPException, Header, Depends
from fastapi.middleware.cors import CORSMiddleware
from pydantic import BaseModel, EmailStr
from database import db, create_document, get_documents
from schemas import User as UserSchema, Game as GameSchema, Order as OrderSchema
from bson.objectid import ObjectId
import hashlib
import secrets

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
    existing = db["user"].find_one({"email": req.email})
    if existing:
        raise HTTPException(status_code=400, detail="Email already registered")
    salt = secrets.token_hex(16)
    password_hash = hash_password(req.password, salt)
    role = "admin" if (req.admin_code and req.admin_code == os.getenv("ADMIN_CODE", "admin123")) else "user"
    user_doc = UserSchema(
        name=req.name,
        email=req.email,
        password_hash=password_hash,
        salt=salt,
        role=role,
        is_active=True,
    )
    user_id = create_document("user", user_doc)
    token = secrets.token_hex(24)
    db["user"].update_one({"_id": ObjectId(user_id)}, {"$set": {"api_token": token}})
    return {"token": token, "role": role, "name": req.name, "email": req.email}


class LoginRequest(BaseModel):
    email: EmailStr
    password: str


@app.post("/auth/login", response_model=AuthResponse)
def login(req: LoginRequest):
    user = db["user"].find_one({"email": req.email})
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


class GamePublic(BaseModel):
    id: str
    title: str
    description: Optional[str] = None
    price: float
    platform: str
    category: Optional[str] = None
    images: List[str] = []
    in_stock: bool


def map_game(doc) -> GamePublic:
    return GamePublic(
        id=str(doc["_id"]),
        title=doc.get("title"),
        description=doc.get("description"),
        price=float(doc.get("price", 0)),
        platform=doc.get("platform"),
        category=doc.get("category"),
        images=doc.get("images", []),
        in_stock=bool(doc.get("in_stock", True)),
    )


@app.get("/games", response_model=List[GamePublic])
def list_games(platform: Optional[str] = None, q: Optional[str] = None, category: Optional[str] = None):
    filt = {}
    if platform:
        filt["platform"] = platform
    if category:
        filt["category"] = category
    if q:
        filt["title"] = {"$regex": q, "$options": "i"}
    docs = db["game"].find(filt).sort("created_at", -1)
    return [map_game(d) for d in docs]


@app.get("/games/{game_id}", response_model=GamePublic)
def get_game(game_id: str):
    try:
        doc = db["game"].find_one({"_id": ObjectId(game_id)})
    except Exception:
        raise HTTPException(status_code=400, detail="Invalid game id")
    if not doc:
        raise HTTPException(status_code=404, detail="Game not found")
    return map_game(doc)


# ------------ Orders (Public create) ------------ #

class OrderCreateRequest(BaseModel):
    game_id: str
    buyer_email: EmailStr
    nagad_number: str
    transaction_id: str
    note: Optional[str] = None


class OrderPublic(BaseModel):
    id: str
    game_id: str
    buyer_email: EmailStr
    nagad_number: str
    transaction_id: str
    status: str
    note: Optional[str] = None


def map_order(doc) -> OrderPublic:
    return OrderPublic(
        id=str(doc["_id"]),
        game_id=str(doc.get("game_id")),
        buyer_email=doc.get("buyer_email"),
        nagad_number=doc.get("nagad_number"),
        transaction_id=doc.get("transaction_id"),
        status=doc.get("status", "pending"),
        note=doc.get("note"),
    )


@app.post("/orders", response_model=OrderPublic)
def create_order(req: OrderCreateRequest):
    # validate game exists
    try:
        game = db["game"].find_one({"_id": ObjectId(req.game_id)})
    except Exception:
        raise HTTPException(status_code=400, detail="Invalid game id")
    if not game:
        raise HTTPException(status_code=404, detail="Game not found")
    order_doc = OrderSchema(
        game_id=req.game_id,
        buyer_email=req.buyer_email,
        nagad_number=req.nagad_number,
        transaction_id=req.transaction_id,
        status="pending",
        note=req.note,
    )
    order_id = create_document("order", order_doc)
    created = db["order"].find_one({"_id": ObjectId(order_id)})
    return map_order(created)


# ------------ Admin: Games CRUD ------------ #

@app.post("/admin/games", response_model=GamePublic)
def admin_create_game(req: GameCreateRequest, user=Depends(require_admin)):
    game_doc = GameSchema(
        title=req.title,
        description=req.description,
        price=req.price,
        platform=req.platform,
        category=req.category,
        images=req.images or [],
        in_stock=req.in_stock,
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


@app.put("/admin/games/{game_id}", response_model=GamePublic)
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

@app.get("/admin/orders", response_model=List[OrderPublic])
def admin_list_orders(user=Depends(require_admin)):
    docs = db["order"].find({}).sort("created_at", -1)
    return [map_order(d) for d in docs]


class OrderUpdateRequest(BaseModel):
    status: Optional[str] = None
    note: Optional[str] = None


@app.put("/admin/orders/{order_id}", response_model=OrderPublic)
def admin_update_order(order_id: str, req: OrderUpdateRequest, user=Depends(require_admin)):
    try:
        oid = ObjectId(order_id)
    except Exception:
        raise HTTPException(status_code=400, detail="Invalid order id")
    update = {k: v for k, v in req.model_dump().items() if v is not None}
    if not update:
        raise HTTPException(status_code=400, detail="Nothing to update")
    db["order"].update_one({"_id": oid}, {"$set": update})
    doc = db["order"].find_one({"_id": oid})
    if not doc:
        raise HTTPException(status_code=404, detail="Order not found")
    return map_order(doc)
