"""
Database Schemas for Game Store

Each Pydantic model below represents a MongoDB collection. The collection
name is the lowercase of the class name (e.g., Game -> "game").
"""

from pydantic import BaseModel, Field, EmailStr
from typing import Optional, List


class User(BaseModel):
    name: str = Field(..., description="Full name")
    email: EmailStr = Field(..., description="Email address (unique)")
    password_hash: str = Field(..., description="Hashed password with salt")
    salt: str = Field(..., description="Password salt")
    role: str = Field("user", description="Role: user or admin")
    is_active: bool = Field(True, description="Whether user is active")


class Game(BaseModel):
    title: str = Field(..., description="Game title")
    description: Optional[str] = Field(None, description="Game description")
    price: float = Field(..., ge=0, description="Price in BDT")
    platform: str = Field(..., description="pc | mobile")
    category: Optional[str] = Field(None, description="Action, RPG, etc.")
    images: List[str] = Field(default_factory=list, description="Image URLs")
    in_stock: bool = Field(True, description="Available for sale")


class Order(BaseModel):
    game_id: str = Field(..., description="Ordered game ObjectId as string")
    buyer_email: EmailStr = Field(..., description="Email to receive the game")
    nagad_number: str = Field(..., description="Sender Nagad number")
    transaction_id: str = Field(..., description="Nagad transaction ID (TRX)")
    status: str = Field("pending", description="pending | processing | completed | cancelled")
    note: Optional[str] = Field(None, description="Optional note by buyer/admin")
