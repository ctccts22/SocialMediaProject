from pydantic import BaseModel
from datetime import date, datetime

from .enums import Gender, Role

class UserBase(BaseModel):
    email: str
    username: str

class AccessToken(BaseModel):
    access_token: str
    token_type: str

class Token(AccessToken):
    refresh_token: str

class UserCreate(UserBase):
    password: str
    name: str | None = None
    dob: date | None = None
    gender: Gender | None = None
    bio: str | None = None
    location: str | None = None
    profile_pic: str | None = None


class UserUpdate(BaseModel):
    name: str | None = None
    dob: date | None = None
    gender: Gender | None = None
    bio: str | None = None
    location: str | None = None
    profile_pic: str | None = None


class User(UserBase, UserUpdate):
    id: int
    role: Role
    created_dt: datetime

    class Config:
        orm_mode = True