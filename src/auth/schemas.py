from pydantic import BaseModel
from datetime import date, datetime

from .enums import Gender, Role

class UserBase(BaseModel):
    email: str
    username: str

class UserAuth(BaseModel):
    id: int
    username: str
    role: str

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