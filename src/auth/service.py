from fastapi import Depends
from sqlalchemy.orm import Session

from passlib.context import CryptContext
from fastapi.security import OAuth2PasswordBearer
from jose import jwt, JWTError
from datetime import timedelta, datetime

from .models import User
from .schemas import UserCreate, UserUpdate

from uuid import uuid4

from ..redis import redis_client

bcrypt_context = CryptContext(schemes=["bcrypt"], deprecated="auto")
oauth2_bearer = OAuth2PasswordBearer(tokenUrl="v1/auth/token")
SECRET_KEY = "mysecretkey"
ALGORITHM = "HS256"
ACCESS_TOKEN_EXPIRE_MINS = 60 * 24 * 30  # 30days
REFRESH_TOKEN_EXPIRE_MINS = 60 * 60 * 24 * 7  # 7days


async def existing_user(db: Session, username: str, email: str):
    db_user = db.query(User).filter(User.username == username).first()
    db_user = db.query(User).filter(User.email == email).first()
    return db_user


async def create_access_token(username: str, id: int):
    encode = {"sub": username, "id": id}
    expires = datetime.utcnow() + timedelta(minutes=ACCESS_TOKEN_EXPIRE_MINS)
    encode.update({"exp": expires})

    return jwt.encode(encode, SECRET_KEY, algorithm=ALGORITHM)


# check refresh_token Before user login or call access_token needed from client
async def call_refresh_token(refresh_token):
    stored_access_token = redis_client.get(refresh_token)
    if stored_access_token:
        return stored_access_token
    return None


async def create_refresh_token(response, access_token: str):
    refresh_token = str(uuid4())
    redis_client.set(refresh_token, access_token, ex=REFRESH_TOKEN_EXPIRE_MINS)

    response.set_cookie(
        key="refresh_token",
        value=refresh_token,
        max_age=3600, # 1 hour
        httponly=False,  # it should be changed with "True"
        secure=False,  # it should be changed with "True"
        samesite="lax"  # or Strict
    )

    return refresh_token


async def get_current_user(db: Session, token: str = Depends(oauth2_bearer)):
    try:
        payload = jwt.decode(token, SECRET_KEY, algorithms=[ALGORITHM])
        username: str = payload.get("sub")
        id: str = payload.get("id")
        expires: datetime = payload.get("exp")
        if datetime.fromtimestamp(expires) < datetime.now():
            return None
        if username is None or id is None:
            return None
        return db.query(User).filter(User.id == id).first()
    except JWTError:
        return None


async def get_user_from_user_id(db: Session, user_id: int):
    return db.query(User).filter(User.id == user_id).first()


async def create_user(db: Session, user: UserCreate):
    db_user = User(
        email=user.email.lower().strip(),
        username=user.username.lower().strip(),
        hashed_password=bcrypt_context.hash(user.password),
        dob=user.dob or None,
        gender=user.gender or None,
        location=user.location or None,
        profile_pic=user.profile_pic or None,
        name=user.name or None
    )
    db.add(db_user)
    db.commit()
    return db_user


async def authenticate(db: Session, username: str, password: str):
    db_user = db.query(User).filter(User.username == username).first()
    if not db_user:
        return None
    if not bcrypt_context.verify(password, db_user.hashed_password):
        return None
    return db_user


async def update_user(db: Session, db_user: User, user_update: UserUpdate):
    db_user.bio = user_update.bio or db_user.bio
    db_user.name = user_update.name or db_user.name
    db_user.dob = user_update.dob or db_user.dob
    db_user.gender = user_update.gender or db_user.gender
    db_user.location = user_update.location or db_user.location
    db_user.profile_pic = user_update.profile_pic or db_user.profile_pic

    db.commit()
