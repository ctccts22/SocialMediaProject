from fastapi import Depends, HTTPException, status, Cookie, Security
from fastapi.security import OAuth2PasswordBearer
from sqlalchemy.orm import Session
from passlib.context import CryptContext
from datetime import timedelta, datetime
from jose import jwt, JWTError
from uuid import uuid4

from .enums import Role
from .models import Users

from ..redis import redis_client

bcrypt_context = CryptContext(schemes=["bcrypt"], deprecated="auto")
oauth2_scheme = OAuth2PasswordBearer(tokenUrl="v1/auth/token")
SECRET_KEY = "mysecretkey"
ALGORITHM = "HS256"
ACCESS_TOKEN_EXPIRE_MINS = 60 * 24 * 30  # 30days
REFRESH_TOKEN_EXPIRE_MINS = 60 * 60 * 24 * 7  # 7days


def role_checker_dep(allowed_role: str):
    async def checker(token: str = Security(oauth2_scheme)):
        return await role_checker(allowed_role, token)

    return checker


async def role_checker(allowed_role: str, token: str = Security(oauth2_scheme)):
    payload = jwt.decode(token, SECRET_KEY, algorithms=[ALGORITHM])
    role = payload.get("role")
    if role != allowed_role:
        raise HTTPException(
            status_code=status.HTTP_401_UNAUTHORIZED,
            detail="You don't have enough permissions"
        )
    return True


async def authenticate(db: Session, username: str, password: str):
    db_user = db.query(Users).filter(Users.username == username).first()
    if not db_user:
        return None
    if not bcrypt_context.verify(password, db_user.hashed_password):
        return None
    return db_user


async def create_access_token(username: str, id: int, role: str):
    encode = {"sub": username, "id": id, "role": role}
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
        max_age=3600,  # 1 hour
        httponly=False,  # it should be changed with "True"
        secure=False,  # it should be changed with "True"
        samesite="lax"  # or Strict
    )

    return refresh_token


async def get_current_user(
        db: Session,
        token: str = Security(oauth2_scheme)
):
    credentials_exception = HTTPException(
        status_code=status.HTTP_401_UNAUTHORIZED,
        detail="Could not validate credentials",
    )

    try:
        payload = jwt.decode(token, SECRET_KEY, algorithms=[ALGORITHM])
        username: str = payload.get("sub")
        user_id: str = payload.get("id")
        role: Role = payload.get("role")
        expires: datetime = payload.get("exp")

        # Check if the token has expired
        if datetime.fromtimestamp(expires) < datetime.now():
            raise credentials_exception

        if username is None or user_id is None or role is None:
            raise credentials_exception

        user = db.query(Users).filter(Users.id == user_id).first()
        if user is None:
            raise credentials_exception

        return user

    except JWTError:
        raise credentials_exception
