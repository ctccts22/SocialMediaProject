from fastapi import Depends, HTTPException, status, Cookie
from sqlalchemy.orm import Session

from passlib.context import CryptContext
from fastapi.security import OAuth2PasswordBearer
from jose import jwt, JWTError
from datetime import timedelta, datetime

from sqlalchemy.testing.suite.test_reflection import users

from .models import User
from .schemas import UserCreate, UserUpdate

from .enums import Role

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
        db: Session = Depends(),
        token: str = Depends(oauth2_bearer)
):
    credentials_exception = HTTPException(
        status_code=status.HTTP_401_UNAUTHORIZED,
        detail="Could not validate credentials",
    )

    try:
        payload = jwt.decode(token, SECRET_KEY, algorithms=[ALGORITHM])
        username: str = payload.get("sub")
        user_id: str = payload.get("id")
        role: str = payload.get("role")
        expires: datetime = payload.get("exp")

        # Check if the token has expired
        if datetime.fromtimestamp(expires) < datetime.now():
            raise credentials_exception

        if username is None or user_id is None or role is None:
            raise credentials_exception

        user = db.query(User).filter(User.id == user_id).first()
        if user is None:
            raise credentials_exception

        return user

    except JWTError:
        raise credentials_exception


async def require_role(required_role: Role):
    def role_checker(user: dict = Depends(get_current_user)):
        if Role(user["role"]) != required_role:
            raise HTTPException(
                status_code=status.HTTP_403_FORBIDDEN,
                detail="Operation not permitted",
            )
        return user

    return role_checker


async def get_user_from_user_id(db: Session, user_id: int):
    return db.query(User).filter(User.id == user_id).first()


async def create_user(db: Session, user: UserCreate):
    db_user = User(
        email=user.email.lower().strip(),
        username=user.username.lower().strip(),
        # role default USER
        hashed_password=bcrypt_context.hash(user.password),
        dob=user.dob or None,
        gender=user.gender or None,
        location=user.location or None,
        profile_pic=user.profile_pic or None,
        name=user.name or None,
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
