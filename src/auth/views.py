from typing import Annotated

from fastapi import APIRouter, Depends, status, HTTPException, Request, Response, Security
from fastapi.security import OAuth2PasswordRequestForm, OAuth2PasswordBearer
from sqlalchemy.orm import Session
from datetime import datetime

from .schemas import UserCreate, UserUpdate, User
from ..database import get_db
from .service import (
    existing_user,
    create_access_token,
    create_refresh_token,
    get_current_user,
    create_user as create_user_svc,
    authenticate,
    update_user as update_user_svc,
    call_refresh_token, role_checker, role_checker_dep,
)

router = APIRouter(prefix="/auth", tags=["auth"])
oauth2_scheme = OAuth2PasswordBearer(tokenUrl="v1/auth/token")

# signup
@router.post("/signup", status_code=status.HTTP_201_CREATED)
async def create_user(user: UserCreate, db: Session = Depends(get_db)):
    # check existing user
    db_user = await existing_user(db, user.username, user.email)
    if db_user:
        raise HTTPException(
            status_code=status.HTTP_409_CONFLICT,
            detail="username or email already in use",
        )

    db_user = await create_user_svc(db, user)
    # check it creates access_token after done with signup
    access_token = await create_access_token(user.username, db_user.id, db_user.role)

    return {
        "access_token": access_token,
        "token_type": "bearer",
        "username": user.username,
    }


# login to generate token
# form_data : help to loginForm with secured username&password
@router.post("/token", status_code=status.HTTP_201_CREATED)
async def login(
        request: Request,
        response: Response,
        form_data: OAuth2PasswordRequestForm = Depends(),
        db: Session = Depends(get_db)
):
    refresh_token = request.cookies.get("refresh_token")
    db_user = await authenticate(db, form_data.username, form_data.password)
    if not db_user:
        raise HTTPException(
            status_code=status.HTTP_401_UNAUTHORIZED,
            detail="incorrect username or password",
        )
    # if refresh_token exist, call access_token from redis
    if refresh_token:
        call_access_token = await call_refresh_token(refresh_token)
        if call_access_token:
            return {
                "access_token": call_access_token,
                "token_type": "bearer",
                "refresh_token": refresh_token
            }

    # create access_token and send to frontend then it deals with token with whatever method
    access_token = await create_access_token(db_user.username, db_user.id, db_user.role)
    # Make a refresh_token in cookie,
    refresh_token = await create_refresh_token(response, access_token)

    return {
        "access_token": access_token,
        "token_type": "bearer",
        "refresh_token": refresh_token
    }


# frontend need access_token to handle many things
@router.get("/refresh", status_code=status.HTTP_200_OK)
async def get_access_token(
        request: Request,
):
    refresh_token = request.cookies.get("refresh_token")
    if not refresh_token:
        raise HTTPException(status_code=status.HTTP_401_UNAUTHORIZED,
                            detail="Refresh token not found or invalid")

    access_token = await call_refresh_token(refresh_token)

    if not access_token:
        raise HTTPException(status_code=status.HTTP_401_UNAUTHORIZED,
                            detail="Could not refresh access token")

    return {"access_token": access_token}


# get current user
@router.get("/profile", status_code=status.HTTP_200_OK, response_model=User)
async def current_user(
        token: str = Security(oauth2_scheme),
        db: Session = Depends(get_db),
        _: bool = Depends(role_checker_dep("user"))
):
    db_user = await get_current_user(db, token)
    if not db_user:
        raise HTTPException(
            status_code=status.HTTP_401_UNAUTHORIZED, detail="token invalid"
        )

    return db_user


# update user header에 있는 토큰을 이용해서 validation 하는 코드로 수정 할 예정
@router.put("/{username}", status_code=status.HTTP_204_NO_CONTENT)
async def update_user(
        username: str,
        user_update: UserUpdate,
        token: str = Security(oauth2_scheme),
        db: Session = Depends(get_db),
):
    db_user = await get_current_user(db, token)

    if db_user.username != username:
        raise HTTPException(
            status_code=status.HTTP_403_FORBIDDEN,
            detail="You are not authorized to update this user",
        )

    await update_user_svc(db, db_user, user_update)
