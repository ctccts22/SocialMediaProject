from fastapi import APIRouter, Depends, status, HTTPException, Request, Response
from fastapi.security import OAuth2PasswordRequestForm
from sqlalchemy.orm import Session

from ..database import get_db

from .security_service import (
    create_access_token,
    create_refresh_token,
    get_current_user,
    authenticate,
    call_refresh_token, role_checker, role_checker_dep,
)

router = APIRouter(prefix="/auth", tags=["auth(login)"])


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
