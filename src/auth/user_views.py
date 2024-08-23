from fastapi import APIRouter, Depends, status, HTTPException, Security
from fastapi.security import OAuth2PasswordBearer
from sqlalchemy.orm import Session

from ..database import get_db

from .schemas import (
    UserCreate,
    UserUpdate,
    User
)

from .security_service import (
    get_current_user,
    role_checker_dep, create_access_token,
)
from .service import (
    update_user as update_user_svc,
    create_user as create_user_svc,
    existing_user,
)

router = APIRouter(prefix="/users", tags=["users"])
oauth2_scheme = OAuth2PasswordBearer(tokenUrl="v1/auth/token")


@router.post("/signup",
             status_code=status.HTTP_201_CREATED
             )
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


@router.put("/{username}", status_code=status.HTTP_204_NO_CONTENT)
async def update_user(
        username: str,
        user_update: UserUpdate,
        token: str = Security(oauth2_scheme),
        db: Session = Depends(get_db),
        _: bool = Depends(role_checker_dep("user"))
):
    db_user = await get_current_user(db, token)

    if db_user.username != username:
        raise HTTPException(
            status_code=status.HTTP_403_FORBIDDEN,
            detail="You are not authorized to update this user",
        )

    await update_user_svc(db, db_user, user_update)
