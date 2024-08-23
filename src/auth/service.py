from sqlalchemy.orm import Session

from passlib.context import CryptContext

from .models import Users
from .schemas import UserCreate, UserUpdate

bcrypt_context = CryptContext(schemes=["bcrypt"], deprecated="auto")


async def existing_user(db: Session, username: str, email: str):
    db_user = db.query(Users).filter(Users.username == username).first()
    db_user = db.query(Users).filter(Users.email == email).first()
    return db_user


async def get_user_from_user_id(db: Session, user_id: int):
    return db.query(Users).filter(Users.id == user_id).first()


async def create_user(db: Session, user: UserCreate):
    db_user = Users(
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


async def update_user(db: Session, db_user: Users, user_update: UserUpdate):
    db_user.bio = user_update.bio or db_user.bio
    db_user.name = user_update.name or db_user.name
    db_user.dob = user_update.dob or db_user.dob
    db_user.gender = user_update.gender or db_user.gender
    db_user.location = user_update.location or db_user.location
    db_user.profile_pic = user_update.profile_pic or db_user.profile_pic

    db.commit()
