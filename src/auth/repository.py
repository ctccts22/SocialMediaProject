from sqlalchemy.orm import Session

from src.auth.models import Users
from src.auth.schemas import UserCreate
from src.auth.service import bcrypt_context


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

async def get_user_from_user_id(db: Session, user_id: int):
    return db.query(Users).filter(Users.id == user_id).first()