from sqlalchemy import Column, Date, DateTime, Integer, String, Enum
from datetime import datetime

from .enums import Gender, Role
from ..database import Base

class Users(Base):
    __tablename__ = "users"

    id = Column(Integer, primary_key=True, index=True)
    email = Column(String, unique=True)
    username = Column(String, unique=True)
    name = Column(String)
    hashed_password = Column(String, nullable=True)
    created_dt = Column(DateTime, default=datetime.utcnow())

    # profile
    dob = Column(Date)
    gender = Column(Enum(Gender))
    profile_pic = Column(String) # Oracle cloud storage
    bio = Column(String)
    location = Column(String)

    # role
    role = Column(Enum(Role), nullable=False, default=Role.USER.value)