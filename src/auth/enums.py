from enum import Enum

class Role(str, Enum):
    SUPER = "super",
    ADMIN = "admin",
    USER = "user"

class Gender(str, Enum):
    MALE = "male"
    FEMALE = "female"

