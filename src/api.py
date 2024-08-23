from fastapi import APIRouter

from .auth.auth_views import router as auth_router
from .auth.user_views import router as user_router
router = APIRouter(prefix="/v1")

router.include_router(auth_router)
router.include_router(user_router)
