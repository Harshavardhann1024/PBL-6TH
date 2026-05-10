from fastapi import APIRouter

from app.api.routes.auth import router as auth_router
from app.api.routes.campaigns import router as campaigns_router
from app.api.routes.dashboard import router as dashboard_router
from app.api.routes.health import router as health_router

api_router = APIRouter()
api_router.include_router(auth_router, prefix="/auth", tags=["auth"])
api_router.include_router(campaigns_router, prefix="/campaigns", tags=["campaigns"])
api_router.include_router(dashboard_router, prefix="/dashboard", tags=["dashboard"])
api_router.include_router(health_router, tags=["health"])
