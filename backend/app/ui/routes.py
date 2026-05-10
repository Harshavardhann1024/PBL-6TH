from pathlib import Path

from fastapi import APIRouter
from fastapi.responses import FileResponse

from app.ui.phishing import router as phishing_router

router = APIRouter(include_in_schema=False)
router.include_router(phishing_router)

STATIC_DIR = Path(__file__).resolve().parents[1] / "static"
INDEX_FILE = STATIC_DIR / "index.html"


@router.get("/")
def serve_dashboard() -> FileResponse:
    return FileResponse(INDEX_FILE)


@router.get("/app")
def serve_dashboard_alias() -> FileResponse:
    return FileResponse(INDEX_FILE)
