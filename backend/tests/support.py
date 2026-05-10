import unittest
from pathlib import Path
from uuid import uuid4

from fastapi.security import OAuth2PasswordRequestForm
from sqlalchemy import create_engine
from sqlalchemy.orm import sessionmaker

from app.db.base import Base
from app.schemas.campaign import CampaignCreate, EventCaptureRequest
from app.schemas.user import UserCreate
from app.api.routes import auth as auth_routes
from app.api.routes import campaigns as campaign_routes


class ShadowTraceDBTestCase(unittest.TestCase):
    def setUp(self) -> None:
        super().setUp()
        self.temp_root = Path(__file__).resolve().parent / ".tmp"
        self.temp_root.mkdir(exist_ok=True)
        self.database_path = self.temp_root / f"shadowtrace_test_{uuid4().hex}.db"
        self.engine = create_engine(
            f"sqlite:///{self.database_path.as_posix()}",
            connect_args={"check_same_thread": False},
        )
        self.session_local = sessionmaker(autocommit=False, autoflush=False, bind=self.engine)
        Base.metadata.create_all(bind=self.engine)
        self.db = self.session_local()

    def tearDown(self) -> None:
        self.db.close()
        Base.metadata.drop_all(bind=self.engine)
        self.engine.dispose()
        if self.database_path.exists():
            self.database_path.unlink()
        super().tearDown()

    def register_user(
        self,
        *,
        email: str,
        password: str = "ShadowTrace123",
        role: str = "admin",
        full_name: str = "Test User",
    ):
        return auth_routes.register_user(
            payload=UserCreate(
                full_name=full_name,
                email=email,
                password=password,
                role=role,
            ),
            db=self.db,
        )

    def login(self, email: str, password: str = "ShadowTrace123"):
        return auth_routes.login(
            form_data=OAuth2PasswordRequestForm(
                username=email,
                password=password,
                scope="",
                client_id=None,
                client_secret=None,
            ),
            db=self.db,
        )

    def create_campaign(self, *, current_user, name: str = "Finance Benefits Update"):
        return campaign_routes.create_campaign(
            payload=CampaignCreate(
                name=name,
                description="Suspicious campaign flow test",
                target_email="employee@test.com",
                starts_at=None,
                ends_at=None,
            ),
            db=self.db,
            current_user=current_user,
        )

    def capture_event(self, *, campaign, event_type: str):
        return campaign_routes.capture_campaign_event(
            tracking_token=campaign.tracking_token,
            payload=EventCaptureRequest(
                event_type=event_type,
                source_ip="127.0.0.1",
                user_agent="UnitTest/1.0",
                event_data={
                    "page": "benefits-login",
                    "captured_username": "employee@test.com",
                    "password_length": 12,
                    "submission_result": "credentials_entered",
                },
            ),
            db=self.db,
        )
