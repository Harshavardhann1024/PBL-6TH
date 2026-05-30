import sys
from pathlib import Path

PROJECT_ROOT = Path(__file__).resolve().parents[1]
if str(PROJECT_ROOT) not in sys.path:
    sys.path.insert(0, str(PROJECT_ROOT))

from app.db.base import Base
from app.db.session import SessionLocal, engine
from app.models.campaign import CampaignStatus, PhishingCampaign, PhishingEventType
from app.models.user import User, UserRole
from app.services.campaign_events import record_campaign_event
from app.services.reports import build_latest_incident_report
from app.services.security import get_password_hash


def ensure_user(
    email: str,
    full_name: str,
    password: str,
    role: UserRole,
) -> User:
    with SessionLocal() as db:
        existing_user = db.query(User).filter(User.email == email).first()
        if existing_user:
            return existing_user

        user = User(
            full_name=full_name,
            email=email,
            hashed_password=get_password_hash(password),
            role=role,
        )
        db.add(user)
        db.commit()
        db.refresh(user)
        return user


def ensure_demo_campaign(created_by_id: int) -> PhishingCampaign:
    with SessionLocal() as db:
        campaign = (
            db.query(PhishingCampaign)
            .filter(PhishingCampaign.name == "Quarterly Payroll Confirmation")
            .first()
        )
        if campaign:
            return campaign

        campaign = PhishingCampaign(
            name="Quarterly Payroll Confirmation",
            description="Seeded phishing simulation that drives the ShadowTrace dashboard demo flow.",
            target_email="employee.demo@example.com",
            created_by_id=created_by_id,
            status=CampaignStatus.active,
        )
        db.add(campaign)
        db.commit()
        db.refresh(campaign)
        return campaign


def seed_events(campaign_id: int) -> None:
    with SessionLocal() as db:
        campaign = db.get(PhishingCampaign, campaign_id)
        if campaign is None:
            return

        existing_event_types = {
            event.event_type.value
            for event in campaign.events
        }

        if PhishingEventType.email_sent.value not in existing_event_types:
            record_campaign_event(
                db=db,
                campaign=campaign,
                event_type=PhishingEventType.email_sent,
                source_ip="10.0.0.10",
                user_agent="SeedScript/1.0",
                event_data={"message": "Payroll review reminder dispatched"},
            )

        if PhishingEventType.link_clicked.value not in existing_event_types:
            record_campaign_event(
                db=db,
                campaign=campaign,
                event_type=PhishingEventType.link_clicked,
                source_ip="10.0.0.52",
                user_agent="Chrome/ShadowTraceDemo",
                event_data={"page": "benefits-login", "result": "opened"},
            )

        if PhishingEventType.credentials_submitted.value not in existing_event_types:
            record_campaign_event(
                db=db,
                campaign=campaign,
                event_type=PhishingEventType.credentials_submitted,
                source_ip="10.0.0.52",
                user_agent="Chrome/ShadowTraceDemo",
                event_data={
                    "page": "benefits-login",
                    "captured_username": campaign.target_email,
                    "password_length": 14,
                    "submission_result": "credentials_entered",
                },
            )

        if PhishingEventType.suspicious_login.value not in existing_event_types:
            record_campaign_event(
                db=db,
                campaign=campaign,
                event_type=PhishingEventType.suspicious_login,
                source_ip="203.0.113.24",
                user_agent="Unknown Linux Client",
                event_data={
                    "location": "unexpected-region",
                    "device_change": True,
                    "risk_score": 93,
                },
            )

        build_latest_incident_report(db=db, campaign=campaign)


def main() -> None:
    Base.metadata.create_all(bind=engine)

    admin = ensure_user(
        email="admin@gmail.com",
        full_name="ShadowTrace Admin",
        password="ShadowTrace123",
        role=UserRole.super_admin,
    )
    ensure_user(
        email="analyst@shadowtrace.local",
        full_name="ShadowTrace Analyst",
        password="ShadowTrace123",
        role=UserRole.analyst,
    )
    ensure_user(
        email="employee.demo@shadowtrace.local",
        full_name="Demo Employee",
        password="ShadowTrace123",
        role=UserRole.employee,
    )
    ensure_user(
        email="employee.demo@example.com",
        full_name="Demo Employee",
        password="ShadowTrace123",
        role=UserRole.employee,
    )
    ensure_user(
        email="viewer@shadowtrace.local",
        full_name="Read-Only Viewer",
        password="ShadowTrace123",
        role=UserRole.viewer,
    )

    campaign = ensure_demo_campaign(created_by_id=admin.id)
    seed_events(campaign.id)

    phishing_link = f"http://127.0.0.1:8000/phish/{campaign.tracking_token}"
    print("ShadowTrace demo data is ready.")
    print(f"Campaign ID: {campaign.id}")
    print(f"Target Email: {campaign.target_email}")
    print(f"Phishing URL: {phishing_link}")
    print("Admin Login: admin@gmail.com / ShadowTrace123")
    print(f"Project root: {PROJECT_ROOT}")


if __name__ == "__main__":
    main()
