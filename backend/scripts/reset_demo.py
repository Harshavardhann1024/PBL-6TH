import argparse
import sys
from pathlib import Path

PROJECT_ROOT = Path(__file__).resolve().parents[1]
if str(PROJECT_ROOT) not in sys.path:
    sys.path.insert(0, str(PROJECT_ROOT))

from app.db.base import Base
from app.db.session import SessionLocal, engine
from app.models.campaign import AuditLog, EvidenceRecord, PhishingCampaign, PhishingEvent
from app.models.user import User


def main() -> None:
    parser = argparse.ArgumentParser(description="Reset ShadowTrace demo data.")
    parser.add_argument(
        "--drop-users",
        action="store_true",
        help="Also delete all registered users instead of preserving login accounts.",
    )
    args = parser.parse_args()

    Base.metadata.create_all(bind=engine)

    with SessionLocal() as db:
        audit_count = db.query(AuditLog).delete()
        evidence_count = db.query(EvidenceRecord).delete()
        event_count = db.query(PhishingEvent).delete()
        campaign_count = db.query(PhishingCampaign).delete()
        user_count = db.query(User).delete() if args.drop_users else 0
        db.commit()

    print("ShadowTrace demo data reset complete.")
    print(f"Campaigns removed: {campaign_count}")
    print(f"Events removed: {event_count}")
    print(f"Evidence removed: {evidence_count}")
    print(f"Audit logs removed: {audit_count}")
    if args.drop_users:
        print(f"Users removed: {user_count}")
    else:
        print("Users preserved. Use --drop-users to clear accounts as well.")


if __name__ == "__main__":
    main()
