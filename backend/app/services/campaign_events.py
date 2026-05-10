from typing import Any

from sqlalchemy.orm import Session

from app.models.campaign import PhishingCampaign, PhishingEvent, PhishingEventType
from app.services.audit import create_audit_log
from app.services.evidence import create_evidence_record, event_requires_evidence


def get_campaign_by_tracking_token(db: Session, tracking_token: str) -> PhishingCampaign | None:
    return (
        db.query(PhishingCampaign)
        .filter(PhishingCampaign.tracking_token == tracking_token)
        .first()
    )


def record_campaign_event(
    db: Session,
    campaign: PhishingCampaign,
    event_type: PhishingEventType,
    source_ip: str | None = None,
    user_agent: str | None = None,
    event_data: dict[str, Any] | None = None,
) -> PhishingEvent:
    event = PhishingEvent(
        campaign_id=campaign.id,
        event_type=event_type,
        source_ip=source_ip,
        user_agent=user_agent,
        event_data=event_data or {},
    )
    db.add(event)
    db.commit()
    db.refresh(event)

    create_audit_log(
        db=db,
        action="event_captured",
        resource_type="campaign_event",
        resource_id=str(event.id),
        actor_user_id=None,
        details={
            "campaign_id": campaign.id,
            "event_type": event.event_type.value,
        },
    )

    if event_requires_evidence(event.event_type):
        evidence_record = create_evidence_record(db=db, campaign=campaign, event=event)
        create_audit_log(
            db=db,
            action="evidence_sealed",
            resource_type="evidence_record",
            resource_id=str(evidence_record.id),
            actor_user_id=None,
            details={
                "campaign_id": campaign.id,
                "event_id": event.id,
                "event_type": event.event_type.value,
                "integrity_hash": evidence_record.integrity_hash,
            },
        )

    return event
