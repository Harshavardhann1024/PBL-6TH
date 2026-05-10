from fastapi import APIRouter, Depends, HTTPException, status
from sqlalchemy import func
from sqlalchemy.orm import Session

from app.api.deps import get_db, require_roles
from app.models.campaign import (
    AuditLog,
    EvidenceRecord,
    EvidenceStatus,
    PhishingCampaign,
    PhishingEvent,
    PhishingEventType,
)
from app.models.user import User
from app.schemas.dashboard import (
    DashboardAuditFeed,
    DashboardAuditItem,
    DashboardCampaignTimeline,
    DashboardCampaignSummary,
    DashboardIncidentItem,
    DashboardOverview,
    DashboardTimelineEvent,
    DashboardTimelineEvidence,
)

router = APIRouter()

SUSPICIOUS_EVENT_TYPES = (
    PhishingEventType.credentials_submitted.value,
    PhishingEventType.suspicious_login.value,
)


@router.get("/overview", response_model=DashboardOverview)
def get_dashboard_overview(
    db: Session = Depends(get_db),
    _: User = Depends(require_roles("admin", "analyst")),
) -> DashboardOverview:
    total_campaigns = db.query(func.count(PhishingCampaign.id)).scalar() or 0
    total_events = db.query(func.count(PhishingEvent.id)).scalar() or 0
    suspicious_events = (
        db.query(func.count(PhishingEvent.id))
        .filter(PhishingEvent.event_type.in_(SUSPICIOUS_EVENT_TYPES))
        .scalar()
        or 0
    )
    total_evidence = db.query(func.count(EvidenceRecord.id)).scalar() or 0
    compromised_evidence = (
        db.query(func.count(EvidenceRecord.id))
        .filter(EvidenceRecord.status == EvidenceStatus.compromised.value)
        .scalar()
        or 0
    )
    audit_actions = db.query(func.count(AuditLog.id)).scalar() or 0

    return DashboardOverview(
        total_campaigns=total_campaigns,
        total_events=total_events,
        suspicious_events=suspicious_events,
        total_evidence=total_evidence,
        compromised_evidence=compromised_evidence,
        audit_actions=audit_actions,
    )


@router.get("/campaigns", response_model=list[DashboardCampaignSummary])
def get_dashboard_campaigns(
    db: Session = Depends(get_db),
    _: User = Depends(require_roles("admin", "analyst")),
) -> list[DashboardCampaignSummary]:
    campaigns = db.query(PhishingCampaign).order_by(PhishingCampaign.created_at.desc()).all()
    campaign_summaries: list[DashboardCampaignSummary] = []

    for campaign in campaigns:
        total_events = (
            db.query(func.count(PhishingEvent.id))
            .filter(PhishingEvent.campaign_id == campaign.id)
            .scalar()
            or 0
        )
        suspicious_events = (
            db.query(func.count(PhishingEvent.id))
            .filter(
                PhishingEvent.campaign_id == campaign.id,
                PhishingEvent.event_type.in_(SUSPICIOUS_EVENT_TYPES),
            )
            .scalar()
            or 0
        )
        evidence_count = (
            db.query(func.count(EvidenceRecord.id))
            .filter(EvidenceRecord.campaign_id == campaign.id)
            .scalar()
            or 0
        )
        compromised_evidence = (
            db.query(func.count(EvidenceRecord.id))
            .filter(
                EvidenceRecord.campaign_id == campaign.id,
                EvidenceRecord.status == EvidenceStatus.compromised.value,
            )
            .scalar()
            or 0
        )
        latest_activity_at = (
            db.query(func.max(PhishingEvent.occurred_at))
            .filter(PhishingEvent.campaign_id == campaign.id)
            .scalar()
        )

        campaign_summaries.append(
            DashboardCampaignSummary(
                campaign_id=campaign.id,
                name=campaign.name,
                status=campaign.status,
                target_email=campaign.target_email,
                total_events=total_events,
                suspicious_events=suspicious_events,
                evidence_count=evidence_count,
                compromised_evidence=compromised_evidence,
                latest_activity_at=latest_activity_at,
                created_at=campaign.created_at,
            )
        )

    return campaign_summaries


@router.get("/incidents", response_model=list[DashboardIncidentItem])
def get_dashboard_incidents(
    db: Session = Depends(get_db),
    _: User = Depends(require_roles("admin", "analyst")),
) -> list[DashboardIncidentItem]:
    suspicious_events = (
        db.query(PhishingEvent, PhishingCampaign)
        .join(PhishingCampaign, PhishingCampaign.id == PhishingEvent.campaign_id)
        .filter(PhishingEvent.event_type.in_(SUSPICIOUS_EVENT_TYPES))
        .order_by(PhishingEvent.occurred_at.desc())
        .limit(20)
        .all()
    )

    incidents: list[DashboardIncidentItem] = []
    for event, campaign in suspicious_events:
        latest_evidence = (
            db.query(EvidenceRecord)
            .filter(EvidenceRecord.campaign_id == campaign.id)
            .order_by(EvidenceRecord.created_at.desc())
            .first()
        )
        incidents.append(
            DashboardIncidentItem(
                campaign_id=campaign.id,
                campaign_name=campaign.name,
                event_id=event.id,
                event_type=event.event_type,
                source_ip=event.source_ip,
                evidence_status=latest_evidence.status if latest_evidence else None,
                occurred_at=event.occurred_at,
            )
        )

    return incidents


@router.get("/campaigns/{campaign_id}/timeline", response_model=DashboardCampaignTimeline)
def get_dashboard_campaign_timeline(
    campaign_id: int,
    db: Session = Depends(get_db),
    _: User = Depends(require_roles("admin", "analyst")),
) -> DashboardCampaignTimeline:
    campaign = db.get(PhishingCampaign, campaign_id)
    if campaign is None:
        raise HTTPException(status_code=status.HTTP_404_NOT_FOUND, detail="Campaign not found")

    events = (
        db.query(PhishingEvent)
        .filter(PhishingEvent.campaign_id == campaign.id)
        .order_by(PhishingEvent.occurred_at.asc())
        .all()
    )
    evidence_records = (
        db.query(EvidenceRecord)
        .filter(EvidenceRecord.campaign_id == campaign.id)
        .order_by(EvidenceRecord.created_at.desc())
        .all()
    )

    timeline_events = [
        DashboardTimelineEvent(
            event_id=event.id,
            event_type=event.event_type,
            source_ip=event.source_ip,
            user_agent=event.user_agent,
            event_data=event.event_data,
            occurred_at=event.occurred_at,
            is_suspicious=event.event_type.value in SUSPICIOUS_EVENT_TYPES,
        )
        for event in events
    ]
    timeline_evidence = [
        DashboardTimelineEvidence(
            evidence_id=evidence.id,
            summary=evidence.summary,
            status=evidence.status,
            integrity_hash=evidence.integrity_hash,
            created_at=evidence.created_at,
        )
        for evidence in evidence_records
    ]

    suspicious_events = sum(1 for event in timeline_events if event.is_suspicious)
    phishing_url = f"/phish/{campaign.tracking_token}"
    return DashboardCampaignTimeline(
        campaign_id=campaign.id,
        name=campaign.name,
        description=campaign.description,
        status=campaign.status,
        target_email=campaign.target_email,
        tracking_token=campaign.tracking_token,
        phishing_url=phishing_url,
        total_events=len(timeline_events),
        suspicious_events=suspicious_events,
        created_at=campaign.created_at,
        events=timeline_events,
        evidence=timeline_evidence,
    )


@router.get("/audit", response_model=DashboardAuditFeed)
def get_dashboard_audit_feed(
    db: Session = Depends(get_db),
    _: User = Depends(require_roles("admin", "analyst")),
) -> DashboardAuditFeed:
    entries = db.query(AuditLog).order_by(AuditLog.created_at.desc()).limit(50).all()
    total_entries = db.query(func.count(AuditLog.id)).scalar() or 0
    evidence_sealed_actions = (
        db.query(func.count(AuditLog.id))
        .filter(AuditLog.action == "evidence_sealed")
        .scalar()
        or 0
    )
    report_actions = (
        db.query(func.count(AuditLog.id))
        .filter(AuditLog.action == "incident_report_generated")
        .scalar()
        or 0
    )
    verification_failures = (
        db.query(func.count(AuditLog.id))
        .filter(
            AuditLog.action == "evidence_verified",
            AuditLog.details["is_valid"].as_boolean() == False,  # noqa: E712
        )
        .scalar()
        or 0
    )

    return DashboardAuditFeed(
        total_entries=total_entries,
        evidence_sealed_actions=evidence_sealed_actions,
        report_actions=report_actions,
        verification_failures=verification_failures,
        entries=[
            DashboardAuditItem(
                id=entry.id,
                action=entry.action,
                resource_type=entry.resource_type,
                resource_id=entry.resource_id,
                details=entry.details,
                previous_hash=entry.previous_hash,
                current_hash=entry.current_hash,
                created_at=entry.created_at,
            )
            for entry in entries
        ],
    )
