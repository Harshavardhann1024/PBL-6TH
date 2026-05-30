import json

from fastapi import APIRouter, Depends, HTTPException, status
from fastapi.responses import Response
from sqlalchemy.orm import Session

from app.api.deps import get_db, require_analyst_plus, require_viewer_plus
from app.models.campaign import (
    AuditLog,
    EvidenceRecord,
    PhishingCampaign,
    PhishingEvent,
)
from app.models.user import User
from app.schemas.campaign import (
    AuditLogRead,
    CampaignCreate,
    CampaignRead,
    EvidenceRecordDetail,
    EvidenceRecordRead,
    EvidenceVerificationRead,
    EventCaptureRequest,
    IncidentReportRead,
    PhishingEventRead,
)
from app.services.audit import create_audit_log
from app.services.campaign_events import get_campaign_by_tracking_token, record_campaign_event
from app.services.evidence import verify_evidence_record
from app.services.reports import build_latest_incident_report, generate_pdf_report

router = APIRouter()


@router.post(
    "/",
    response_model=CampaignRead,
    status_code=status.HTTP_201_CREATED,
)
def create_campaign(
    payload: CampaignCreate,
    db: Session = Depends(get_db),
    current_user: User = Depends(require_analyst_plus),
) -> PhishingCampaign:
    campaign = PhishingCampaign(
        name=payload.name,
        description=payload.description,
        target_email=payload.target_email,
        starts_at=payload.starts_at,
        ends_at=payload.ends_at,
        created_by_id=current_user.id,
    )
    db.add(campaign)
    db.commit()
    db.refresh(campaign)

    create_audit_log(
        db=db,
        action="campaign_created",
        resource_type="campaign",
        resource_id=str(campaign.id),
        actor_user_id=current_user.id,
        details={
            "campaign_name": campaign.name,
            "tracking_token": campaign.tracking_token,
        },
    )
    return campaign


@router.get("/", response_model=list[CampaignRead])
def list_campaigns(
    db: Session = Depends(get_db),
    _: User = Depends(require_viewer_plus),
) -> list[PhishingCampaign]:
    return db.query(PhishingCampaign).order_by(PhishingCampaign.created_at.desc()).all()


@router.get("/{campaign_id}", response_model=CampaignRead)
def get_campaign(
    campaign_id: int,
    db: Session = Depends(get_db),
    _: User = Depends(require_viewer_plus),
) -> PhishingCampaign:
    campaign = db.get(PhishingCampaign, campaign_id)
    if campaign is None:
        raise HTTPException(status_code=status.HTTP_404_NOT_FOUND, detail="Campaign not found")
    return campaign


@router.get("/{campaign_id}/events", response_model=list[PhishingEventRead])
def list_campaign_events(
    campaign_id: int,
    db: Session = Depends(get_db),
    _: User = Depends(require_viewer_plus),
) -> list[PhishingEvent]:
    campaign = db.get(PhishingCampaign, campaign_id)
    if campaign is None:
        raise HTTPException(status_code=status.HTTP_404_NOT_FOUND, detail="Campaign not found")

    return (
        db.query(PhishingEvent)
        .filter(PhishingEvent.campaign_id == campaign_id)
        .order_by(PhishingEvent.occurred_at.desc())
        .all()
    )


@router.get("/{campaign_id}/evidence", response_model=list[EvidenceRecordRead])
def list_campaign_evidence(
    campaign_id: int,
    db: Session = Depends(get_db),
    _: User = Depends(require_viewer_plus),
) -> list[EvidenceRecord]:
    campaign = db.get(PhishingCampaign, campaign_id)
    if campaign is None:
        raise HTTPException(status_code=status.HTTP_404_NOT_FOUND, detail="Campaign not found")

    return (
        db.query(EvidenceRecord)
        .filter(EvidenceRecord.campaign_id == campaign_id)
        .order_by(EvidenceRecord.created_at.desc())
        .all()
    )


@router.get("/{campaign_id}/evidence/{evidence_id}", response_model=EvidenceRecordDetail)
def get_campaign_evidence(
    campaign_id: int,
    evidence_id: int,
    db: Session = Depends(get_db),
    _: User = Depends(require_viewer_plus),
) -> EvidenceRecord:
    evidence = (
        db.query(EvidenceRecord)
        .filter(
            EvidenceRecord.id == evidence_id,
            EvidenceRecord.campaign_id == campaign_id,
        )
        .first()
    )
    if evidence is None:
        raise HTTPException(status_code=status.HTTP_404_NOT_FOUND, detail="Evidence record not found")
    return evidence


@router.get(
    "/{campaign_id}/evidence/{evidence_id}/verify",
    response_model=EvidenceVerificationRead,
)
def verify_campaign_evidence(
    campaign_id: int,
    evidence_id: int,
    db: Session = Depends(get_db),
    current_user: User = Depends(require_analyst_plus),
) -> EvidenceVerificationRead:
    evidence = (
        db.query(EvidenceRecord)
        .filter(
            EvidenceRecord.id == evidence_id,
            EvidenceRecord.campaign_id == campaign_id,
        )
        .first()
    )
    if evidence is None:
        raise HTTPException(status_code=status.HTTP_404_NOT_FOUND, detail="Evidence record not found")

    verification_result = verify_evidence_record(db=db, evidence_record=evidence)
    create_audit_log(
        db=db,
        action="evidence_verified",
        resource_type="evidence_record",
        resource_id=str(evidence.id),
        actor_user_id=current_user.id,
        details={
            "campaign_id": campaign_id,
            "is_valid": verification_result["is_valid"],
            "status": verification_result["status"].value,
        },
    )
    return EvidenceVerificationRead(**verification_result)


@router.get("/{campaign_id}/reports/latest", response_model=IncidentReportRead)
def get_latest_incident_report(
    campaign_id: int,
    db: Session = Depends(get_db),
    current_user: User = Depends(require_analyst_plus),
) -> IncidentReportRead:
    campaign = db.get(PhishingCampaign, campaign_id)
    if campaign is None:
        raise HTTPException(status_code=status.HTTP_404_NOT_FOUND, detail="Campaign not found")

    try:
        report = build_latest_incident_report(db=db, campaign=campaign)
    except ValueError as exc:
        raise HTTPException(status_code=status.HTTP_404_NOT_FOUND, detail=str(exc)) from exc

    create_audit_log(
        db=db,
        action="incident_report_generated",
        resource_type="campaign",
        resource_id=str(campaign.id),
        actor_user_id=current_user.id,
        details={
            "campaign_id": campaign.id,
            "report_hash": report["report_hash"],
            "evidence_id": report["evidence"]["id"],
        },
    )
    return IncidentReportRead(**report)


@router.get("/{campaign_id}/reports/latest/download")
def download_latest_incident_report(
    campaign_id: int,
    db: Session = Depends(get_db),
    current_user: User = Depends(require_analyst_plus),
) -> Response:
    report = get_latest_incident_report(campaign_id=campaign_id, db=db, current_user=current_user)
    filename = f"shadowtrace_campaign_{campaign_id}_incident_report.json"
    return Response(
        content=report.model_dump_json(indent=2),
        media_type="application/json",
        headers={"Content-Disposition": f'attachment; filename="{filename}"'},
    )


@router.get("/{campaign_id}/reports/latest/download/pdf")
def download_latest_incident_report_pdf(
    campaign_id: int,
    db: Session = Depends(get_db),
    current_user: User = Depends(require_analyst_plus),
) -> Response:
    campaign = db.get(PhishingCampaign, campaign_id)
    if campaign is None:
        raise HTTPException(status_code=status.HTTP_404_NOT_FOUND, detail="Campaign not found")

    try:
        report = build_latest_incident_report(db=db, campaign=campaign)
    except ValueError as exc:
        raise HTTPException(status_code=status.HTTP_404_NOT_FOUND, detail=str(exc)) from exc

    create_audit_log(
        db=db,
        action="pdf_report_downloaded",
        resource_type="campaign",
        resource_id=str(campaign.id),
        actor_user_id=current_user.id,
        details={
            "campaign_id": campaign.id,
            "report_hash": report["report_hash"],
            "format": "pdf",
        },
    )

    pdf_bytes = generate_pdf_report(report)
    filename = f"shadowtrace_campaign_{campaign_id}_incident_report.pdf"
    return Response(
        content=pdf_bytes,
        media_type="application/pdf",
        headers={"Content-Disposition": f'attachment; filename="{filename}"'},
    )


@router.post(
    "/track/{tracking_token}/events",
    response_model=PhishingEventRead,
    status_code=status.HTTP_201_CREATED,
)
def capture_campaign_event(
    tracking_token: str,
    payload: EventCaptureRequest,
    db: Session = Depends(get_db),
) -> PhishingEvent:
    campaign = get_campaign_by_tracking_token(db, tracking_token)
    if campaign is None:
        raise HTTPException(status_code=status.HTTP_404_NOT_FOUND, detail="Campaign not found")

    return record_campaign_event(
        db=db,
        campaign=campaign,
        event_type=payload.event_type,
        source_ip=payload.source_ip,
        user_agent=payload.user_agent,
        event_data=payload.event_data,
    )


@router.get("/audit/logs", response_model=list[AuditLogRead])
def list_audit_logs(
    db: Session = Depends(get_db),
    _: User = Depends(require_viewer_plus),
) -> list[AuditLog]:
    return db.query(AuditLog).order_by(AuditLog.created_at.desc()).limit(100).all()
