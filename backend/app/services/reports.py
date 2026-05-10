import hashlib
import json
from datetime import UTC, datetime
from typing import Any

from sqlalchemy.orm import Session

from app.models.campaign import EvidenceRecord, PhishingCampaign, PhishingEvent, PhishingEventType
from app.services.evidence import verify_evidence_record
from app.services.signing import get_public_key_pem, sign_payload

SUSPICIOUS_REPORT_EVENTS = (
    PhishingEventType.credentials_submitted,
    PhishingEventType.suspicious_login,
)


def _canonicalize_report(report: dict[str, Any]) -> bytes:
    return json.dumps(report, sort_keys=True, separators=(",", ":")).encode("utf-8")


def build_latest_incident_report(db: Session, campaign: PhishingCampaign) -> dict[str, Any]:
    suspicious_event = (
        db.query(PhishingEvent)
        .filter(
            PhishingEvent.campaign_id == campaign.id,
            PhishingEvent.event_type.in_([event.value for event in SUSPICIOUS_REPORT_EVENTS]),
        )
        .order_by(PhishingEvent.occurred_at.desc())
        .first()
    )
    if suspicious_event is None:
        raise ValueError("No suspicious incident has been captured for this campaign yet")

    evidence_record = (
        db.query(EvidenceRecord)
        .filter(EvidenceRecord.campaign_id == campaign.id)
        .order_by(EvidenceRecord.created_at.desc())
        .first()
    )
    if evidence_record is None:
        raise ValueError("No evidence record is available for this campaign")

    verification = verify_evidence_record(db=db, evidence_record=evidence_record)
    generated_at = datetime.now(UTC)
    report_body = {
        "generated_at": generated_at.isoformat(),
        "campaign": {
            "id": campaign.id,
            "name": campaign.name,
            "target_email": campaign.target_email,
            "tracking_token": campaign.tracking_token,
        },
        "incident": {
            "event_id": suspicious_event.id,
            "event_type": suspicious_event.event_type.value,
            "source_ip": suspicious_event.source_ip,
            "occurred_at": suspicious_event.occurred_at.isoformat(),
            "event_data": suspicious_event.event_data,
        },
        "evidence": {
            "id": evidence_record.id,
            "status": verification["status"].value,
            "stored_hash": verification["stored_hash"],
            "calculated_hash": verification["calculated_hash"],
            "is_valid": verification["is_valid"],
        },
        "summary": (
            f"Campaign '{campaign.name}' captured a {suspicious_event.event_type.value} event "
            f"and sealed evidence record #{evidence_record.id} for forensic review."
        ),
    }

    canonical_report = _canonicalize_report(report_body)
    report_hash = hashlib.sha256(canonical_report).hexdigest()
    signature = sign_payload(canonical_report)
    evidence_record.signature = signature
    db.add(evidence_record)
    db.commit()
    db.refresh(evidence_record)

    return {
        **report_body,
        "report_hash": report_hash,
        "signature": signature,
        "public_key_pem": get_public_key_pem(),
    }
