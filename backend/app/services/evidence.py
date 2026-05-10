import base64
import hashlib
import json
import os
from datetime import UTC, datetime
from typing import Any

from cryptography.hazmat.primitives.ciphers.aead import AESGCM
from sqlalchemy.orm import Session

from app.core.config import settings
from app.models.campaign import (
    EvidenceRecord,
    EvidenceStatus,
    PhishingCampaign,
    PhishingEvent,
    PhishingEventType,
)

SUSPICIOUS_EVENT_TYPES = {
    PhishingEventType.credentials_submitted,
    PhishingEventType.suspicious_login,
}


def event_requires_evidence(event_type: PhishingEventType) -> bool:
    return event_type in SUSPICIOUS_EVENT_TYPES


def _serialize_payload(payload: dict[str, Any]) -> str:
    return json.dumps(payload, sort_keys=True, separators=(",", ":"))


def _hash_payload(serialized_payload: str) -> str:
    return hashlib.sha256(serialized_payload.encode("utf-8")).hexdigest()


def _get_encryption_key() -> bytes:
    return hashlib.sha256(settings.evidence_encryption_secret.encode("utf-8")).digest()


def _encrypt_payload(serialized_payload: str) -> str:
    aesgcm = AESGCM(_get_encryption_key())
    nonce = os.urandom(12)
    ciphertext = aesgcm.encrypt(nonce, serialized_payload.encode("utf-8"), None)
    package = {
        "algorithm": "AES-256-GCM",
        "nonce": base64.b64encode(nonce).decode("utf-8"),
        "ciphertext": base64.b64encode(ciphertext).decode("utf-8"),
    }
    return json.dumps(package, separators=(",", ":"))


def _decrypt_payload(encrypted_payload: str) -> str:
    package = json.loads(encrypted_payload)
    nonce = base64.b64decode(package["nonce"])
    ciphertext = base64.b64decode(package["ciphertext"])
    aesgcm = AESGCM(_get_encryption_key())
    plaintext = aesgcm.decrypt(nonce, ciphertext, None)
    return plaintext.decode("utf-8")


def build_evidence_payload(
    campaign: PhishingCampaign,
    event: PhishingEvent,
) -> dict[str, Any]:
    return {
        "campaign": {
            "id": campaign.id,
            "name": campaign.name,
            "target_email": campaign.target_email,
            "tracking_token": campaign.tracking_token,
        },
        "event": {
            "id": event.id,
            "type": event.event_type.value,
            "source_ip": event.source_ip,
            "user_agent": event.user_agent,
            "event_data": event.event_data,
            "occurred_at": event.occurred_at.isoformat(),
        },
        "sealed_at": datetime.now(UTC).isoformat(),
        "status": "sealed_for_forensic_review",
    }


def create_evidence_record(
    db: Session,
    campaign: PhishingCampaign,
    event: PhishingEvent,
) -> EvidenceRecord:
    payload = build_evidence_payload(campaign, event)
    serialized_payload = _serialize_payload(payload)
    integrity_hash = _hash_payload(serialized_payload)
    encrypted_payload = _encrypt_payload(serialized_payload)

    evidence_record = EvidenceRecord(
        campaign_id=campaign.id,
        summary=f"Sealed evidence for {event.event_type.value} event",
        encrypted_payload=encrypted_payload,
        integrity_hash=integrity_hash,
        status=EvidenceStatus.sealed,
    )
    db.add(evidence_record)
    db.commit()
    db.refresh(evidence_record)
    return evidence_record


def verify_evidence_record(
    db: Session,
    evidence_record: EvidenceRecord,
) -> dict[str, Any]:
    calculated_hash: str | None = None
    is_valid = False

    try:
        if not evidence_record.encrypted_payload:
            raise ValueError("Evidence payload is missing")

        serialized_payload = _decrypt_payload(evidence_record.encrypted_payload)
        calculated_hash = _hash_payload(serialized_payload)
        is_valid = calculated_hash == evidence_record.integrity_hash
    except Exception:
        is_valid = False

    expected_status = EvidenceStatus.sealed if is_valid else EvidenceStatus.compromised
    if evidence_record.status != expected_status:
        evidence_record.status = expected_status
        db.add(evidence_record)
        db.commit()
        db.refresh(evidence_record)

    return {
        "evidence_id": evidence_record.id,
        "campaign_id": evidence_record.campaign_id,
        "status": evidence_record.status,
        "is_valid": is_valid,
        "stored_hash": evidence_record.integrity_hash,
        "calculated_hash": calculated_hash,
        "verified_at": datetime.now(UTC),
    }
