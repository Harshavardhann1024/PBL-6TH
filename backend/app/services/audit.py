import hashlib
import json
from datetime import UTC, datetime
from typing import Any

from sqlalchemy.orm import Session

from app.models.campaign import AuditLog


def _build_hash_payload(
    previous_hash: str | None,
    action: str,
    resource_type: str,
    resource_id: str,
    details: dict[str, Any],
    created_at: datetime,
) -> str:
    payload = {
        "previous_hash": previous_hash or "",
        "action": action,
        "resource_type": resource_type,
        "resource_id": resource_id,
        "details": details,
        "created_at": created_at.isoformat(),
    }
    normalized_payload = json.dumps(payload, sort_keys=True, separators=(",", ":"))
    return hashlib.sha256(normalized_payload.encode("utf-8")).hexdigest()


def create_audit_log(
    db: Session,
    action: str,
    resource_type: str,
    resource_id: str,
    details: dict[str, Any],
    actor_user_id: int | None = None,
) -> AuditLog:
    last_log = db.query(AuditLog).order_by(AuditLog.id.desc()).first()
    previous_hash = last_log.current_hash if last_log else None
    created_at = datetime.now(UTC)
    current_hash = _build_hash_payload(
        previous_hash=previous_hash,
        action=action,
        resource_type=resource_type,
        resource_id=resource_id,
        details=details,
        created_at=created_at,
    )

    audit_log = AuditLog(
        actor_user_id=actor_user_id,
        action=action,
        resource_type=resource_type,
        resource_id=resource_id,
        details=details,
        previous_hash=previous_hash,
        current_hash=current_hash,
        created_at=created_at,
    )
    db.add(audit_log)
    db.commit()
    db.refresh(audit_log)
    return audit_log
