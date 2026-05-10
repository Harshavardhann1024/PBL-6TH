from datetime import datetime
from typing import Any

from pydantic import BaseModel, ConfigDict, EmailStr, Field

from app.models.campaign import CampaignStatus, EvidenceStatus, PhishingEventType


class CampaignCreate(BaseModel):
    name: str = Field(min_length=3, max_length=150)
    description: str | None = Field(default=None, max_length=1000)
    target_email: EmailStr | None = None
    starts_at: datetime | None = None
    ends_at: datetime | None = None


class CampaignRead(BaseModel):
    model_config = ConfigDict(from_attributes=True)

    id: int
    name: str
    description: str | None
    target_email: str | None
    tracking_token: str
    status: CampaignStatus
    created_by_id: int
    starts_at: datetime | None
    ends_at: datetime | None
    created_at: datetime


class EventCaptureRequest(BaseModel):
    event_type: PhishingEventType
    source_ip: str | None = Field(default=None, max_length=64)
    user_agent: str | None = Field(default=None, max_length=500)
    event_data: dict[str, Any] = Field(default_factory=dict)


class PhishingEventRead(BaseModel):
    model_config = ConfigDict(from_attributes=True)

    id: int
    campaign_id: int
    event_type: PhishingEventType
    source_ip: str | None
    user_agent: str | None
    event_data: dict[str, Any]
    occurred_at: datetime


class EvidenceRecordRead(BaseModel):
    model_config = ConfigDict(from_attributes=True)

    id: int
    campaign_id: int
    summary: str
    integrity_hash: str | None
    status: EvidenceStatus
    created_at: datetime


class EvidenceRecordDetail(EvidenceRecordRead):
    encrypted_payload: str | None


class EvidenceVerificationRead(BaseModel):
    evidence_id: int
    campaign_id: int
    status: EvidenceStatus
    is_valid: bool
    stored_hash: str | None
    calculated_hash: str | None
    verified_at: datetime


class IncidentReportRead(BaseModel):
    generated_at: datetime
    campaign: dict[str, Any]
    incident: dict[str, Any]
    evidence: dict[str, Any]
    summary: str
    report_hash: str
    signature: str
    public_key_pem: str


class AuditLogRead(BaseModel):
    model_config = ConfigDict(from_attributes=True)

    id: int
    actor_user_id: int | None
    action: str
    resource_type: str
    resource_id: str
    details: dict[str, Any]
    previous_hash: str | None
    current_hash: str | None
    created_at: datetime
