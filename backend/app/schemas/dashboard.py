from datetime import datetime
from typing import Any

from pydantic import BaseModel

from app.models.campaign import CampaignStatus, EvidenceStatus, PhishingEventType


class DashboardOverview(BaseModel):
    total_campaigns: int
    total_events: int
    suspicious_events: int
    total_evidence: int
    compromised_evidence: int
    audit_actions: int


class DashboardCampaignSummary(BaseModel):
    campaign_id: int
    name: str
    status: CampaignStatus
    target_email: str | None
    total_events: int
    suspicious_events: int
    evidence_count: int
    compromised_evidence: int
    latest_activity_at: datetime | None
    created_at: datetime


class DashboardIncidentItem(BaseModel):
    campaign_id: int
    campaign_name: str
    event_id: int
    event_type: PhishingEventType
    source_ip: str | None
    evidence_status: EvidenceStatus | None
    occurred_at: datetime


class DashboardTimelineEvent(BaseModel):
    event_id: int
    event_type: PhishingEventType
    source_ip: str | None
    user_agent: str | None
    event_data: dict[str, Any]
    occurred_at: datetime
    is_suspicious: bool


class DashboardTimelineEvidence(BaseModel):
    evidence_id: int
    summary: str
    status: EvidenceStatus
    integrity_hash: str | None
    created_at: datetime


class DashboardCampaignTimeline(BaseModel):
    campaign_id: int
    name: str
    description: str | None
    status: CampaignStatus
    target_email: str | None
    tracking_token: str
    phishing_url: str
    total_events: int
    suspicious_events: int
    created_at: datetime
    events: list[DashboardTimelineEvent]
    evidence: list[DashboardTimelineEvidence]


class DashboardAuditItem(BaseModel):
    id: int
    action: str
    resource_type: str
    resource_id: str
    details: dict[str, Any]
    previous_hash: str | None
    current_hash: str | None
    created_at: datetime


class DashboardAuditFeed(BaseModel):
    total_entries: int
    evidence_sealed_actions: int
    report_actions: int
    verification_failures: int
    entries: list[DashboardAuditItem]
