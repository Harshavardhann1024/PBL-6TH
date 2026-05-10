import enum
from datetime import datetime
from uuid import uuid4

from sqlalchemy import JSON, DateTime, Enum, ForeignKey, String, Text, func
from sqlalchemy.orm import Mapped, mapped_column, relationship

from app.models.base import Base


class CampaignStatus(str, enum.Enum):
    draft = "draft"
    active = "active"
    paused = "paused"
    closed = "closed"


class PhishingEventType(str, enum.Enum):
    email_sent = "email_sent"
    link_clicked = "link_clicked"
    credentials_submitted = "credentials_submitted"
    suspicious_login = "suspicious_login"
    report_opened = "report_opened"


class EvidenceStatus(str, enum.Enum):
    pending = "pending"
    sealed = "sealed"
    compromised = "compromised"


class PhishingCampaign(Base):
    __tablename__ = "phishing_campaigns"

    id: Mapped[int] = mapped_column(primary_key=True, index=True)
    name: Mapped[str] = mapped_column(String(150), nullable=False)
    description: Mapped[str | None] = mapped_column(Text, nullable=True)
    target_email: Mapped[str | None] = mapped_column(String(255), nullable=True)
    tracking_token: Mapped[str] = mapped_column(
        String(64),
        unique=True,
        index=True,
        default=lambda: uuid4().hex,
        nullable=False,
    )
    status: Mapped[CampaignStatus] = mapped_column(
        Enum(CampaignStatus, values_callable=lambda obj: [item.value for item in obj]),
        default=CampaignStatus.draft,
        nullable=False,
    )
    created_by_id: Mapped[int] = mapped_column(ForeignKey("users.id"), nullable=False)
    starts_at: Mapped[datetime | None] = mapped_column(DateTime(timezone=True), nullable=True)
    ends_at: Mapped[datetime | None] = mapped_column(DateTime(timezone=True), nullable=True)
    created_at: Mapped[datetime] = mapped_column(
        DateTime(timezone=True),
        server_default=func.now(),
        nullable=False,
    )

    created_by = relationship("User")
    events = relationship("PhishingEvent", back_populates="campaign", cascade="all, delete-orphan")
    evidence_records = relationship(
        "EvidenceRecord",
        back_populates="campaign",
        cascade="all, delete-orphan",
    )


class PhishingEvent(Base):
    __tablename__ = "phishing_events"

    id: Mapped[int] = mapped_column(primary_key=True, index=True)
    campaign_id: Mapped[int] = mapped_column(ForeignKey("phishing_campaigns.id"), nullable=False)
    event_type: Mapped[PhishingEventType] = mapped_column(
        Enum(PhishingEventType, values_callable=lambda obj: [item.value for item in obj]),
        nullable=False,
    )
    source_ip: Mapped[str | None] = mapped_column(String(64), nullable=True)
    user_agent: Mapped[str | None] = mapped_column(String(500), nullable=True)
    event_data: Mapped[dict] = mapped_column(JSON, default=dict, nullable=False)
    occurred_at: Mapped[datetime] = mapped_column(
        DateTime(timezone=True),
        server_default=func.now(),
        nullable=False,
    )

    campaign = relationship("PhishingCampaign", back_populates="events")


class EvidenceRecord(Base):
    __tablename__ = "evidence_records"

    id: Mapped[int] = mapped_column(primary_key=True, index=True)
    campaign_id: Mapped[int] = mapped_column(ForeignKey("phishing_campaigns.id"), nullable=False)
    summary: Mapped[str] = mapped_column(String(255), nullable=False)
    encrypted_payload: Mapped[str | None] = mapped_column(Text, nullable=True)
    integrity_hash: Mapped[str | None] = mapped_column(String(128), nullable=True)
    signature: Mapped[str | None] = mapped_column(Text, nullable=True)
    status: Mapped[EvidenceStatus] = mapped_column(
        Enum(EvidenceStatus, values_callable=lambda obj: [item.value for item in obj]),
        default=EvidenceStatus.pending,
        nullable=False,
    )
    created_at: Mapped[datetime] = mapped_column(
        DateTime(timezone=True),
        server_default=func.now(),
        nullable=False,
    )

    campaign = relationship("PhishingCampaign", back_populates="evidence_records")


class AuditLog(Base):
    __tablename__ = "audit_logs"

    id: Mapped[int] = mapped_column(primary_key=True, index=True)
    actor_user_id: Mapped[int | None] = mapped_column(ForeignKey("users.id"), nullable=True)
    action: Mapped[str] = mapped_column(String(100), nullable=False, index=True)
    resource_type: Mapped[str] = mapped_column(String(100), nullable=False)
    resource_id: Mapped[str] = mapped_column(String(100), nullable=False)
    details: Mapped[dict] = mapped_column(JSON, default=dict, nullable=False)
    previous_hash: Mapped[str | None] = mapped_column(String(64), nullable=True)
    current_hash: Mapped[str | None] = mapped_column(String(64), nullable=True)
    created_at: Mapped[datetime] = mapped_column(
        DateTime(timezone=True),
        server_default=func.now(),
        nullable=False,
    )

    actor = relationship("User")
