import hashlib
import io
import json
from datetime import UTC, datetime
from typing import Any

from reportlab.lib import colors
from reportlab.lib.pagesizes import A4
from reportlab.lib.styles import ParagraphStyle, getSampleStyleSheet
from reportlab.lib.units import mm
from reportlab.platypus import (
    HRFlowable,
    Paragraph,
    SimpleDocTemplate,
    Spacer,
    Table,
    TableStyle,
)
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


# ---------------------------------------------------------------------------
# PDF Report Generation
# ---------------------------------------------------------------------------

# Colour palette
_DARK_BG = colors.HexColor("#0d1117")
_PANEL_BG = colors.HexColor("#161b22")
_ACCENT = colors.HexColor("#c9a84c")
_TEXT_PRIMARY = colors.HexColor("#e6edf3")
_TEXT_SECONDARY = colors.HexColor("#8b949e")
_GREEN = colors.HexColor("#3fb950")
_RED = colors.HexColor("#f85149")
_BORDER = colors.HexColor("#30363d")


def _build_styles() -> dict[str, ParagraphStyle]:
    """Create custom paragraph styles for the report."""
    base = getSampleStyleSheet()
    return {
        "title": ParagraphStyle(
            "ReportTitle",
            parent=base["Title"],
            fontSize=22,
            textColor=_ACCENT,
            spaceAfter=4 * mm,
            fontName="Helvetica-Bold",
        ),
        "subtitle": ParagraphStyle(
            "ReportSubtitle",
            parent=base["Normal"],
            fontSize=9,
            textColor=_TEXT_SECONDARY,
            spaceAfter=6 * mm,
        ),
        "section": ParagraphStyle(
            "SectionHeading",
            parent=base["Heading2"],
            fontSize=13,
            textColor=_ACCENT,
            spaceBefore=6 * mm,
            spaceAfter=3 * mm,
            fontName="Helvetica-Bold",
        ),
        "body": ParagraphStyle(
            "BodyText",
            parent=base["Normal"],
            fontSize=10,
            textColor=_TEXT_PRIMARY,
            leading=14,
        ),
        "label": ParagraphStyle(
            "Label",
            parent=base["Normal"],
            fontSize=9,
            textColor=_TEXT_SECONDARY,
        ),
        "mono": ParagraphStyle(
            "Mono",
            parent=base["Normal"],
            fontSize=8,
            textColor=_TEXT_PRIMARY,
            fontName="Courier",
            leading=11,
        ),
        "footer": ParagraphStyle(
            "Footer",
            parent=base["Normal"],
            fontSize=7,
            textColor=_TEXT_SECONDARY,
            alignment=1,  # centered
        ),
        "badge_intact": ParagraphStyle(
            "BadgeIntact",
            parent=base["Normal"],
            fontSize=11,
            textColor=_GREEN,
            fontName="Helvetica-Bold",
        ),
        "badge_compromised": ParagraphStyle(
            "BadgeCompromised",
            parent=base["Normal"],
            fontSize=11,
            textColor=_RED,
            fontName="Helvetica-Bold",
        ),
    }


def _info_table(data: list[list[str]], styles: dict) -> Table:
    """Build a two-column key-value table."""
    table_data = [
        [Paragraph(row[0], styles["label"]), Paragraph(row[1], styles["body"])]
        for row in data
    ]
    table = Table(table_data, colWidths=[45 * mm, 120 * mm])
    table.setStyle(
        TableStyle(
            [
                ("BACKGROUND", (0, 0), (-1, -1), _PANEL_BG),
                ("BOX", (0, 0), (-1, -1), 0.5, _BORDER),
                ("INNERGRID", (0, 0), (-1, -1), 0.25, _BORDER),
                ("VALIGN", (0, 0), (-1, -1), "TOP"),
                ("TOPPADDING", (0, 0), (-1, -1), 4),
                ("BOTTOMPADDING", (0, 0), (-1, -1), 4),
                ("LEFTPADDING", (0, 0), (-1, -1), 6),
                ("RIGHTPADDING", (0, 0), (-1, -1), 6),
            ]
        )
    )
    return table


def generate_pdf_report(report_data: dict[str, Any]) -> bytes:
    """Generate a professional forensic incident report PDF.

    Returns the PDF content as bytes.
    """
    buf = io.BytesIO()
    doc = SimpleDocTemplate(
        buf,
        pagesize=A4,
        topMargin=15 * mm,
        bottomMargin=20 * mm,
        leftMargin=18 * mm,
        rightMargin=18 * mm,
    )

    styles = _build_styles()
    story: list[Any] = []

    # ── Header ──────────────────────────────────────────────────────────
    story.append(Paragraph("SHADOWTRACE", styles["title"]))
    story.append(
        Paragraph(
            f"Forensic Incident Report &bull; Generated {report_data['generated_at'][:19].replace('T', ' ')} UTC",
            styles["subtitle"],
        )
    )
    story.append(
        HRFlowable(width="100%", thickness=0.5, color=_BORDER, spaceAfter=4 * mm)
    )

    # ── 1. Campaign Information ─────────────────────────────────────────
    campaign = report_data["campaign"]
    story.append(Paragraph("1 &mdash; Campaign Information", styles["section"]))
    story.append(
        _info_table(
            [
                ["Campaign ID", str(campaign["id"])],
                ["Campaign Name", campaign["name"]],
                ["Target Email", campaign.get("target_email") or "N/A"],
                ["Tracking Token", campaign["tracking_token"]],
            ],
            styles,
        )
    )

    # ── 2. Incident Details ─────────────────────────────────────────────
    incident = report_data["incident"]
    story.append(Spacer(1, 2 * mm))
    story.append(Paragraph("2 &mdash; Incident Details", styles["section"]))
    event_data_str = json.dumps(incident.get("event_data", {}), indent=2)
    story.append(
        _info_table(
            [
                ["Event ID", str(incident["event_id"])],
                ["Event Type", incident["event_type"]],
                ["Source IP", incident.get("source_ip") or "Unknown"],
                ["Occurred At", incident["occurred_at"][:19].replace("T", " ") + " UTC"],
            ],
            styles,
        )
    )
    story.append(Spacer(1, 2 * mm))
    story.append(Paragraph("Event Data Payload:", styles["label"]))
    story.append(Spacer(1, 1 * mm))
    story.append(Paragraph(event_data_str.replace("\n", "<br/>"), styles["mono"]))

    # ── 3. Evidence Integrity ───────────────────────────────────────────
    evidence = report_data["evidence"]
    story.append(Spacer(1, 2 * mm))
    story.append(Paragraph("3 &mdash; Evidence Integrity Verification", styles["section"]))

    is_valid = evidence["is_valid"]
    badge_style = styles["badge_intact"] if is_valid else styles["badge_compromised"]
    badge_text = "✔ INTACT — Hash verified" if is_valid else "✘ COMPROMISED — Hash mismatch detected"
    story.append(Paragraph(badge_text, badge_style))
    story.append(Spacer(1, 2 * mm))

    story.append(
        _info_table(
            [
                ["Evidence ID", str(evidence["id"])],
                ["Status", evidence["status"].upper()],
                ["Stored Hash", evidence["stored_hash"] or "N/A"],
                ["Calculated Hash", evidence["calculated_hash"] or "N/A"],
            ],
            styles,
        )
    )

    # ── 4. Cryptographic Signature ──────────────────────────────────────
    story.append(Spacer(1, 2 * mm))
    story.append(Paragraph("4 &mdash; Cryptographic Signature", styles["section"]))

    sig = report_data.get("signature", "")
    sig_display = sig[:80] + "…" if len(sig) > 80 else sig

    story.append(
        _info_table(
            [
                ["Report Hash (SHA-256)", report_data["report_hash"]],
                ["RSA Signature (truncated)", sig_display],
                ["Signing Algorithm", "RSASSA-PSS / SHA-256"],
            ],
            styles,
        )
    )

    # ── 5. Summary ──────────────────────────────────────────────────────
    story.append(Spacer(1, 2 * mm))
    story.append(Paragraph("5 &mdash; Conclusion", styles["section"]))
    story.append(Paragraph(report_data.get("summary", ""), styles["body"]))

    # ── Footer ──────────────────────────────────────────────────────────
    story.append(Spacer(1, 8 * mm))
    story.append(
        HRFlowable(width="100%", thickness=0.5, color=_BORDER, spaceAfter=3 * mm)
    )
    story.append(
        Paragraph(
            "This report was generated and cryptographically signed by the ShadowTrace Forensics Platform. "
            "The evidence and signature can be independently verified using the RSA public key on file. "
            "Do not distribute without authorization.",
            styles["footer"],
        )
    )

    doc.build(story)
    return buf.getvalue()

