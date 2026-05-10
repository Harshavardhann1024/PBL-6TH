from tests.support import ShadowTraceDBTestCase
from app.api.routes import campaigns as campaign_routes
from app.api.routes import dashboard as dashboard_routes


class CampaignFlowTests(ShadowTraceDBTestCase):
    def test_suspicious_campaign_flow_creates_evidence_and_report(self) -> None:
        admin = self.register_user(email="admin@test.com")
        campaign = self.create_campaign(current_user=admin)

        event = self.capture_event(campaign=campaign, event_type="credentials_submitted")
        self.assertEqual(event.event_type.value, "credentials_submitted")

        evidence_items = campaign_routes.list_campaign_evidence(
            campaign_id=campaign.id,
            db=self.db,
            _=admin,
        )
        self.assertEqual(len(evidence_items), 1)
        self.assertEqual(evidence_items[0].status.value, "sealed")

        verification = campaign_routes.verify_campaign_evidence(
            campaign_id=campaign.id,
            evidence_id=evidence_items[0].id,
            db=self.db,
            current_user=admin,
        )
        self.assertTrue(verification.is_valid)

        timeline = dashboard_routes.get_dashboard_campaign_timeline(
            campaign_id=campaign.id,
            db=self.db,
            _=admin,
        )
        self.assertEqual(timeline.suspicious_events, 1)
        self.assertEqual(len(timeline.evidence), 1)

        audit_feed = dashboard_routes.get_dashboard_audit_feed(db=self.db, _=admin)
        self.assertGreaterEqual(audit_feed.total_entries, 3)

        report = campaign_routes.get_latest_incident_report(
            campaign_id=campaign.id,
            db=self.db,
            current_user=admin,
        )
        self.assertTrue(report.report_hash)
        self.assertTrue(report.signature)
        self.assertEqual(report.evidence["is_valid"], True)
