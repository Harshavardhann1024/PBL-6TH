const state = {
  token: localStorage.getItem("shadowtrace_token") || "",
  user: localStorage.getItem("shadowtrace_user") || "",
  role: localStorage.getItem("shadowtrace_role") || "",
  campaigns: [],
  overview: null,
  incidents: [],
  auditFeed: null,
  selectedCampaignId: null,
  selectedTimelineCampaignId: null,
  timeline: null,
  evidence: [],
  latestCampaignLink: "",
  latestReport: null,
  users: [],
};

const $ = (id) => document.getElementById(id);
const elements = {
  loginOverlay: $("login-overlay"),
  loginForm: $("login-form"),
  emailInput: $("email-input"),
  passwordInput: $("password-input"),
  sessionUser: $("session-user"),
  logoutButton: $("logout-button"),
  connectionStatus: $("connection-status"),
  feedbackBanner: $("feedback-banner"),
  statsGrid: $("stats-grid"),
  campaignForm: $("campaign-form"),
  campaignNameInput: $("campaign-name-input"),
  campaignTargetInput: $("campaign-target-input"),
  campaignDescriptionInput: $("campaign-description-input"),
  campaignLinkCard: $("campaign-link-card"),
  campaignLinkValue: $("campaign-link-value"),
  copyLinkButton: $("copy-link-button"),
  openLinkButton: $("open-link-button"),
  campaignsTableBody: $("campaigns-table-body"),
  timelineCard: $("timeline-card"),
  timelineTitle: $("timeline-title"),
  timelineTarget: $("timeline-target"),
  timelineStatus: $("timeline-status"),
  timelineEventCount: $("timeline-event-count"),
  timelineSuspiciousCount: $("timeline-suspicious-count"),
  timelineEvents: $("timeline-events"),
  timelineEvidence: $("timeline-evidence"),
  timelineCopyLinkButton: $("timeline-copy-link-button"),
  timelineOpenLinkButton: $("timeline-open-link-button"),
  incidentsList: $("incidents-list"),
  campaignSelector: $("campaign-selector"),
  evidenceTableBody: $("evidence-table-body"),
  verificationEmpty: $("verification-empty"),
  verificationResult: $("verification-result"),
  verificationStatusPill: $("verification-status-pill"),
  verifyEvidenceId: $("verify-evidence-id"),
  verifyCampaignId: $("verify-campaign-id"),
  verifyStoredHash: $("verify-stored-hash"),
  verifyCalculatedHash: $("verify-calculated-hash"),
  verifyTimestamp: $("verify-timestamp"),
  generateReportButton: $("generate-report-button"),
  downloadReportButton: $("download-report-button"),
  downloadPdfButton: $("download-pdf-button"),
  reportEmpty: $("report-empty"),
  reportResult: $("report-result"),
  reportHash: $("report-hash"),
  reportEvidenceStatus: $("report-evidence-status"),
  reportSignature: $("report-signature"),
  reportGeneratedAt: $("report-generated-at"),
  auditStatsGrid: $("audit-stats-grid"),
  auditTableBody: $("audit-table-body"),
  roleBadge: $("role-badge"),
  navUsers: $("nav-users"),
  usersTableBody: $("users-table-body"),
};

const navButtons = Array.from(document.querySelectorAll("[data-view]"));
const views = {
  overview: $("overview-view"),
  campaigns: $("campaigns-view"),
  incidents: $("incidents-view"),
  evidence: $("evidence-view"),
  audit: $("audit-view"),
  users: $("users-view"),
};

const ROLE_LABELS = {
  super_admin: "Super Admin",
  admin: "Admin",
  analyst: "Analyst",
  viewer: "Viewer",
  employee: "Employee",
};

const ALL_ROLES = ["super_admin", "admin", "analyst", "viewer", "employee"];

function escapeHtml(value) {
  return String(value ?? "")
    .replaceAll("&", "&amp;")
    .replaceAll("<", "&lt;")
    .replaceAll(">", "&gt;")
    .replaceAll('"', "&quot;")
    .replaceAll("'", "&#39;");
}

function formatDate(value) {
  if (!value) return "-";
  return new Date(value).toLocaleString();
}

function prettyJson(value) {
  return JSON.stringify(value ?? {}, null, 2);
}

function truncate(value, length = 20) {
  if (!value) return "-";
  return value.length > length ? `${value.slice(0, length)}...` : value;
}

function getStatusClass(status) {
  const normalized = String(status || "").toLowerCase();
  if (["sealed", "valid", "active"].includes(normalized)) return "status-active";
  if (["compromised", "invalid"].includes(normalized)) return "status-compromised";
  if (["paused", "closed"].includes(normalized)) return "status-paused";
  return "status-draft";
}

function showFeedback(message = "", type = "success") {
  if (!message) {
    elements.feedbackBanner.className = "feedback-banner hidden";
    elements.feedbackBanner.textContent = "";
    return;
  }
  elements.feedbackBanner.className = `feedback-banner ${type}`;
  elements.feedbackBanner.textContent = message;
}

function setSessionState(authenticated) {
  elements.loginOverlay.classList.toggle("hidden", authenticated);
  elements.sessionUser.textContent = authenticated ? state.user : "Not authenticated";
  elements.connectionStatus.textContent = authenticated ? "Secure channel active" : "Awaiting authentication";
  updateRoleBadge();
  applyRoleVisibility();
}

function updateRoleBadge() {
  const badge = elements.roleBadge;
  if (!state.role) {
    badge.textContent = "";
    badge.className = "role-badge";
    return;
  }
  badge.textContent = ROLE_LABELS[state.role] || state.role;
  badge.className = `role-badge role-${state.role}`;
}

function applyRoleVisibility() {
  const role = state.role;
  const isViewer = role === "viewer";
  const isSuperAdmin = role === "super_admin";
  const isAdminPlus = ["super_admin", "admin"].includes(role);

  // Users tab: only super_admin and admin
  if (elements.navUsers) {
    elements.navUsers.style.display = isAdminPlus ? "" : "none";
  }

  // Campaign create form: hide for viewer
  const campaignForm = elements.campaignForm;
  if (campaignForm) {
    campaignForm.closest(".campaign-layout").style.display = isViewer ? "none" : "";
  }

  // Report/verify buttons: hide for viewer
  const reportBtns = [elements.generateReportButton, elements.downloadReportButton, elements.downloadPdfButton];
  reportBtns.forEach((btn) => { if (btn) btn.style.display = isViewer ? "none" : ""; });
}

function setActiveView(viewName) {
  navButtons.forEach((button) => {
    button.classList.toggle("active", button.dataset.view === viewName);
  });
  Object.entries(views).forEach(([name, element]) => {
    element.classList.toggle("hidden", name !== viewName);
  });
  document.querySelector(".dashboard-main")?.scrollTo({ top: 0, behavior: "smooth" });
}

function setButtonBusy(button, isBusy, label = "Working...") {
  if (!button) return;
  if (isBusy) {
    button.dataset.originalLabel = button.textContent;
    button.textContent = label;
    button.disabled = true;
    return;
  }
  button.textContent = button.dataset.originalLabel || button.textContent;
  button.disabled = false;
}

function getCampaignLink(campaign) {
  if (!campaign?.tracking_token) return "";
  return `${window.location.origin}/phish/${campaign.tracking_token}`;
}

function getCampaignById(campaignId) {
  return state.campaigns.find((campaign) => Number(campaign.campaign_id || campaign.id) === Number(campaignId));
}

function renderCampaignLinkPanel(link = "") {
  state.latestCampaignLink = link;
  if (!link) {
    elements.campaignLinkCard.classList.add("hidden");
    elements.campaignLinkValue.textContent = "No campaign created yet.";
    elements.openLinkButton.href = "#";
    return;
  }
  elements.campaignLinkCard.classList.remove("hidden");
  elements.campaignLinkValue.textContent = link;
  elements.openLinkButton.href = link;
}

function resetVerification() {
  elements.verificationEmpty.classList.remove("hidden");
  elements.verificationResult.classList.add("hidden");
}

function resetReport() {
  state.latestReport = null;
  elements.reportEmpty.classList.remove("hidden");
  elements.reportResult.classList.add("hidden");
  elements.reportHash.textContent = "-";
  elements.reportEvidenceStatus.textContent = "-";
  elements.reportSignature.textContent = "-";
  elements.reportGeneratedAt.textContent = "-";
}

function renderOverview() {
  const stats = state.overview || {
    total_campaigns: 0,
    total_events: 0,
    suspicious_events: 0,
    total_evidence: 0,
    compromised_evidence: 0,
    audit_actions: 0,
  };
  const cards = [
    ["Total Campaigns", stats.total_campaigns],
    ["Captured Events", stats.total_events],
    ["Suspicious Events", stats.suspicious_events],
    ["Evidence Records", stats.total_evidence],
    ["Compromised Evidence", stats.compromised_evidence],
    ["Audit Actions", stats.audit_actions],
  ];

  elements.statsGrid.innerHTML = cards
    .map(
      ([label, value]) => `
        <dl class="stat-card">
          <dt>${escapeHtml(label)}</dt>
          <dd>${escapeHtml(value)}</dd>
        </dl>`,
    )
    .join("");
}

function renderCampaigns() {
  if (!state.campaigns.length) {
    elements.campaignsTableBody.innerHTML = `<tr><td colspan="9" class="muted-cell">No campaigns available yet.</td></tr>`;
    return;
  }

  elements.campaignsTableBody.innerHTML = state.campaigns
    .map(
      (campaign) => `
        <tr>
          <td>${escapeHtml(campaign.name)}</td>
          <td><span class="status-pill ${getStatusClass(campaign.status)}">${escapeHtml(campaign.status)}</span></td>
          <td>${escapeHtml(campaign.target_email || "-")}</td>
          <td>${escapeHtml(campaign.total_events)}</td>
          <td>${escapeHtml(campaign.suspicious_events)}</td>
          <td>${escapeHtml(campaign.evidence_count)}</td>
          <td>${escapeHtml(campaign.compromised_evidence)}</td>
          <td>${escapeHtml(formatDate(campaign.latest_activity_at || campaign.created_at))}</td>
          <td>
            <div class="campaign-link-actions">
              <button type="button" class="verify-button" data-view-timeline="${campaign.campaign_id}">Timeline</button>
              <button type="button" class="verify-button" data-copy-token="${campaign.campaign_id}">Copy</button>
              <button type="button" class="verify-button" data-open-token="${campaign.campaign_id}">Open</button>
            </div>
          </td>
        </tr>`,
    )
    .join("");

  document.querySelectorAll("[data-view-timeline]").forEach((button) => {
    button.addEventListener("click", () => focusTimelineCampaign(Number(button.dataset.viewTimeline)));
  });
  document.querySelectorAll("[data-copy-token]").forEach((button) => {
    button.addEventListener("click", () => copyCampaignLink(Number(button.dataset.copyToken)));
  });
  document.querySelectorAll("[data-open-token]").forEach((button) => {
    button.addEventListener("click", () => openCampaignLink(Number(button.dataset.openToken)));
  });
}

function renderTimeline() {
  if (!state.timeline) {
    elements.timelineCard.classList.add("hidden");
    return;
  }

  elements.timelineCard.classList.remove("hidden");
  elements.timelineTitle.textContent = `${state.timeline.name} timeline`;
  elements.timelineTarget.textContent = state.timeline.target_email || "-";
  elements.timelineStatus.innerHTML = `<span class="status-pill ${getStatusClass(state.timeline.status)}">${escapeHtml(state.timeline.status)}</span>`;
  elements.timelineEventCount.textContent = state.timeline.total_events;
  elements.timelineSuspiciousCount.textContent = state.timeline.suspicious_events;

  elements.timelineEvents.innerHTML = state.timeline.events.length
    ? state.timeline.events
        .map(
          (event) => `
            <article class="timeline-item ${event.is_suspicious ? "suspicious" : ""}">
              <div class="timeline-item-header">
                <div>
                  <p class="panel-kicker">Event</p>
                  <h4>${escapeHtml(event.event_type)}</h4>
                </div>
                <span class="status-pill ${event.is_suspicious ? "status-compromised" : "status-active"}">
                  ${event.is_suspicious ? "Suspicious" : "Normal"}
                </span>
              </div>
              <div class="timeline-item-meta">
                <span>${escapeHtml(formatDate(event.occurred_at))}</span>
                <span>${escapeHtml(event.source_ip || "Unknown source")}</span>
                <span>${escapeHtml(event.user_agent || "Unknown agent")}</span>
              </div>
              <pre class="timeline-item-pre">${escapeHtml(prettyJson(event.event_data))}</pre>
            </article>`,
        )
        .join("")
    : `<div class="empty-state">No events recorded for this campaign yet.</div>`;

  elements.timelineEvidence.innerHTML = state.timeline.evidence.length
    ? state.timeline.evidence
        .map(
          (evidence) => `
            <article class="timeline-evidence-card">
              <p class="panel-kicker">Evidence #${escapeHtml(evidence.evidence_id)}</p>
              <h4>${escapeHtml(evidence.summary)}</h4>
              <span class="status-pill ${getStatusClass(evidence.status)}">${escapeHtml(evidence.status)}</span>
              <p>${escapeHtml(truncate(evidence.integrity_hash, 28))}</p>
              <p>${escapeHtml(formatDate(evidence.created_at))}</p>
            </article>`,
        )
        .join("")
    : `<div class="empty-state">No evidence has been sealed for this campaign yet.</div>`;
}

function renderIncidents() {
  if (!state.incidents.length) {
    elements.incidentsList.innerHTML = `<div class="empty-state">No suspicious incidents captured yet.</div>`;
    return;
  }

  elements.incidentsList.innerHTML = state.incidents
    .map(
      (incident) => `
        <article class="incident-card">
          <div>
            <p class="panel-kicker">Campaign</p>
            <h4>${escapeHtml(incident.campaign_name)}</h4>
            <p>Event #${escapeHtml(incident.event_id)}</p>
          </div>
          <div>
            <p class="panel-kicker">Event Type</p>
            <h4>${escapeHtml(incident.event_type)}</h4>
            <p>${escapeHtml(formatDate(incident.occurred_at))}</p>
          </div>
          <div>
            <p class="panel-kicker">Source IP</p>
            <h4>${escapeHtml(incident.source_ip || "Unknown")}</h4>
          </div>
          <div>
            <p class="panel-kicker">Evidence</p>
            <span class="status-pill ${getStatusClass(incident.evidence_status)}">${escapeHtml(incident.evidence_status || "none")}</span>
          </div>
        </article>`,
    )
    .join("");
}

function renderEvidenceSelector() {
  if (!state.campaigns.length) {
    elements.campaignSelector.innerHTML = `<option value="">No campaigns available</option>`;
    return;
  }
  elements.campaignSelector.innerHTML = state.campaigns
    .map(
      (campaign) => `
        <option value="${campaign.campaign_id}" ${String(state.selectedCampaignId) === String(campaign.campaign_id) ? "selected" : ""}>
          ${escapeHtml(campaign.name)} (#${escapeHtml(campaign.campaign_id)})
        </option>`,
    )
    .join("");
}

function renderEvidence() {
  if (!state.evidence.length) {
    elements.evidenceTableBody.innerHTML = `<tr><td colspan="6" class="muted-cell">No evidence records found for the selected campaign.</td></tr>`;
    resetVerification();
    resetReport();
    return;
  }

  elements.evidenceTableBody.innerHTML = state.evidence
    .map(
      (item) => `
        <tr>
          <td>${escapeHtml(item.id)}</td>
          <td>${escapeHtml(item.summary)}</td>
          <td><span class="status-pill ${getStatusClass(item.status)}">${escapeHtml(item.status)}</span></td>
          <td>${escapeHtml(truncate(item.integrity_hash, 18))}</td>
          <td>${escapeHtml(formatDate(item.created_at))}</td>
          <td><button type="button" class="verify-button" data-evidence-id="${item.id}">Verify</button></td>
        </tr>`,
    )
    .join("");

  document.querySelectorAll("[data-evidence-id]").forEach((button) => {
    button.addEventListener("click", () => verifyEvidence(button.dataset.evidenceId));
  });
}

function renderVerification(result) {
  elements.verificationEmpty.classList.add("hidden");
  elements.verificationResult.classList.remove("hidden");
  elements.verificationStatusPill.className = `status-pill ${result.is_valid ? "status-active" : "status-compromised"}`;
  elements.verificationStatusPill.textContent = result.is_valid ? "Valid" : "Compromised";
  elements.verifyEvidenceId.textContent = result.evidence_id;
  elements.verifyCampaignId.textContent = result.campaign_id;
  elements.verifyStoredHash.textContent = result.stored_hash || "-";
  elements.verifyCalculatedHash.textContent = result.calculated_hash || "-";
  elements.verifyTimestamp.textContent = formatDate(result.verified_at);
}

function renderReport(report) {
  elements.reportEmpty.classList.add("hidden");
  elements.reportResult.classList.remove("hidden");
  elements.reportHash.textContent = report.report_hash || "-";
  elements.reportEvidenceStatus.textContent = report.evidence?.status || "-";
  elements.reportSignature.textContent = report.signature ? `${report.signature.slice(0, 64)}...` : "-";
  elements.reportGeneratedAt.textContent = formatDate(report.generated_at);
}

function renderAuditFeed() {
  const auditFeed = state.auditFeed || {
    total_entries: 0,
    evidence_sealed_actions: 0,
    report_actions: 0,
    verification_failures: 0,
    entries: [],
  };

  const stats = [
    ["Total Entries", auditFeed.total_entries],
    ["Evidence Sealed", auditFeed.evidence_sealed_actions],
    ["Reports Generated", auditFeed.report_actions],
    ["Verification Failures", auditFeed.verification_failures],
  ];
  elements.auditStatsGrid.innerHTML = stats
    .map(
      ([label, value]) => `
        <dl class="audit-stat-card">
          <dt>${escapeHtml(label)}</dt>
          <dd>${escapeHtml(value)}</dd>
        </dl>`,
    )
    .join("");

  elements.auditTableBody.innerHTML = auditFeed.entries.length
    ? auditFeed.entries
        .map(
          (entry) => `
            <tr>
              <td>${escapeHtml(entry.action)}</td>
              <td>${escapeHtml(`${entry.resource_type} #${entry.resource_id}`)}</td>
              <td><pre class="timeline-item-pre">${escapeHtml(prettyJson(entry.details))}</pre></td>
              <td>${escapeHtml(truncate(entry.previous_hash, 18))}</td>
              <td>${escapeHtml(truncate(entry.current_hash, 18))}</td>
              <td>${escapeHtml(formatDate(entry.created_at))}</td>
            </tr>`,
        )
        .join("")
    : `<tr><td colspan="6" class="muted-cell">No audit entries available.</td></tr>`;
}

async function apiFetch(path, options = {}) {
  const headers = new Headers(options.headers || {});
  if (state.token) {
    headers.set("Authorization", `Bearer ${state.token}`);
  }

  const response = await fetch(path, { ...options, headers });
  if (response.status === 401) {
    clearSession();
    throw new Error("Session expired. Sign in again.");
  }
  if (!response.ok) {
    throw new Error((await response.text()) || `Request failed with status ${response.status}`);
  }
  return response.json();
}

async function copyToClipboard(text) {
  if (navigator.clipboard?.writeText) {
    await navigator.clipboard.writeText(text);
    return;
  }
  const temp = document.createElement("input");
  temp.value = text;
  document.body.appendChild(temp);
  temp.select();
  document.execCommand("copy");
  document.body.removeChild(temp);
}

async function loadTimelineForCampaign(campaignId) {
  if (!campaignId) {
    state.timeline = null;
    renderTimeline();
    return;
  }
  state.selectedTimelineCampaignId = Number(campaignId);
  state.timeline = await apiFetch(`/api/v1/dashboard/campaigns/${campaignId}/timeline`);
  renderTimeline();
}

async function loadEvidenceForCampaign(campaignId) {
  if (!campaignId) {
    state.evidence = [];
    renderEvidence();
    return;
  }
  state.selectedCampaignId = Number(campaignId);
  state.evidence = await apiFetch(`/api/v1/campaigns/${campaignId}/evidence`);
  renderEvidenceSelector();
  renderEvidence();
}

async function refreshDashboardData() {
  const [overview, campaignSummaries, incidents, campaignDetails, auditFeed] = await Promise.all([
    apiFetch("/api/v1/dashboard/overview"),
    apiFetch("/api/v1/dashboard/campaigns"),
    apiFetch("/api/v1/dashboard/incidents"),
    apiFetch("/api/v1/campaigns/"),
    apiFetch("/api/v1/dashboard/audit"),
  ]);

  state.overview = overview;
  state.campaigns = campaignSummaries.map((summary) => {
    const detail = campaignDetails.find((campaign) => campaign.id === summary.campaign_id);
    return detail ? { ...summary, tracking_token: detail.tracking_token } : summary;
  });
  state.incidents = incidents;
  state.auditFeed = auditFeed;

  const selectedCampaignStillExists = state.campaigns.some(
    (campaign) => Number(campaign.campaign_id) === Number(state.selectedCampaignId),
  );
  const selectedTimelineStillExists = state.campaigns.some(
    (campaign) => Number(campaign.campaign_id) === Number(state.selectedTimelineCampaignId),
  );

  if ((!state.selectedCampaignId || !selectedCampaignStillExists) && state.campaigns.length) {
    state.selectedCampaignId = state.campaigns[0].campaign_id;
  }
  if ((!state.selectedTimelineCampaignId || !selectedTimelineStillExists) && state.campaigns.length) {
    state.selectedTimelineCampaignId = state.campaigns[0].campaign_id;
  }
  if (!state.campaigns.length) {
    state.selectedCampaignId = null;
    state.selectedTimelineCampaignId = null;
  }
}

async function loadDashboard(showMessage = true) {
  await refreshDashboardData();
  renderOverview();
  renderCampaigns();
  renderIncidents();
  renderAuditFeed();
  renderEvidenceSelector();
  await Promise.all([
    loadEvidenceForCampaign(state.selectedCampaignId),
    loadTimelineForCampaign(state.selectedTimelineCampaignId),
  ]);
  if (showMessage) {
    showFeedback("Dashboard data loaded successfully.");
  }
}

async function verifyEvidence(evidenceId) {
  try {
    const result = await apiFetch(`/api/v1/campaigns/${state.selectedCampaignId}/evidence/${evidenceId}/verify`);
    await loadDashboard(false);
    renderVerification(result);
    showFeedback(
      result.is_valid ? `Evidence #${evidenceId} verified successfully.` : `Evidence #${evidenceId} is compromised.`,
      result.is_valid ? "success" : "error",
    );
  } catch (error) {
    showFeedback(error.message, "error");
  }
}

async function generateLatestReport() {
  if (!state.selectedCampaignId) {
    showFeedback("Select a campaign first.", "error");
    return;
  }
  try {
    setButtonBusy(elements.generateReportButton, true, "Generating...");
    const report = await apiFetch(`/api/v1/campaigns/${state.selectedCampaignId}/reports/latest`);
    state.latestReport = report;
    await loadDashboard(false);
    renderReport(report);
    showFeedback("Signed incident report generated successfully.");
  } catch (error) {
    showFeedback(error.message, "error");
  } finally {
    setButtonBusy(elements.generateReportButton, false);
  }
}

async function downloadLatestReport() {
  if (!state.selectedCampaignId) {
    showFeedback("Select a campaign first.", "error");
    return;
  }
  try {
    setButtonBusy(elements.downloadReportButton, true, "Preparing...");
    const response = await fetch(`/api/v1/campaigns/${state.selectedCampaignId}/reports/latest/download`, {
      headers: { Authorization: `Bearer ${state.token}` },
    });
    if (response.status === 401) {
      clearSession();
      throw new Error("Session expired. Sign in again.");
    }
    if (!response.ok) {
      throw new Error((await response.text()) || "Could not download report.");
    }
    const blob = await response.blob();
    const url = URL.createObjectURL(blob);
    const link = document.createElement("a");
    link.href = url;
    link.download = `shadowtrace_campaign_${state.selectedCampaignId}_incident_report.json`;
    document.body.appendChild(link);
    link.click();
    link.remove();
    URL.revokeObjectURL(url);
    showFeedback("Incident report downloaded successfully.");
  } catch (error) {
    showFeedback(error.message, "error");
  } finally {
    setButtonBusy(elements.downloadReportButton, false);
  }
}

async function copyCampaignLink(campaignId) {
  const campaign = getCampaignById(campaignId);
  if (!campaign?.tracking_token) {
    showFeedback("Tracking token is not available for this campaign.", "error");
    return;
  }
  const link = getCampaignLink(campaign);
  renderCampaignLinkPanel(link);
  try {
    await copyToClipboard(link);
    showFeedback("Phishing link copied to clipboard.");
  } catch {
    showFeedback(link, "success");
  }
}

function openCampaignLink(campaignId) {
  const campaign = getCampaignById(campaignId);
  if (!campaign?.tracking_token) {
    showFeedback("Tracking token is not available for this campaign.", "error");
    return;
  }
  const link = getCampaignLink(campaign);
  renderCampaignLinkPanel(link);
  window.open(link, "_blank", "noopener,noreferrer");
}

async function focusTimelineCampaign(campaignId) {
  try {
    await loadTimelineForCampaign(campaignId);
    const campaign = getCampaignById(campaignId);
    if (campaign?.tracking_token) {
      renderCampaignLinkPanel(getCampaignLink(campaign));
    }
    setActiveView("campaigns");
    elements.timelineCard.scrollIntoView({ behavior: "smooth", block: "start" });
  } catch (error) {
    showFeedback(error.message, "error");
  }
}

async function handleLogin(event) {
  event.preventDefault();
  showFeedback("");
  const email = elements.emailInput.value.trim();
  const password = elements.passwordInput.value;
  const payload = new URLSearchParams({ username: email, password });

  try {
    setButtonBusy(elements.loginForm.querySelector("button[type='submit']"), true, "Authorizing...");
    const response = await fetch("/api/v1/auth/login", {
      method: "POST",
      headers: { "Content-Type": "application/x-www-form-urlencoded" },
      body: payload,
    });
    if (!response.ok) {
      throw new Error("Login failed. Check your credentials.");
    }
    const data = await response.json();
    state.token = data.access_token;
    state.user = email;
    localStorage.setItem("shadowtrace_token", state.token);
    localStorage.setItem("shadowtrace_user", state.user);

    // Fetch role from /me
    const me = await apiFetch("/api/v1/auth/me");
    state.role = me.role;
    localStorage.setItem("shadowtrace_role", state.role);

    setSessionState(true);
    await loadDashboard();
  } catch (error) {
    showFeedback(error.message, "error");
  } finally {
    setButtonBusy(elements.loginForm.querySelector("button[type='submit']"), false);
  }
}

async function handleCampaignCreate(event) {
  event.preventDefault();
  showFeedback("");
  const payload = {
    name: elements.campaignNameInput.value.trim(),
    description: elements.campaignDescriptionInput.value.trim() || null,
    target_email: elements.campaignTargetInput.value.trim() || null,
    starts_at: null,
    ends_at: null,
  };

  try {
    setButtonBusy(elements.campaignForm.querySelector("button[type='submit']"), true, "Creating...");
    const createdCampaign = await apiFetch("/api/v1/campaigns/", {
      method: "POST",
      headers: { "Content-Type": "application/json" },
      body: JSON.stringify(payload),
    });
    const phishingLink = getCampaignLink(createdCampaign);
    state.selectedCampaignId = createdCampaign.id;
    state.selectedTimelineCampaignId = createdCampaign.id;
    renderCampaignLinkPanel(phishingLink);
    await copyToClipboard(phishingLink).catch(() => undefined);
    elements.campaignForm.reset();
    await loadDashboard(false);
    await loadTimelineForCampaign(createdCampaign.id);
    setActiveView("campaigns");
    showFeedback("Campaign created successfully. The phishing link is ready to use.");
  } catch (error) {
    showFeedback(error.message, "error");
  } finally {
    setButtonBusy(elements.campaignForm.querySelector("button[type='submit']"), false);
  }
}

function clearSession() {
  state.token = "";
  state.user = "";
  state.role = "";
  state.campaigns = [];
  state.overview = null;
  state.incidents = [];
  state.auditFeed = null;
  state.selectedCampaignId = null;
  state.selectedTimelineCampaignId = null;
  state.timeline = null;
  state.evidence = [];
  state.latestCampaignLink = "";
  state.latestReport = null;
  state.users = [];
  localStorage.removeItem("shadowtrace_token");
  localStorage.removeItem("shadowtrace_user");
  localStorage.removeItem("shadowtrace_role");
  setSessionState(false);
  showFeedback("");
  resetVerification();
  resetReport();
  renderCampaignLinkPanel("");
  renderOverview();
  renderCampaigns();
  renderTimeline();
  renderIncidents();
  renderAuditFeed();
  renderEvidenceSelector();
  renderEvidence();
}

elements.loginForm.addEventListener("submit", handleLogin);
elements.campaignForm.addEventListener("submit", handleCampaignCreate);
elements.logoutButton.addEventListener("click", () => {
  clearSession();
  showFeedback("Session closed.");
});
elements.copyLinkButton.addEventListener("click", async () => {
  if (!state.latestCampaignLink) return;
  try {
    await copyToClipboard(state.latestCampaignLink);
    showFeedback("Phishing link copied to clipboard.");
  } catch {
    showFeedback(state.latestCampaignLink, "success");
  }
});
elements.timelineCopyLinkButton.addEventListener("click", () => {
  if (state.selectedTimelineCampaignId) {
    copyCampaignLink(state.selectedTimelineCampaignId);
  }
});
elements.timelineOpenLinkButton.addEventListener("click", () => {
  if (state.selectedTimelineCampaignId) {
    openCampaignLink(state.selectedTimelineCampaignId);
  }
});
elements.campaignSelector.addEventListener("change", async (event) => {
  try {
    await loadEvidenceForCampaign(event.target.value);
    resetReport();
  } catch (error) {
    showFeedback(error.message, "error");
  }
});
elements.generateReportButton.addEventListener("click", generateLatestReport);
elements.downloadReportButton.addEventListener("click", downloadLatestReport);

// PDF download handler
elements.downloadPdfButton.addEventListener("click", async () => {
  if (!state.selectedCampaignId) {
    showFeedback("Select a campaign first.", "error");
    return;
  }
  try {
    setButtonBusy(elements.downloadPdfButton, true, "Preparing...");
    const response = await fetch(
      `/api/v1/campaigns/${state.selectedCampaignId}/reports/latest/download/pdf`,
      { headers: { Authorization: `Bearer ${state.token}` } },
    );
    if (response.status === 401) { clearSession(); throw new Error("Session expired."); }
    if (!response.ok) { throw new Error((await response.text()) || "Could not download PDF."); }
    const blob = await response.blob();
    const url = URL.createObjectURL(blob);
    const link = document.createElement("a");
    link.href = url;
    link.download = `shadowtrace_campaign_${state.selectedCampaignId}_incident_report.pdf`;
    document.body.appendChild(link);
    link.click();
    link.remove();
    URL.revokeObjectURL(url);
    showFeedback("PDF incident report downloaded successfully.");
  } catch (error) {
    showFeedback(error.message, "error");
  } finally {
    setButtonBusy(elements.downloadPdfButton, false);
  }
});

navButtons.forEach((button) => {
  button.addEventListener("click", async () => {
    setActiveView(button.dataset.view);
    // Load users on first visit
    if (button.dataset.view === "users" && !state.users.length) {
      await loadUsers();
    }
  });
});

// ── Users management ──────────────────────────────────────────────────
async function loadUsers() {
  try {
    state.users = await apiFetch("/api/v1/auth/users");
    renderUsers();
  } catch (error) {
    showFeedback(error.message, "error");
  }
}

function renderUsers() {
  if (!state.users.length) {
    elements.usersTableBody.innerHTML = `<tr><td colspan="6" class="muted-cell">No users found.</td></tr>`;
    return;
  }
  const isSuperAdmin = state.role === "super_admin";
  elements.usersTableBody.innerHTML = state.users
    .map(
      (user) => `
        <tr>
          <td>${escapeHtml(user.id)}</td>
          <td>${escapeHtml(user.full_name)}</td>
          <td>${escapeHtml(user.email)}</td>
          <td><span class="role-badge role-${user.role}">${escapeHtml(ROLE_LABELS[user.role] || user.role)}</span></td>
          <td>${escapeHtml(formatDate(user.created_at))}</td>
          <td>
            ${isSuperAdmin && user.email !== state.user ? `
              <select class="role-change-select" data-user-id="${user.id}">
                ${ALL_ROLES.map((r) => `<option value="${r}" ${user.role === r ? "selected" : ""}>${ROLE_LABELS[r]}</option>`).join("")}
              </select>
            ` : `<span class="muted-cell">—</span>`}
          </td>
        </tr>`,
    )
    .join("");

  document.querySelectorAll(".role-change-select").forEach((select) => {
    select.addEventListener("change", async (event) => {
      const userId = event.target.dataset.userId;
      const newRole = event.target.value;
      try {
        event.target.disabled = true;
        await apiFetch(`/api/v1/auth/users/${userId}/role`, {
          method: "PATCH",
          headers: { "Content-Type": "application/json" },
          body: JSON.stringify({ role: newRole }),
        });
        showFeedback(`User #${userId} role changed to ${ROLE_LABELS[newRole]}.`);
        await loadUsers();
      } catch (error) {
        showFeedback(error.message, "error");
        await loadUsers(); // revert UI
      }
    });
  });
}

renderCampaignLinkPanel("");
resetVerification();
resetReport();
renderOverview();
renderCampaigns();
renderTimeline();
renderIncidents();
renderAuditFeed();
renderEvidenceSelector();
renderEvidence();
setActiveView("overview");
setSessionState(Boolean(state.token));

if (state.token) {
  // Re-fetch role on page reload
  apiFetch("/api/v1/auth/me")
    .then((me) => {
      state.role = me.role;
      localStorage.setItem("shadowtrace_role", state.role);
      updateRoleBadge();
      applyRoleVisibility();
    })
    .catch(() => {});

  loadDashboard().catch((error) => {
    clearSession();
    showFeedback(error.message, "error");
  });
}
