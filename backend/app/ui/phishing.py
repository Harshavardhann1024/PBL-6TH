from html import escape

from fastapi import APIRouter, Depends, Form, HTTPException, Request, status
from fastapi.responses import HTMLResponse, RedirectResponse
from sqlalchemy.orm import Session

from app.api.deps import get_db
from app.models.campaign import PhishingEventType
from app.services.campaign_events import get_campaign_by_tracking_token, record_campaign_event

router = APIRouter(include_in_schema=False)


def _client_ip(request: Request) -> str | None:
    return request.client.host if request.client else None


def _user_agent(request: Request) -> str | None:
    return request.headers.get("user-agent")


def _phishing_page_html(tracking_token: str, campaign_name: str, target_email: str | None) -> str:
    safe_campaign_name = escape(campaign_name)
    safe_target_email = escape(target_email or "")
    email_value = f'value="{safe_target_email}"' if safe_target_email else ""
    return f"""<!doctype html>
<html lang="en">
  <head>
    <meta charset="UTF-8" />
    <meta name="viewport" content="width=device-width, initial-scale=1.0" />
    <title>{safe_campaign_name} | Benefits Access</title>
    <link rel="stylesheet" href="/static/styles/phish.css" />
  </head>
  <body>
    <main class="page-shell">
      <section class="hero-card" style="padding: 2rem; box-sizing: border-box;">
        <div class="hero-layout-wrapper" style="display: flex; gap: 3rem; flex-wrap: wrap; align-items: flex-start;">
          <div class="hero-copy" style="flex: 1; min-width: 300px;">
            <p class="eyebrow">Employee Benefits Portal</p>
            <h1 style="line-height: 1.2; margin-bottom: 1rem;">Annual benefit confirmation required.</h1>
            <p class="hero-description">
              Your benefits selection is pending review. Sign in with your work email to confirm your
              health and reimbursement preferences before the cycle closes.
            </p>
            <ul class="bullet-list">
              <li>Benefits window closes tonight</li>
              <li>Unconfirmed profiles may lose pending approvals</li>
              <li>HR review status updates within one business day</li>
            </ul>
          </div>

          <form class="login-panel" method="post" action="/phish/{escape(tracking_token)}/submit" style="flex: 0 1 400px; min-width: 300px;">
            <div class="panel-top">
              <p class="eyebrow">Secure Sign-In</p>
              <h2>Benefits access</h2>
            </div>
            <label>
              <span>Work email</span>
              <input type="email" name="email" placeholder="name@company.com" {email_value} required />
            </label>
            <label>
              <span>Password</span>
              <input type="password" name="password" placeholder="Enter your password" required />
            </label>
            <button type="submit">Review my benefits</button>
            <p class="helper-text">Protected by enterprise sign-on and activity monitoring.</p>
          </form>
        </div>
      </section>
    </main>
  </body>
</html>"""


def _awareness_page_html(campaign_name: str) -> str:
    safe_campaign_name = escape(campaign_name)
    return f"""<!doctype html>
<html lang="en">
  <head>
    <meta charset="UTF-8" />
    <meta name="viewport" content="width=device-width, initial-scale=1.0" />
    <title>Security Awareness Notice</title>
    <link rel="stylesheet" href="/static/styles/phish.css" />
  </head>
  <body>
    <main class="page-shell">
      <section class="hero-card result-card" style="padding: 2rem; box-sizing: border-box;">
        <div class="hero-layout-wrapper" style="display: flex; justify-content: center;">
          <div class="hero-copy hero-copy-full" style="max-width: 800px; text-align: center;">
            <p class="eyebrow">Simulation Complete</p>
            <h1>This was a controlled phishing exercise.</h1>
            <p class="hero-description">
              The <strong>{safe_campaign_name}</strong> sign-in screen was part of a security awareness
              simulation. No real credentials were stored, and the event has been recorded as forensic
              evidence inside ShadowTrace.
            </p>
            <ul class="bullet-list">
              <li>Check the sender and destination URL before signing in</li>
              <li>Report unexpected urgency around HR, payroll, or account changes</li>
              <li>Use the real company portal for any sensitive sign-in</li>
            </ul>
            <div class="action-area">
              <a class="return-link" href="/">Return to ShadowTrace dashboard</a>
            </div>
          </div>
        </div>
      </section>
    </main>
  </body>
</html>"""


@router.get("/phish/{tracking_token}", response_class=HTMLResponse)
def open_phishing_page(
    tracking_token: str,
    request: Request,
    db: Session = Depends(get_db),
) -> HTMLResponse:
    campaign = get_campaign_by_tracking_token(db, tracking_token)
    if campaign is None:
        raise HTTPException(status_code=status.HTTP_404_NOT_FOUND, detail="Campaign not found")

    record_campaign_event(
        db=db,
        campaign=campaign,
        event_type=PhishingEventType.link_clicked,
        source_ip=_client_ip(request),
        user_agent=_user_agent(request),
        event_data={"page": "benefits-login", "result": "opened"},
    )
    return HTMLResponse(_phishing_page_html(tracking_token, campaign.name, campaign.target_email))


@router.post("/phish/{tracking_token}/submit")
def submit_phishing_credentials(
    tracking_token: str,
    request: Request,
    email: str = Form(...),
    password: str = Form(...),
    db: Session = Depends(get_db),
) -> RedirectResponse:
    campaign = get_campaign_by_tracking_token(db, tracking_token)
    if campaign is None:
        raise HTTPException(status_code=status.HTTP_404_NOT_FOUND, detail="Campaign not found")

    record_campaign_event(
        db=db,
        campaign=campaign,
        event_type=PhishingEventType.credentials_submitted,
        source_ip=_client_ip(request),
        user_agent=_user_agent(request),
        event_data={
            "page": "benefits-login",
            "captured_username": email,
            "password_length": len(password),
            "submission_result": "credentials_entered",
        },
    )
    return RedirectResponse(
        url=f"/phish/{tracking_token}/awareness",
        status_code=status.HTTP_303_SEE_OTHER,
    )


@router.get("/phish/{tracking_token}/awareness", response_class=HTMLResponse)
def phishing_awareness_page(
    tracking_token: str,
    request: Request,
    db: Session = Depends(get_db),
) -> HTMLResponse:
    campaign = get_campaign_by_tracking_token(db, tracking_token)
    if campaign is None:
        raise HTTPException(status_code=status.HTTP_404_NOT_FOUND, detail="Campaign not found")

    record_campaign_event(
        db=db,
        campaign=campaign,
        event_type=PhishingEventType.report_opened,
        source_ip=_client_ip(request),
        user_agent=_user_agent(request),
        event_data={"page": "awareness-notice", "result": "training-shown"},
    )
    return HTMLResponse(_awareness_page_html(campaign.name))
