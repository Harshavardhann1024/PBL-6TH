# ShadowTrace — Phase 1 Presentation Guide
## Phishing Investigation & Cryptographic Forensics Platform
### Subjects: Ethical Hacking | Cryptography & Network Security

---

## Slide 1: Title Slide 

**Title:** ShadowTrace — AI-Driven Phishing Investigation & Cryptographic Forensics Platform

**Subtitle:** Phase 1 — System Design, Core Architecture & Prototype

**Subjects:** Ethical Hacking and Cryptography & Network Security

**Team Members:** [Your Names]

**Guide:** [Faculty Name]

**College & Department:** [Fill In]

---

## Slide 2: Problem Statement

### The Problem

- **Phishing attacks** are the #1 cyber threat — responsible for **36% of all data breaches** (Verizon DBIR 2025).
- Organizations lack tools to **simulate, track, and forensically analyze** phishing attacks in a controlled environment.
- Digital evidence from phishing incidents is **easily tampered with** — there is no built-in chain-of-custody mechanism.
- Traditional forensics tools **don't seal evidence cryptographically**, making court admissibility questionable.

### Why It Matters

| Ethical Hacking Perspective | Cryptography Perspective |
|---|---|
| No safe environment to simulate & study phishing tactics | Captured evidence lacks encryption at rest |
| Incident response teams can't reconstruct attack timelines | No integrity verification (hash-based tamper detection) |
| Awareness training lacks realistic, controlled simulations | Reports are unsigned — origin & authenticity unverifiable |

---

## Slide 3: Objectives

1. **Build a controlled phishing simulation platform** for ethical security testing and awareness training.
2. **Implement end-to-end cryptographic evidence protection** using AES-GCM encryption, SHA-256 integrity hashing, and RSA digital signatures.
3. **Create a tamper-proof audit chain** to ensure forensic accountability.
4. **Generate digitally signed incident reports** with verifiable authenticity.
5. **Provide a real-time dashboard** for campaign monitoring, incident reconstruction, and evidence analysis.

---

## Slide 4: Approach / Methodology

### Dual-Subject Approach

```
┌─────────────────────────────────────────────────────────────────┐
│                     ShadowTrace Platform                        │
├────────────────────────────┬────────────────────────────────────┤
│   ETHICAL HACKING SIDE     │     CRYPTOGRAPHY SIDE              │
├────────────────────────────┼────────────────────────────────────┤
│ • Phishing campaign setup  │ • AES-256-GCM evidence encryption  │
│ • Fake landing pages       │ • SHA-256 integrity hashing        │
│ • Credential capture sim   │ • RSA-2048 report signing          │
│ • Attack timeline recon    │ • Hash-chained audit log           │
│ • IP + User-Agent tracking │ • Tamper detection & verification  │
│ • Awareness redirection    │ • Key management system            │
└────────────────────────────┴────────────────────────────────────┘
```

### Development Methodology

1. **Reconnaissance & Research** — Study real phishing kits, MITRE ATT&CK framework
2. **System Design** — FastAPI backend, SQLAlchemy ORM, modular service architecture
3. **Crypto Layer Implementation** — AES-GCM + SHA-256 + RSA signing pipeline
4. **Phishing Simulation Engine** — Campaign lifecycle, event capture, tracking tokens
5. **Forensic Dashboard** — Real-time monitoring, evidence verification, report export

---

## Slide 5: System Architecture

```
┌──────────────────────────────────────────────────────────────────┐
│                        FRONTEND LAYER                            │
│  ┌─────────────────┐    ┌──────────────────────────────┐        │
│  │  Dashboard UI    │    │  Phishing Simulation Page    │        │
│  │  (HTML/JS/CSS)   │    │  (Fake Login + Awareness)    │        │
│  └────────┬─────────┘    └─────────────┬────────────────┘        │
├───────────┼────────────────────────────┼─────────────────────────┤
│           │         API LAYER          │                         │
│  ┌────────▼────────────────────────────▼────────────────┐       │
│  │              FastAPI REST Endpoints                   │       │
│  │   /auth  |  /campaigns  |  /dashboard  |  /health    │       │
│  └────────────────────────┬─────────────────────────────┘       │
├───────────────────────────┼──────────────────────────────────────┤
│                   SERVICE LAYER                                  │
│  ┌──────────────┐ ┌────────────┐ ┌───────────┐ ┌────────────┐  │
│  │Campaign Event│ │ Evidence   │ │ Signing   │ │  Audit     │  │
│  │  Service     │ │ Service    │ │ Service   │ │  Service   │  │
│  │              │ │AES-GCM enc│ │RSA-2048   │ │Hash-chain  │  │
│  │Event capture │ │SHA-256 hash│ │Key mgmt   │ │Tamper det. │  │
│  └──────┬───────┘ └──────┬─────┘ └─────┬─────┘ └─────┬──────┘  │
├─────────┼────────────────┼─────────────┼─────────────┼───────────┤
│         │          DATABASE LAYER       │             │           │
│  ┌──────▼──────────────────▼───────────────▼─────────▼────────┐ │
│  │                    SQLite + SQLAlchemy ORM                  │ │
│  │  users | campaigns | events | evidence | audit_logs        │ │
│  └────────────────────────────────────────────────────────────┘ │
└──────────────────────────────────────────────────────────────────┘
```

---

## Slide 6: Ethical Hacking Components (Deep Dive)

### Phishing Campaign Engine

- **Campaign Lifecycle:** Draft → Active → Paused → Closed
- Each campaign generates a **unique tracking token** (UUID-based)
- **Fake phishing landing page** mimics real login portals
- On submission → captures credentials (simulated) + logs IP, User-Agent, timestamp

### Event Tracking (5 Event Types)

| Event Type | Description |
|---|---|
| `email_sent` | Campaign link dispatched |
| `link_clicked` | Victim opens phishing URL |
| `credentials_submitted` | Victim submits fake form |
| `suspicious_login` | Anomalous access detected |
| `report_opened` | Incident report accessed |

### Security Awareness

- After credential capture → victim is **redirected to an awareness page**
- Educational content explains what happened and how to avoid real phishing

---

## Slide 7: Cryptography Components (Deep Dive)

### 1. Evidence Encryption — AES-256-GCM

```
Plain Evidence → AES-256-GCM Encrypt → Encrypted Payload (stored in DB)
                     ↓
              96-bit random IV + Authentication Tag
```

- **Why AES-GCM?** Provides both confidentiality AND authenticity in one operation (AEAD cipher)
- Evidence is encrypted at rest — even database breach won't expose raw data

### 2. Integrity Verification — SHA-256

```
Evidence Data → SHA-256 → Integrity Hash (stored alongside)
                            ↓
           On verify: recompute hash → compare → MATCH or COMPROMISED
```

- Detects any tampering with stored evidence
- Status transitions: `pending` → `sealed` → `compromised` (if tampered)

### 3. Report Signing — RSA-2048

```
Incident Report → SHA-256 Digest → RSA Private Key Sign → Digital Signature
                                                              ↓
                              Verifier: RSA Public Key → Confirm Authenticity
```

- Auto-generated RSA key pair stored in `.shadowtrace/keys/`
- Reports carry a verifiable signature proving origin and integrity

### 4. Audit Chain — Hash Linkage

```
Log Entry N: hash = SHA-256(action + details + previous_hash)
                                                ↑
Log Entry N-1: hash = SHA-256(...)  ────────────┘
```

- Each audit log entry is **chained** to the previous one
- Breaking any link exposes tampering — blockchain-inspired immutability

---

## Slide 8: Technology Stack

| Component | Technology | Purpose |
|---|---|---|
| Backend Framework | FastAPI (Python) | Async REST API |
| ORM | SQLAlchemy 2.0 | Database modeling & queries |
| Database | SQLite | Lightweight, file-based storage |
| Authentication | JWT (HS256) | Stateless token-based auth |
| Password Security | Passlib (bcrypt) | Secure password hashing |
| Encryption | AES-256-GCM | Evidence encryption at rest |
| Hashing | SHA-256 | Integrity verification |
| Digital Signatures | RSA-2048 | Report authenticity |
| Configuration | Pydantic Settings | Environment-based config |
| Frontend | HTML + JS + CSS | Dashboard & phishing pages |

---

## Slide 9: Database Design

### Entity Relationship

```
┌─────────┐       ┌──────────────────┐       ┌────────────────┐
│  Users  │──1:N──│ PhishingCampaigns │──1:N──│ PhishingEvents │
│         │       │                  │       │                │
│ id      │       │ id               │       │ id             │
│ name    │       │ name             │       │ event_type     │
│ email   │       │ tracking_token   │       │ source_ip      │
│ password│       │ status           │       │ user_agent     │
│ role    │       │ created_by_id FK │       │ event_data     │
└─────────┘       └────────┬─────────┘       └────────────────┘
     │                     │
     │              1:N    │
     │            ┌────────▼─────────┐
     │            │ EvidenceRecords  │
     │            │                  │
     │            │ encrypted_payload│
     │            │ integrity_hash   │
     │            │ signature        │
     │            │ status           │
     │            └──────────────────┘
     │
     └──1:N──┌──────────────┐
             │  AuditLogs   │
             │              │
             │ action       │
             │ resource_type│
             │ previous_hash│
             │ current_hash │
             └──────────────┘
```

---

## Slide 10: Novelty / Innovation

### What Makes ShadowTrace Unique?

| Aspect | Traditional Tools | ShadowTrace |
|---|---|---|
| Phishing + Forensics | Separate tools | **Unified platform** |
| Evidence Storage | Plain text | **AES-256-GCM encrypted** |
| Tamper Detection | Manual checking | **Automated SHA-256 verification** |
| Report Authenticity | Unsigned PDFs | **RSA-2048 digitally signed** |
| Audit Trail | Simple logs | **Hash-chained audit (blockchain-inspired)** |
| Awareness Training | Generic videos | **Live simulation + educational redirect** |

### Key Innovations

1. **Crypto-Sealed Evidence Pipeline** — First-of-its-kind integration of AES-GCM + SHA-256 + RSA in a phishing forensics context
2. **Hash-Chained Audit Trail** — Blockchain-inspired immutable logging without the overhead of a blockchain
3. **Dual-Purpose Platform** — Simultaneously serves ethical hacking (offensive simulation) and cryptographic security (defensive forensics)
4. **Awareness-by-Experience** — Victims learn through controlled exposure, not passive training

---

## Slide 11: Phase 1 Deliverables / Current Status

| Component | Status |
|---|---|
| System Architecture & Design | ✅ Complete |
| Database Schema (5 tables) | ✅ Complete |
| JWT Authentication (3 roles) | ✅ Complete |
| Phishing Campaign Engine | ✅ Complete |
| Phishing Landing Page + Awareness | ✅ Complete |
| AES-GCM Evidence Encryption | ✅ Complete |
| SHA-256 Integrity Verification | ✅ Complete |
| RSA-2048 Report Signing | ✅ Complete |
| Hash-Chained Audit System | ✅ Complete |
| Dashboard UI | ✅ Complete |
| Demo Data Seeder | ✅ Complete |
| Unit Tests | ✅ Complete |

---

## Slide 12: Demo Flow (Live Demonstration)

1. **Login** → Sign in as `admin@gmail.com`
2. **Create Campaign** → Set up a new phishing campaign
3. **Open Phishing Link** → Simulate victim clicking the link
4. **Submit Credentials** → Show credential capture + awareness redirect
5. **Inspect Dashboard** → View incidents, timeline, evidence
6. **Verify Evidence** → Run integrity check (SHA-256)
7. **Generate Report** → Download RSA-signed incident report
8. **Tamper Demo** → Manually modify a hash in DB → re-verify → show "COMPROMISED" detection

---

## Slide 13: Future Scope (Phase 2)

- Email integration for automated phishing delivery
- Multi-vector attacks (SMS phishing / smishing)
- ML-based phishing URL detection
- Advanced analytics and threat scoring
- Role-based access control hardening
- Cloud deployment with HTTPS

---

## Slide 14: References

1. Verizon Data Breach Investigations Report (DBIR) — 2025
2. MITRE ATT&CK Framework — Phishing Techniques (T1566)
3. NIST SP 800-38D — Recommendation for GCM Mode of Operation
4. RFC 7519 — JSON Web Token (JWT)
5. OWASP Phishing Prevention Guidelines
6. Python Cryptography Library Documentation
7. FastAPI Official Documentation

---

## Slide 15: Thank You

**ShadowTrace** — Where Ethical Hacking Meets Cryptographic Forensics

**Questions?**

---
