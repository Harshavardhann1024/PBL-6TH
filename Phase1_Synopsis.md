# ShadowTrace — Phase 1 Synopsis
## Phishing Investigation & Cryptographic Forensics Platform
### Subjects: Ethical Hacking | Cryptography & Network Security

---

## 1. INTRODUCTION

**ShadowTrace** is a web-based cybersecurity platform that combines **ethical hacking** (controlled phishing simulation) with **applied cryptography** (evidence encryption, integrity verification, and digital signing). It enables security teams and researchers to conduct phishing campaigns in a controlled environment while ensuring all captured evidence follows a cryptographically sealed forensic pipeline. The platform addresses the growing need for organizations to simulate real-world phishing threats, understand attack patterns, and maintain tamper-proof digital evidence chains — bridging the gap between offensive security testing and defensive forensic analysis.

---

## 2. PROBLEM STATEMENT

Phishing attacks continue to be the most prevalent and effective cyber threat vector, accounting for over one-third of all data breaches globally. Despite this, organizations face two critical gaps:

**From an Ethical Hacking Perspective:**
- There are limited platforms that allow controlled phishing simulations with complete attack lifecycle tracking.
- Security teams cannot reconstruct phishing attack timelines with forensic-grade evidence.
- Employee awareness training relies on passive methods (presentations, videos) rather than experiential learning through safe, simulated attacks.

**From a Cryptography Perspective:**
- Captured digital evidence from phishing investigations is stored in plaintext, making it vulnerable to unauthorized access.
- There is no mechanism to verify if stored evidence has been tampered with after collection.
- Incident reports lack digital signatures, making their origin and authenticity unverifiable.
- Audit trails use simple sequential logs with no cryptographic linkage, making them easy to alter without detection.

**ShadowTrace addresses both gaps** by creating a unified platform where phishing simulation (ethical hacking) meets cryptographic evidence protection (cryptography), ensuring that every piece of evidence captured during a simulated attack is encrypted, hashed, signed, and audit-chained.

---

## 3. OBJECTIVES

1. To design and develop a controlled phishing simulation engine that supports full campaign lifecycle management (creation, tracking, event capture, and awareness redirection).
2. To implement AES-256-GCM authenticated encryption for securing captured evidence at rest.
3. To provide SHA-256 integrity verification for detecting any unauthorized modification of stored evidence.
4. To enable RSA-2048 digital signing of incident reports to guarantee authenticity and non-repudiation.
5. To build a hash-chained audit trail (blockchain-inspired) ensuring every system action is cryptographically linked and immutable.
6. To create a real-time operational dashboard for campaign monitoring, incident investigation, and evidence verification.

---

## 4. METHODOLOGY / APPROACH

### 4.1 System Design Approach

The platform follows a **layered architecture** with clear separation of concerns:

- **Presentation Layer** — HTML/CSS/JavaScript dashboard and phishing simulation pages
- **API Layer** — FastAPI REST endpoints for authentication, campaigns, dashboard, and health monitoring
- **Service Layer** — Modular business logic for campaign events, evidence processing, report generation, audit logging, and cryptographic operations
- **Data Layer** — SQLAlchemy ORM with SQLite database containing five normalized tables

### 4.2 Ethical Hacking Workflow

1. **Campaign Creation** — Administrator defines a phishing campaign with target details
2. **Tracking Token Generation** — System generates a unique UUID-based tracking token per campaign
3. **Phishing Page Deployment** — A realistic fake login page is served at the tracking URL
4. **Event Capture** — System records five event types: email_sent, link_clicked, credentials_submitted, suspicious_login, report_opened — capturing IP address, User-Agent, and timestamp
5. **Awareness Redirection** — After credential submission, victim is redirected to an educational awareness page explaining the simulation

### 4.3 Cryptographic Pipeline

```
[Evidence Captured] 
    → AES-256-GCM Encryption (96-bit IV + Auth Tag)
        → SHA-256 Integrity Hash Computed & Stored
            → RSA-2048 Signature on Incident Report
                → Hash-Chained Audit Log Entry
```

| Stage | Algorithm | Purpose |
|---|---|---|
| Encryption | AES-256-GCM | Confidentiality + authentication (AEAD) |
| Integrity | SHA-256 | Tamper detection via hash comparison |
| Signing | RSA-2048 | Report authenticity and non-repudiation |
| Audit Chain | SHA-256 (chained) | Immutable action trail |

---

## 5. SYSTEM ARCHITECTURE

```
┌─────────────────────────────────────────────────────────────┐
│                    CLIENT LAYER                              │
│   Dashboard UI  ──────────────  Phishing Landing Page       │
└──────────┬──────────────────────────────┬────────────────────┘
           │                              │
┌──────────▼──────────────────────────────▼────────────────────┐
│                    FastAPI REST API                           │
│   /api/v1/auth  │  /api/v1/campaigns  │  /api/v1/dashboard  │
└──────────┬──────────────────────────────┬────────────────────┘
           │                              │
┌──────────▼──────────────────────────────▼────────────────────┐
│                    SERVICE LAYER                              │
│  Campaign Events │ Evidence (AES+SHA) │ Signing (RSA) │ Audit│
└──────────┬──────────────────────────────┬────────────────────┘
           │                              │
┌──────────▼──────────────────────────────▼────────────────────┐
│          SQLite Database (SQLAlchemy ORM)                     │
│  users │ phishing_campaigns │ phishing_events │ evidence │ audit│
└──────────────────────────────────────────────────────────────┘
```

---

## 6. TECHNOLOGY STACK

| Component | Technology | Version |
|---|---|---|
| Backend Framework | FastAPI (Python) | 0.116.1 |
| ORM | SQLAlchemy | 2.0.43 |
| Database | SQLite | 3.x |
| Authentication | JWT (python-jose) | HS256 |
| Password Hashing | Passlib (bcrypt) | 1.7.4 |
| Encryption | AES-256-GCM (cryptography lib) | 45.0.7 |
| Hashing | SHA-256 (hashlib) | Built-in |
| Digital Signatures | RSA-2048 (cryptography lib) | 45.0.7 |
| Configuration | Pydantic Settings | 2.10.1 |
| Frontend | HTML + Vanilla JS + CSS | — |
| Server | Uvicorn (ASGI) | 0.35.0 |

---

## 7. DATABASE DESIGN

### Tables

| Table | Key Columns | Purpose |
|---|---|---|
| `users` | id, full_name, email, hashed_password, role | JWT-authenticated user accounts (admin/analyst/employee) |
| `phishing_campaigns` | id, name, tracking_token, status, created_by_id | Phishing campaign management with UUID tracking |
| `phishing_events` | id, campaign_id, event_type, source_ip, user_agent, event_data | Granular event capture for attack reconstruction |
| `evidence_records` | id, campaign_id, encrypted_payload, integrity_hash, signature, status | AES-encrypted evidence with SHA-256 hash + RSA signature |
| `audit_logs` | id, actor_user_id, action, resource_type, previous_hash, current_hash | Hash-chained immutable audit trail |

---

## 8. NOVELTY / INNOVATION

### 8.1 Unified Offensive + Defensive Platform
Unlike existing tools that handle either phishing simulation (GoPhish, King Phisher) or forensic analysis (Autopsy, FTK) separately, ShadowTrace **unifies both** into a single platform — capturing evidence during simulation and immediately sealing it cryptographically.

### 8.2 Crypto-Sealed Evidence Pipeline
A novel four-stage cryptographic pipeline:
1. **AES-256-GCM** encrypts evidence at rest (ensuring confidentiality + authenticity)
2. **SHA-256** hashes verify integrity (detecting any post-capture tampering)
3. **RSA-2048** signatures guarantee report authenticity (non-repudiation)
4. **Hash-chained audit** ensures chronological immutability (blockchain-inspired)

### 8.3 Awareness-by-Experience
Instead of passive security training, ShadowTrace provides **experiential learning** — users who fall for the simulated phishing attack are immediately shown what happened and how to protect themselves.

### 8.4 Tamper-Evident Architecture
The system can **actively detect evidence tampering** — modifying any record in the database is automatically caught through hash verification, with status transitioning from "sealed" to "compromised."

---

## 9. PHASE 1 DELIVERABLES

| # | Deliverable | Status |
|---|---|---|
| 1 | System Architecture & Design | ✅ Complete |
| 2 | Database Schema (5 tables, normalized) | ✅ Complete |
| 3 | JWT Authentication System (3 roles) | ✅ Complete |
| 4 | Phishing Campaign Engine (CRUD + lifecycle) | ✅ Complete |
| 5 | Phishing Landing Page + Awareness Redirect | ✅ Complete |
| 6 | AES-256-GCM Evidence Encryption Service | ✅ Complete |
| 7 | SHA-256 Integrity Verification Service | ✅ Complete |
| 8 | RSA-2048 Report Signing Service | ✅ Complete |
| 9 | Hash-Chained Audit System | ✅ Complete |
| 10 | Operational Dashboard UI | ✅ Complete |
| 11 | Demo Data Seeder & Reset Scripts | ✅ Complete |
| 12 | Automated Test Suite | ✅ Complete |

---

## 10. FUTURE SCOPE (Phase 2)

- Automated email delivery integration for phishing campaigns
- Multi-vector attack simulation (SMS phishing / vishing)
- Machine learning-based phishing URL detection
- Advanced threat analytics and risk scoring
- Cloud deployment with TLS/HTTPS
- Exportable forensic reports in PDF format

---

## 11. REFERENCES

1. Verizon, "2025 Data Breach Investigations Report (DBIR)," 2025.
2. MITRE Corporation, "ATT&CK Framework — Phishing (T1566)," https://attack.mitre.org.
3. NIST, "SP 800-38D: Recommendation for Block Cipher Modes of Operation: GCM," 2007.
4. M. Jones et al., "RFC 7519: JSON Web Token (JWT)," IETF, 2015.
5. OWASP Foundation, "Phishing Prevention Cheat Sheet," https://cheatsheetseries.owasp.org.
6. Python Cryptography Authority, "cryptography Library Documentation," https://cryptography.io.
7. S. Ramírez, "FastAPI Documentation," https://fastapi.tiangolo.com.
8. W. Stallings, "Cryptography and Network Security: Principles and Practice," 8th Edition, Pearson, 2022.

---
