# PhishGuard SOC Dashboard

PhishGuard is a real-time email security monitoring and phishing detection dashboard built with Python, Streamlit, SQLite, IMAP, and cybersecurity rule-based analysis.

It connects to an authorized mailbox, fetches unread emails, extracts forensic artifacts, classifies messages, and provides a SOC-style investigation workflow.

## Features

- Real-time Gmail/IMAP mailbox monitoring
- Manual `.eml` email upload
- Phishing, spam, marketing, suspicious, and safe classification
- Rule-based risk scoring
- Lightweight ML-assisted classification
- IOC extraction: URLs, domains, IPs, email addresses, MD5, SHA256
- Static attachment analysis
- SPF/DKIM/DMARC header parsing
- MITRE ATT&CK mapping
- Explainable risk score
- Trusted and blocked domain rules
- Analyst review workflow
- Analyst notes and final verdict
- Local quarantine status
- Investigation timeline
- Optional VirusTotal enrichment
- Optional Gmail label automation
- CSV exports

## Project Architecture

```text
Mailbox / .eml Upload
        |
        v
Email Parser
        |
        v
Header + URL + Attachment + IOC Analysis
        |
        v
Rule-Based + ML Classification
        |
        v
SQLite Database
        |
        v
Streamlit SOC Dashboard
```

## Local Setup

```powershell
cd "C:\Users\vitla\OneDrive\Desktop\phishguard"
.\venv\Scripts\python.exe -m streamlit run app.py
```

## Required Environment Variables

Create a local `.env` file:

```env
IMAP_SERVER=imap.gmail.com
IMAP_PORT=993
IMAP_USER=your_email@gmail.com
IMAP_PASSWORD=your_gmail_app_password
IMAP_FOLDER=INBOX

VIRUSTOTAL_API_KEY=
APPLY_GMAIL_LABELS=false

APP_LOGIN_ENABLED=false
APP_USERNAME=admin
APP_PASSWORD=change_this_password
```

Do not commit `.env`.

## Deployment

Deploy with Streamlit Community Cloud:

1. Push this repository to GitHub.
2. Open Streamlit Community Cloud.
3. Create a new app.
4. Select this repository.
5. Set main file path to `app.py`.
6. Add secrets in the app settings.
7. Deploy.

Use `.streamlit/secrets.toml.example` as a template.

## Safety Notice

PhishGuard performs static analysis only. Do not execute suspicious attachments or click suspicious links.
