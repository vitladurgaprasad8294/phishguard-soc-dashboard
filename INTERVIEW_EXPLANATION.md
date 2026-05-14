
## Simple Explanation

PhishGuard is a real-time email security monitoring dashboard. It connects to a mailbox using IMAP, fetches unread emails, extracts forensic artifacts, analyzes risk indicators, and classifies each email as phishing, spam, marketing, suspicious, or safe.

## Why I Built It

Phishing emails are one of the most common attack vectors. I wanted to build a practical SOC-style dashboard that supports real-time monitoring, email forensics, IOC extraction, risk scoring, and analyst review.

## How It Works

1. The system fetches emails through IMAP or accepts uploaded `.eml` files.
2. The parser extracts headers, sender information, body content, URLs, and attachments.
3. The classifier checks phishing keywords, spam patterns, trusted/blocked domains, suspicious URLs, attachment risks, and authentication headers.
4. IOCs are extracted and stored in SQLite.
5. The dashboard shows category counts, case details, risk explanation, MITRE mapping, and investigation timeline.
6. Analysts can mark cases reviewed, add notes, set final verdict, and export data.

## Key Cybersecurity Concepts Used

- Email header analysis
- Phishing detection
- IOC extraction
- Static malware attachment analysis
- SPF/DKIM/DMARC parsing
- MITRE ATT&CK mapping
- Threat intelligence enrichment
- Digital evidence preservation
- SOC triage workflow

## Limitations

- It performs static analysis only.
- It does not execute attachments.
- VirusTotal enrichment requires an API key.
- Gmail automation requires App Password and IMAP access.
- ML classifier is lightweight and suitable for demonstration, not production-grade detection.
