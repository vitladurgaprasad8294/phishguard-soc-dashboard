# Resume Points for PhishGuard

## Project Title

PhishGuard: Real-Time Email Security Monitoring and Phishing Detection SOC Dashboard

## Short Description

Developed a real-time email security monitoring dashboard that connects to an authorized mailbox, analyzes incoming emails, extracts forensic artifacts, classifies emails into phishing/spam/marketing/suspicious/safe categories, and supports SOC-style investigation.

## Resume Bullet Points

- Built a real-time email security monitoring dashboard using Python, Streamlit, SQLite, and IMAP over SSL.
- Implemented phishing, spam, marketing, suspicious, and safe email classification using rule-based scoring and lightweight ML logic.
- Developed forensic email parsing modules to extract headers, sender metadata, URLs, attachments, raw evidence, and message body artifacts.
- Added IOC extraction for URLs, domains, IP addresses, email addresses, MD5 hashes, and SHA256 hashes.
- Implemented static attachment analysis to detect risky extensions, double extensions, macro-enabled files, compressed archives, entropy, and file hashes.
- Added SPF, DKIM, and DMARC authentication header parsing to identify potential spoofing indicators.
- Integrated MITRE ATT&CK mapping for phishing links, suspicious attachments, and user execution risks.
- Created analyst workflow features including review status, final verdict, analyst notes, timeline, quarantine marking, and CSV exports.
- Added optional VirusTotal API enrichment for suspicious URLs, domains, IP addresses, and file hashes.
- Designed a clean SOC-style Streamlit dashboard with command center, intake, investigation, and settings pages.

## LinkedIn Project Description

PhishGuard is a real-time email security monitoring and phishing detection SOC dashboard. It connects to an authorized mailbox, analyzes incoming emails, extracts IOCs, performs static attachment analysis, parses authentication headers, maps findings to MITRE ATT&CK, and provides analyst review workflow with risk scoring and investigation views.
