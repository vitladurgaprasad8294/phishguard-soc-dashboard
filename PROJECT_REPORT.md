# PhishGuard Project Report

## Title

PhishGuard: Real-Time Email Security Monitoring and Phishing Detection SOC Dashboard

## Objective

The objective of this project is to develop a real-time email security monitoring platform that can connect to an authorized mailbox, analyze incoming emails, classify them into security categories, extract indicators of compromise, and support analyst investigation.

## Problem Statement

Phishing, spam, and malicious email attachments are common attack vectors. Manual email investigation is time-consuming and error-prone. A dashboard-based system can help detect suspicious emails, preserve evidence, classify threats, and support digital forensic analysis.

## Methodology

The system follows this workflow:

1. Fetch email from live mailbox or upload `.eml` file.
2. Parse metadata, headers, body, URLs, and attachments.
3. Extract IOCs such as URLs, domains, IP addresses, email addresses, and file hashes.
4. Analyze sender mismatch, Reply-To mismatch, URLs, attachment types, and authentication headers.
5. Apply rule-based risk scoring and lightweight ML classification.
6. Store results in SQLite.
7. Display results in a Streamlit SOC dashboard.
8. Allow analyst review, notes, final verdict, and quarantine marking.

## Modules

### Email Parser

Extracts subject, sender, recipient, date, Message-ID, body, URLs, attachments, and raw headers.

### Classifier

Classifies email as phishing, spam, marketing, suspicious, or safe.

### IOC Extractor

Extracts URLs, domains, IP addresses, email addresses, MD5 hashes, and SHA256 hashes.

### Attachment Analyzer

Performs static attachment analysis using filename, extension, double extensions, entropy, and hashes.

### Authentication Analyzer

Parses SPF, DKIM, and DMARC results from email headers.

### MITRE Mapper

Maps phishing indicators to MITRE ATT&CK techniques such as phishing link, phishing attachment, and user execution.

### Threat Intelligence

Optionally enriches IOCs using VirusTotal API.

### SOC Dashboard

Provides command center, intake, investigation, and settings pages.

## Technologies Used

- Python
- Streamlit
- SQLite
- IMAP over SSL
- Pandas
- BeautifulSoup
- Requests
- VirusTotal API
- Gmail App Password / IMAP

## Outcome

The project successfully provides a real-time email security dashboard with automated classification, evidence storage, IOC extraction, risk scoring, threat intelligence enrichment, and investigation workflow.

## Resume Summary

Developed a real-time email security monitoring and phishing detection SOC dashboard using Python, Streamlit, SQLite, IMAP, IOC extraction, attachment analysis, MITRE ATT&CK mapping, and optional VirusTotal threat intelligence.
