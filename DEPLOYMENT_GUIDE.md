# PhishGuard GitHub and Deployment Guide

## 1. Prepare Local Project

Run:

```powershell
cd "C:\Users\vitla\OneDrive\Desktop\phishguard"
.\venv\Scripts\python.exe -m streamlit run app.py
```

Make sure the app works locally.

## 2. Check Sensitive Files

These must NOT be uploaded to GitHub:

```text
.env
venv/
database/*.db
live_emails/
quarantine/
.streamlit/secrets.toml
```

The `.gitignore` file already blocks them.

## 3. Create GitHub Repository

Create a new empty repository on GitHub named:

```text
phishguard-soc-dashboard
```

Do not add README from GitHub because this project already has one.

## 4. Push Local Project to GitHub

Option A: Use the helper script:

```powershell
cd "C:\Users\vitla\OneDrive\Desktop\phishguard"
.\push_to_github.ps1
```

Option B: Manual commands:

```powershell
cd "C:\Users\vitla\OneDrive\Desktop\phishguard"
git init
git add .
git commit -m "Initial commit: PhishGuard SOC dashboard"
git branch -M main
git remote add origin https://github.com/YOUR_USERNAME/phishguard-soc-dashboard.git
git push -u origin main
```

## 5. Deploy on Streamlit Community Cloud

1. Open Streamlit Community Cloud.
2. Sign in with GitHub.
3. Click New app.
4. Select your repository.
5. Branch: `main`
6. Main file path: `app.py`
7. Add secrets from `.streamlit/secrets.toml.example`.
8. Deploy.

## 6. Streamlit Secrets Example

Paste this into Streamlit Cloud app secrets:

```toml
IMAP_SERVER = "imap.gmail.com"
IMAP_PORT = "993"
IMAP_USER = "your_email@gmail.com"
IMAP_PASSWORD = "your_gmail_app_password"
IMAP_FOLDER = "INBOX"

VIRUSTOTAL_API_KEY = ""
APPLY_GMAIL_LABELS = "false"

APP_LOGIN_ENABLED = "true"
APP_USERNAME = "admin"
APP_PASSWORD = "change_this_password"
```

## 7. Important Security Notes

- Never commit `.env`.
- Never commit Gmail password or App Password.
- Never upload real emails to public GitHub.
- Keep Gmail label automation disabled unless required.
- Use a lab mailbox for demo deployment.
