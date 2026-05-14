import imaplib
import os
from datetime import datetime

from modules.config import get_config, is_enabled
from modules.email_parser import parse_eml_bytes
from modules.classifier import classify_email
from modules.database import save_email


def get_imap_config():
    return {
        "server": get_config("IMAP_SERVER", "imap.gmail.com").strip(),
        "port": int(get_config("IMAP_PORT", "993")),
        "user": get_config("IMAP_USER", "").strip(),
        "password": get_config("IMAP_PASSWORD", "").strip(),
        "folder": get_config("IMAP_FOLDER", "INBOX").strip(),
        "apply_gmail_labels": is_enabled("APPLY_GMAIL_LABELS", "false")
    }


def is_mailbox_configured():
    config = get_imap_config()

    if not config["server"] or not config["user"] or not config["password"]:
        return False

    blocked_values = [
        "your_app_password",
        "PASTE_YOUR_GMAIL_APP_PASSWORD_HERE",
        "YOUR_16_CHARACTER_APP_PASSWORD",
        "YOUR_16_CHARACTER_GMAIL_APP_PASSWORD",
        "YOUR_GMAIL_APP_PASSWORD"
    ]

    if config["password"] in blocked_values:
        return False

    return True


def ensure_label(mail, label):
    try:
        mail.create(label)
    except Exception:
        pass


def apply_gmail_label(mail, uid, category):
    """
    Basic IMAP label support for Gmail-like mailboxes.
    If it fails, the dashboard still works.
    """
    label = f"PhishGuard/{category}"
    ensure_label(mail, "PhishGuard")
    ensure_label(mail, label)

    try:
        status, _ = mail.uid("COPY", uid, label)
        return status == "OK"
    except Exception:
        return False


def fetch_unread_emails(mark_as_read=True, max_emails=25):
    config = get_imap_config()

    if not is_mailbox_configured():
        raise ValueError("Mailbox is not configured. Add IMAP settings using .env locally or Streamlit secrets in deployment.")

    results = []

    mail = imaplib.IMAP4_SSL(config["server"], config["port"])
    mail.login(config["user"], config["password"])
    mail.select(config["folder"])

    status, messages = mail.uid("search", None, "UNSEEN")

    if status != "OK":
        mail.logout()
        return results

    email_uids = messages[0].split()

    if max_emails:
        email_uids = email_uids[-max_emails:]

    os.makedirs("live_emails", exist_ok=True)

    for uid in email_uids:
        status, msg_data = mail.uid("fetch", uid, "(BODY.PEEK[])")

        if status != "OK":
            continue

        raw_email = None

        for response_part in msg_data:
            if isinstance(response_part, tuple):
                raw_email = response_part[1]

        if not raw_email:
            continue

        parsed_email = parse_eml_bytes(raw_email)
        classification = classify_email(parsed_email)

        timestamp = datetime.now().strftime("%Y%m%d_%H%M%S")
        safe_id = uid.decode(errors="ignore")
        evidence_filename = f"live_emails/live_email_{safe_id}_{timestamp}.eml"

        with open(evidence_filename, "wb") as f:
            f.write(raw_email)

        save_result = save_email(
            email_data=parsed_email,
            classification=classification,
            evidence_file=evidence_filename,
            source="Live Mailbox"
        )

        label_applied = False

        if config["apply_gmail_labels"]:
            label_applied = apply_gmail_label(mail, uid, classification.get("category", "Unknown"))

        results.append({
            "email_id": save_result["email_id"],
            "inserted": save_result["inserted"],
            "subject": parsed_email.get("subject", ""),
            "category": classification.get("category", ""),
            "risk_score": classification.get("risk_score", 0),
            "gmail_label_applied": label_applied
        })

        if mark_as_read:
            mail.uid("store", uid, "+FLAGS", "\\Seen")

    mail.logout()
    return results
