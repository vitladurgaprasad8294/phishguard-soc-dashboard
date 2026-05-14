from email import policy
from email.parser import BytesParser
from email.utils import parseaddr
from bs4 import BeautifulSoup
from pathlib import Path
import hashlib
import math
import re


URL_REGEX = re.compile(r"(https?://[^\s<>\"']+|www\.[^\s<>\"']+)", re.IGNORECASE)


def parse_eml_bytes(raw_email_bytes):
    msg = BytesParser(policy=policy.default).parsebytes(raw_email_bytes)

    email_data = {
        "subject": msg.get("subject", ""),
        "from": msg.get("from", ""),
        "to": msg.get("to", ""),
        "reply_to": msg.get("reply-to", ""),
        "return_path": msg.get("return-path", ""),
        "date": msg.get("date", ""),
        "message_id": msg.get("message-id", ""),
        "sender_email": parseaddr(msg.get("from", ""))[1],
        "body": "",
        "urls": [],
        "attachments": [],
        "headers": dict(msg.items())
    }

    body_parts = []
    urls_found = []

    if msg.is_multipart():
        for part in msg.walk():
            content_disposition = part.get_content_disposition()
            content_type = part.get_content_type()

            if content_disposition == "attachment":
                email_data["attachments"].append(extract_attachment_info(part))
                continue

            if content_type in ["text/plain", "text/html"]:
                try:
                    content = part.get_content()
                except Exception:
                    continue

                urls_found.extend(extract_urls(content))

                if content_type == "text/html":
                    body_parts.append(clean_html(content))
                else:
                    body_parts.append(content)
    else:
        try:
            content = msg.get_content()
            urls_found.extend(extract_urls(content))
            if msg.get_content_type() == "text/html":
                email_data["body"] = clean_html(content)
            else:
                email_data["body"] = content
        except Exception:
            email_data["body"] = ""

    if body_parts:
        email_data["body"] = "\n".join(body_parts)

    urls_found.extend(extract_urls(email_data["body"]))
    email_data["urls"] = sorted(list(set(urls_found)))

    if not email_data["message_id"]:
        fallback_id = hashlib.sha256(
            (
                email_data["subject"]
                + email_data["from"]
                + email_data["date"]
                + email_data["body"][:500]
            ).encode(errors="ignore")
        ).hexdigest()
        email_data["message_id"] = fallback_id

    return email_data


def clean_html(html):
    soup = BeautifulSoup(html, "html.parser")
    return soup.get_text(separator=" ", strip=True)


def extract_urls(text):
    if not text:
        return []

    urls = URL_REGEX.findall(text)
    cleaned = []

    for url in urls:
        url = url.strip().rstrip(".,);]</}\"'")
        if url.startswith("www."):
            url = "http://" + url
        cleaned.append(url)

    return cleaned


def calculate_entropy(data):
    if not data:
        return 0.0

    counts = {}
    for byte in data:
        counts[byte] = counts.get(byte, 0) + 1

    entropy = 0.0
    length = len(data)

    for count in counts.values():
        probability = count / length
        entropy -= probability * math.log2(probability)

    return round(entropy, 3)


def extract_attachment_info(part):
    filename = part.get_filename() or "unknown_attachment"
    content_type = part.get_content_type()

    try:
        payload = part.get_payload(decode=True)
    except Exception:
        payload = b""

    if payload is None:
        payload = b""

    extension = Path(filename).suffix.lower()

    return {
        "filename": filename,
        "content_type": content_type,
        "size_bytes": len(payload),
        "sha256": hashlib.sha256(payload).hexdigest(),
        "md5": hashlib.md5(payload).hexdigest(),
        "extension": extension,
        "entropy": calculate_entropy(payload)
    }
