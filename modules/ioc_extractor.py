import re


IP_REGEX = re.compile(r"\b(?:\d{1,3}\.){3}\d{1,3}\b")
EMAIL_REGEX = re.compile(r"\b[A-Za-z0-9._%+-]+@[A-Za-z0-9.-]+\.[A-Za-z]{2,}\b")
HASH_REGEX = re.compile(r"\b[a-fA-F0-9]{32}\b|\b[a-fA-F0-9]{64}\b")


def extract_iocs(email_data, url_results=None, attachment_results=None):
    url_results = url_results or []
    attachment_results = attachment_results or []

    body = email_data.get("body", "") or ""
    headers = email_data.get("headers", {}) or {}
    all_text = body + " " + " ".join(str(v) for v in headers.values())

    iocs = []

    for url_item in url_results:
        url = url_item.get("url", "")
        domain = url_item.get("domain", "")

        if url:
            iocs.append({"value": url, "type": "URL", "severity": url_item.get("risk_level", "Low"), "source": "URL Analysis"})

        if domain:
            iocs.append({"value": domain, "type": "Domain", "severity": url_item.get("risk_level", "Low"), "source": "URL Analysis"})

    for ip in IP_REGEX.findall(all_text):
        if is_valid_ipv4(ip):
            iocs.append({"value": ip, "type": "IP Address", "severity": "Medium", "source": "Email Body/Header"})

    for email in EMAIL_REGEX.findall(all_text):
        iocs.append({"value": email, "type": "Email Address", "severity": "Low", "source": "Email Body/Header"})

    for attachment in attachment_results:
        if attachment.get("sha256"):
            iocs.append({"value": attachment["sha256"], "type": "SHA256", "severity": attachment.get("risk_level", "Low"), "source": "Attachment Hash"})
        if attachment.get("md5"):
            iocs.append({"value": attachment["md5"], "type": "MD5", "severity": attachment.get("risk_level", "Low"), "source": "Attachment Hash"})

    for hash_value in HASH_REGEX.findall(body):
        iocs.append({"value": hash_value, "type": "Hash", "severity": "Medium", "source": "Email Body"})

    return deduplicate_iocs(iocs)


def is_valid_ipv4(ip):
    try:
        parts = ip.split(".")
        return len(parts) == 4 and all(0 <= int(part) <= 255 for part in parts)
    except Exception:
        return False


def deduplicate_iocs(iocs):
    seen = set()
    unique = []

    for ioc in iocs:
        key = (ioc.get("value", ""), ioc.get("type", ""))
        if key not in seen and ioc.get("value"):
            seen.add(key)
            unique.append(ioc)

    return unique
