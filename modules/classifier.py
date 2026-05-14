from urllib.parse import urlparse
from email.utils import parseaddr
from modules.ioc_extractor import extract_iocs
from modules.rules_manager import get_trusted_domains, get_blocked_domains, is_domain_or_parent_match
from modules.auth_analyzer import analyze_authentication
from modules.ml_classifier import classify_with_ml
from modules.mitre_mapper import map_to_mitre
import re
import json


PHISHING_KEYWORDS = [
    "verify", "account locked", "password expired", "login now",
    "urgent", "suspended", "confirm your account", "security alert",
    "unusual activity", "click here", "bank account", "limited time",
    "update payment", "reset password", "confirm identity",
    "your account will be closed", "validate your account",
    "unauthorized login", "payment failed", "kyc update"
]

SPAM_KEYWORDS = [
    "lottery", "winner", "prize", "free money", "crypto profit",
    "loan approved", "earn money", "work from home", "congratulations",
    "investment opportunity", "claim now", "double your income",
    "guaranteed profit", "selected winner"
]

MARKETING_KEYWORDS = [
    "newsletter", "unsubscribe", "discount", "sale", "offer",
    "webinar", "promotion", "limited offer", "deal", "coupon",
    "subscribe", "campaign", "new product", "exclusive offer",
    "welcome", "booking", "ticket", "travel", "invoice", "receipt"
]

ACCOUNT_ALERT_WORDS = [
    "welcome", "booking", "ticket", "otp", "receipt", "invoice",
    "order", "confirmed", "payment received", "subscription"
]

SENSITIVE_URL_WORDS = [
    "login", "verify", "account", "password", "bank", "payment",
    "wallet", "secure", "signin", "auth", "reset", "confirm", "kyc"
]

SHORTENER_DOMAINS = [
    "bit.ly", "tinyurl.com", "t.co", "goo.gl", "ow.ly",
    "is.gd", "buff.ly", "cutt.ly", "rebrand.ly"
]

RISKY_EXTENSIONS = [
    ".exe", ".scr", ".bat", ".cmd", ".js", ".vbs", ".ps1",
    ".jar", ".msi", ".dll", ".com", ".pif", ".hta", ".lnk"
]

MACRO_EXTENSIONS = [".docm", ".xlsm", ".pptm"]
ARCHIVE_EXTENSIONS = [".zip", ".rar", ".7z", ".iso"]
DOCUMENT_EXTENSIONS = [".pdf", ".doc", ".docx", ".xls", ".xlsx", ".ppt", ".pptx"]

FREE_EMAIL_DOMAINS = [
    "gmail.com", "yahoo.com", "outlook.com", "hotmail.com", "proton.me"
]


def get_domain_from_email(email_value):
    parsed = parseaddr(email_value or "")[1]
    if "@" in parsed:
        return parsed.split("@")[-1].lower()
    return ""


def classify_email(email_data):
    trusted_domains = get_trusted_domains()
    blocked_domains = get_blocked_domains()

    subject = (email_data.get("subject") or "").lower()
    body = (email_data.get("body") or "").lower()
    combined_text = subject + " " + body

    from_domain = get_domain_from_email(email_data.get("from", ""))
    sender_domain = get_domain_from_email(email_data.get("sender_email", "")) or from_domain
    is_trusted_sender = is_domain_or_parent_match(sender_domain, trusted_domains)
    is_blocked_sender = is_domain_or_parent_match(sender_domain, blocked_domains)

    score = 0
    reasons = []
    risk_details = []
    sub_tag = "General"

    phishing_hits = count_keyword_hits(combined_text, PHISHING_KEYWORDS)
    spam_hits = count_keyword_hits(combined_text, SPAM_KEYWORDS)
    marketing_hits = count_keyword_hits(combined_text, MARKETING_KEYWORDS)
    account_alert_hits = count_keyword_hits(combined_text, ACCOUNT_ALERT_WORDS)

    if is_blocked_sender:
        add_score(risk_details, reasons, "Blocked sender domain", 60, "Sender domain is in blocked list")
        score += 60

    if is_trusted_sender:
        risk_details.append({"factor": "Trusted sender domain", "points": -20, "direction": "reduce", "reason": "Sender domain is in trusted list"})
        reasons.append("Sender domain is in trusted list")

    if phishing_hits:
        points = min(phishing_hits * 7, 30)
        add_score(risk_details, reasons, "Phishing keywords", points, f"Phishing keywords found: {phishing_hits}")
        score += points

    if spam_hits:
        points = min(spam_hits * 6, 24)
        add_score(risk_details, reasons, "Spam keywords", points, f"Spam keywords found: {spam_hits}")
        score += points

    if marketing_hits:
        reasons.append(f"Marketing or notification indicators found: {marketing_hits}")
        risk_details.append({"factor": "Marketing indicators", "points": 0, "direction": "informational", "reason": f"Marketing/notification indicators found: {marketing_hits}"})

    headers = email_data.get("headers", {}) or {}
    header_keys = {k.lower() for k in headers.keys()}
    if "list-unsubscribe" in header_keys:
        marketing_hits += 2
        reasons.append("List-Unsubscribe header found")
        risk_details.append({"factor": "List-Unsubscribe", "points": 0, "direction": "informational", "reason": "Marketing/newsletter indicator"})

    header_score, header_reasons = analyze_headers(email_data, is_trusted_sender)
    if header_score:
        score += header_score
        risk_details.append({"factor": "Header anomalies", "points": header_score, "direction": "increase", "reason": "; ".join(header_reasons)})
    reasons.extend(header_reasons)

    auth_result = analyze_authentication(email_data)
    if auth_result.get("score", 0):
        score += auth_result["score"]
        risk_details.append({"factor": "Authentication failure", "points": auth_result["score"], "direction": "increase", "reason": "; ".join(auth_result.get("reasons", []))})
        reasons.extend(auth_result.get("reasons", []))

    url_results = analyze_urls(email_data.get("urls", []), trusted_domains, blocked_domains)
    risky_urls = [u for u in url_results if u["risk_level"] in ["High", "Medium"]]

    for item in url_results:
        if item["risk_level"] == "High":
            score += 20
            risk_details.append({"factor": "High-risk URL", "points": 20, "direction": "increase", "reason": item.get("reason", "")})
        elif item["risk_level"] == "Medium":
            score += 10
            risk_details.append({"factor": "Medium-risk URL", "points": 10, "direction": "increase", "reason": item.get("reason", "")})

    if risky_urls:
        reasons.append(f"Suspicious URLs found: {len(risky_urls)}")

    attachment_results = analyze_attachments(email_data.get("attachments", []))
    malware_attachment_found = False

    for item in attachment_results:
        if item["risk_level"] == "High":
            score += 30
            malware_attachment_found = True
            risk_details.append({"factor": "High-risk attachment", "points": 30, "direction": "increase", "reason": item.get("reason", "")})
        elif item["risk_level"] == "Medium":
            score += 15
            risk_details.append({"factor": "Medium-risk attachment", "points": 15, "direction": "increase", "reason": item.get("reason", "")})

    if malware_attachment_found:
        sub_tag = "Malware Attachment"
        reasons.append("Potentially dangerous attachment found")

    ml_result = classify_with_ml(subject, body)
    if ml_result["prediction"] == "Phishing" and ml_result["confidence"] >= 70:
        score += 10
        risk_details.append({"factor": "ML phishing prediction", "points": 10, "direction": "increase", "reason": f"ML predicted phishing with {ml_result['confidence']}% confidence"})
        reasons.append(f"ML model predicted phishing: {ml_result['confidence']}%")
    elif ml_result["prediction"] == "Safe" and ml_result["confidence"] >= 70:
        risk_details.append({"factor": "ML safe prediction", "points": -5, "direction": "reduce", "reason": f"ML predicted safe with {ml_result['confidence']}% confidence"})
        score = max(0, score - 5)

    if is_trusted_sender and not malware_attachment_found and not any(u["risk_level"] == "High" for u in url_results):
        old_score = score
        score = min(score, 35)
        if old_score != score:
            risk_details.append({"factor": "Trusted sender adjustment", "points": score - old_score, "direction": "reduce", "reason": "Trusted sender reduced false positive risk"})

    if account_alert_hits >= 1 and marketing_hits >= 1 and not malware_attachment_found and not any(u["risk_level"] == "High" for u in url_results):
        old_score = score
        score = min(score, 35)
        if old_score != score:
            risk_details.append({"factor": "Normal notification adjustment", "points": score - old_score, "direction": "reduce", "reason": "Looks like normal account/booking/receipt email"})
        if sub_tag == "General":
            sub_tag = "Account Alert"

    if is_blocked_sender:
        score = max(score, 75)

    score = min(max(score, 0), 100)
    risk_level = get_risk_level(score)

    category = decide_category(
        score=score,
        phishing_hits=phishing_hits,
        spam_hits=spam_hits,
        marketing_hits=marketing_hits,
        account_alert_hits=account_alert_hits,
        malware_attachment_found=malware_attachment_found,
        risky_url_count=len(risky_urls),
        is_trusted_sender=is_trusted_sender
    )

    if category == "Phishing" and sub_tag == "General":
        if any(word in combined_text for word in ["password", "login", "verify", "signin", "reset", "kyc"]):
            sub_tag = "Credential Theft"
        elif any(word in combined_text for word in ["bank", "payment", "wallet", "invoice"]):
            sub_tag = "Financial Fraud"

    if category == "Spam" and sub_tag == "General":
        sub_tag = "Bulk Spam"

    if category == "Marketing" and sub_tag == "General":
        sub_tag = "Promotional"

    if category == "Safe" and sub_tag == "General" and account_alert_hits:
        sub_tag = "Account Alert"

    ioc_results = extract_iocs(email_data, url_results, attachment_results)

    classification = {
        "category": category,
        "sub_tag": sub_tag,
        "risk_score": score,
        "risk_level": risk_level,
        "main_reason": "; ".join(reasons[:8]) if reasons else "No major suspicious indicators found",
        "url_results": url_results,
        "attachment_results": attachment_results,
        "ioc_results": ioc_results,
        "risk_details": risk_details,
        "auth_result": auth_result,
        "ml_result": ml_result
    }

    classification["mitre_results"] = map_to_mitre(classification)
    return classification


def add_score(risk_details, reasons, factor, points, reason):
    risk_details.append({"factor": factor, "points": points, "direction": "increase", "reason": reason})
    reasons.append(reason)


def count_keyword_hits(text, keywords):
    return sum(1 for keyword in keywords if keyword in text)


def analyze_headers(email_data, is_trusted_sender=False):
    score = 0
    reasons = []

    from_domain = get_domain_from_email(email_data.get("from", ""))
    reply_domain = get_domain_from_email(email_data.get("reply_to", ""))
    return_path_domain = get_domain_from_email(email_data.get("return_path", ""))

    if reply_domain and from_domain and reply_domain != from_domain:
        points = 8 if is_trusted_sender else 15
        score += points
        reasons.append("From and Reply-To domain mismatch")

    if return_path_domain and from_domain and return_path_domain != from_domain:
        points = 5 if is_trusted_sender else 10
        score += points
        reasons.append("From and Return-Path domain mismatch")

    if reply_domain in FREE_EMAIL_DOMAINS and from_domain and reply_domain != from_domain and not is_trusted_sender:
        score += 10
        reasons.append("Reply-To uses free email domain")

    if not email_data.get("message_id"):
        score += 5
        reasons.append("Missing Message-ID")

    return score, reasons


def analyze_urls(urls, trusted_domains=None, blocked_domains=None):
    trusted_domains = trusted_domains or []
    blocked_domains = blocked_domains or []
    results = []

    for url in urls:
        parsed = urlparse(url)
        domain = parsed.netloc.lower()
        path = parsed.path.lower()
        full_url_lower = url.lower()

        risk_level = "Low"
        reasons = []

        if is_domain_or_parent_match(domain, trusted_domains):
            reasons.append("URL domain is trusted")

        if is_domain_or_parent_match(domain, blocked_domains):
            risk_level = raise_risk(risk_level, "High")
            reasons.append("URL domain is blocked")

        if url.startswith("http://") and not is_domain_or_parent_match(domain, trusted_domains):
            risk_level = raise_risk(risk_level, "Medium")
            reasons.append("Uses HTTP instead of HTTPS")

        if domain in SHORTENER_DOMAINS:
            risk_level = raise_risk(risk_level, "Medium")
            reasons.append("URL shortener detected")

        if is_ip_address(domain):
            risk_level = raise_risk(risk_level, "High")
            reasons.append("IP address used instead of domain")

        if any(word in full_url_lower or word in path for word in SENSITIVE_URL_WORDS):
            if not is_domain_or_parent_match(domain, trusted_domains):
                risk_level = raise_risk(risk_level, "Medium")
                reasons.append("Sensitive action keyword found in URL")

        if len(url) > 120:
            risk_level = raise_risk(risk_level, "Medium")
            reasons.append("Unusually long URL")

        if "@" in parsed.netloc:
            risk_level = raise_risk(risk_level, "High")
            reasons.append("URL contains @ symbol in host section")

        results.append({
            "url": url,
            "domain": domain,
            "risk_level": risk_level,
            "reason": "; ".join(reasons) if reasons else "No major URL issue found"
        })

    return results


def analyze_attachments(attachments):
    results = []

    for attachment in attachments:
        filename_original = attachment.get("filename") or ""
        filename = filename_original.lower()
        extension = attachment.get("extension") or get_extension(filename)
        entropy = float(attachment.get("entropy") or 0.0)

        risk_level = "Low"
        reasons = []
        is_risky = False
        is_double_extension = False

        if any(filename.endswith(ext) for ext in RISKY_EXTENSIONS):
            risk_level = raise_risk(risk_level, "High")
            reasons.append("Executable or script attachment")
            is_risky = True

        if any(filename.endswith(ext) for ext in MACRO_EXTENSIONS):
            risk_level = raise_risk(risk_level, "Medium")
            reasons.append("Macro-enabled Office document")
            is_risky = True

        if any(filename.endswith(ext) for ext in ARCHIVE_EXTENSIONS):
            risk_level = raise_risk(risk_level, "Medium")
            reasons.append("Compressed archive attachment")

        parts = filename.split(".")
        if len(parts) >= 3:
            is_double_extension = True
            risk_level = raise_risk(risk_level, "Medium")
            reasons.append("Double extension detected")

            inner_extensions = ["." + part for part in parts[1:-1]]
            if any(ext in DOCUMENT_EXTENSIONS for ext in inner_extensions) and extension in RISKY_EXTENSIONS:
                risk_level = raise_risk(risk_level, "High")
                reasons.append("Document disguised as executable")

        if entropy >= 7.2 and attachment.get("size_bytes", 0) > 1024:
            risk_level = raise_risk(risk_level, "Medium")
            reasons.append("High entropy content detected")

        if attachment.get("size_bytes", 0) == 0:
            reasons.append("Attachment has zero-byte payload")

        result = dict(attachment)
        result["extension"] = extension
        result["entropy"] = entropy
        result["is_risky"] = is_risky
        result["is_double_extension"] = is_double_extension
        result["risk_level"] = risk_level
        result["reason"] = "; ".join(reasons) if reasons else "No major attachment issue found"
        results.append(result)

    return results


def get_extension(filename):
    if "." not in filename:
        return ""
    return "." + filename.split(".")[-1].lower()


def raise_risk(current, new):
    levels = {"Low": 1, "Medium": 2, "High": 3}
    return new if levels[new] > levels[current] else current


def is_ip_address(domain):
    pattern = r"^\d{1,3}(\.\d{1,3}){3}$"
    if not re.match(pattern, domain):
        return False
    try:
        return all(0 <= int(part) <= 255 for part in domain.split("."))
    except Exception:
        return False


def get_risk_level(score):
    if score >= 80:
        return "Critical"
    if score >= 60:
        return "High"
    if score >= 31:
        return "Medium"
    return "Low"


def decide_category(score, phishing_hits, spam_hits, marketing_hits, account_alert_hits, malware_attachment_found, risky_url_count, is_trusted_sender):
    if malware_attachment_found:
        return "Phishing"

    if is_trusted_sender and score <= 35:
        if marketing_hits >= 2:
            return "Marketing"
        return "Safe"

    if score >= 70:
        return "Phishing"

    if phishing_hits >= 2 and risky_url_count >= 1:
        return "Phishing"

    if spam_hits >= 2 and score < 70:
        return "Spam"

    if marketing_hits >= 2 and score < 45:
        return "Marketing"

    if account_alert_hits >= 1 and score <= 35:
        return "Safe"

    if score >= 31:
        return "Suspicious"

    return "Safe"
