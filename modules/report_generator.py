from datetime import datetime
from fpdf import FPDF
import re
import textwrap


def clean_text(value, max_len=None):
    """
    Make text safe for simple PDF output:
    - Convert None to empty string
    - Remove emojis/non-ASCII symbols
    - Normalize whitespace
    - Truncate very long values
    """
    text = "" if value is None else str(value)
    text = text.encode("ascii", errors="ignore").decode("ascii", errors="ignore")
    text = text.replace("\r", " ").replace("\t", " ")
    text = re.sub(r"\s+", " ", text).strip()
    if max_len and len(text) > max_len:
        return text[:max_len] + "..."
    return text


def break_long_words(text, max_word_length=55):
    """
    fpdf2 can fail when a very long URL/hash/word has no spaces.
    This inserts spaces every max_word_length characters in long tokens.
    """
    text = clean_text(text)

    fixed_words = []
    for word in text.split(" "):
        if len(word) > max_word_length:
            chunks = textwrap.wrap(
                word,
                width=max_word_length,
                break_long_words=True,
                break_on_hyphens=False
            )
            fixed_words.append(" ".join(chunks))
        else:
            fixed_words.append(word)

    return " ".join(fixed_words)


class CasePDF(FPDF):
    def header(self):
        self.set_font("Helvetica", "B", 14)
        self.set_text_color(15, 23, 42)
        self.cell(0, 9, "PhishGuard Forensic Email Investigation Report", 0, 1, "C")

        self.set_font("Helvetica", "", 8)
        self.set_text_color(71, 85, 105)
        self.cell(0, 6, f"Generated: {datetime.now().strftime('%Y-%m-%d %H:%M:%S')}", 0, 1, "C")
        self.ln(3)

    def footer(self):
        self.set_y(-15)
        self.set_font("Helvetica", "I", 8)
        self.set_text_color(100, 116, 139)
        self.cell(0, 10, f"Page {self.page_no()} | PhishGuard", 0, 0, "C")


def page_width(pdf):
    return pdf.w - pdf.l_margin - pdf.r_margin


def safe_multicell(pdf, text, height=6, font_size=9, bold=False):
    """
    Always writes using full page width from left margin.
    Avoids the common fpdf error caused by remaining-width multi_cell usage.
    """
    pdf.set_x(pdf.l_margin)
    pdf.set_font("Helvetica", "B" if bold else "", font_size)
    pdf.set_text_color(15, 23, 42)
    safe_text = break_long_words(text)
    if not safe_text:
        safe_text = "-"
    pdf.multi_cell(page_width(pdf), height, safe_text)


def add_section(pdf, title):
    pdf.ln(4)
    pdf.set_x(pdf.l_margin)
    pdf.set_font("Helvetica", "B", 11)
    pdf.set_text_color(255, 255, 255)
    pdf.set_fill_color(37, 99, 235)
    pdf.cell(page_width(pdf), 8, clean_text(title), 0, 1, "L", fill=True)
    pdf.ln(2)


def add_key_value(pdf, key, value):
    """
    Robust key-value rendering.
    Key and value are placed on separate lines to avoid horizontal-space errors.
    """
    pdf.set_x(pdf.l_margin)
    pdf.set_font("Helvetica", "B", 9)
    pdf.set_text_color(30, 41, 59)
    pdf.cell(page_width(pdf), 6, clean_text(key) + ":", 0, 1)

    pdf.set_x(pdf.l_margin)
    pdf.set_font("Helvetica", "", 9)
    pdf.set_text_color(51, 65, 85)
    value_text = break_long_words(clean_text(value, 1200))
    if not value_text:
        value_text = "-"
    pdf.multi_cell(page_width(pdf), 6, value_text)
    pdf.ln(1)


def create_case_pdf(details):
    email = details.get("email") or {}
    urls = details.get("urls") or []
    attachments = details.get("attachments") or []
    iocs = details.get("iocs") or []

    pdf = CasePDF()
    pdf.set_auto_page_break(auto=True, margin=15)
    pdf.add_page()

    add_section(pdf, "1. Case Summary")
    add_key_value(pdf, "Case ID", email.get("id"))
    add_key_value(pdf, "Subject", email.get("subject"))
    add_key_value(pdf, "Sender", email.get("sender"))
    add_key_value(pdf, "Sender Email", email.get("sender_email"))
    add_key_value(pdf, "Recipient", email.get("recipient"))
    add_key_value(pdf, "Email Date", email.get("email_date"))
    add_key_value(pdf, "Source", email.get("source"))
    add_key_value(pdf, "Evidence File", email.get("evidence_file"))

    add_section(pdf, "2. Classification Result")
    add_key_value(pdf, "Category", email.get("category"))
    add_key_value(pdf, "Sub Tag", email.get("sub_tag"))
    add_key_value(pdf, "Risk Score", f"{email.get('risk_score')}/100")
    add_key_value(pdf, "Risk Level", email.get("risk_level"))
    add_key_value(pdf, "Main Reason", email.get("main_reason"))

    add_section(pdf, "3. URL Analysis")
    if urls:
        for idx, item in enumerate(urls, 1):
            add_key_value(pdf, f"URL {idx}", item.get("url"))
            add_key_value(pdf, "Domain", item.get("domain"))
            add_key_value(pdf, "Risk", item.get("risk_level"))
            add_key_value(pdf, "Reason", item.get("reason"))
    else:
        add_key_value(pdf, "URLs", "No URLs found.")

    add_section(pdf, "4. Attachment Analysis")
    if attachments:
        for idx, item in enumerate(attachments, 1):
            add_key_value(pdf, f"Attachment {idx}", item.get("filename"))
            add_key_value(pdf, "Content Type", item.get("content_type"))
            add_key_value(pdf, "Extension", item.get("extension"))
            add_key_value(pdf, "Size", item.get("size_bytes"))
            add_key_value(pdf, "Entropy", item.get("entropy"))
            add_key_value(pdf, "SHA256", item.get("sha256"))
            add_key_value(pdf, "MD5", item.get("md5"))
            add_key_value(pdf, "Risk", item.get("risk_level"))
            add_key_value(pdf, "Reason", item.get("reason"))
    else:
        add_key_value(pdf, "Attachments", "No attachments found.")

    add_section(pdf, "5. Indicators of Compromise")
    if iocs:
        for idx, item in enumerate(iocs, 1):
            add_key_value(pdf, f"IOC {idx}", item.get("ioc_value"))
            add_key_value(pdf, "Type", item.get("ioc_type"))
            add_key_value(pdf, "Severity", item.get("severity"))
            add_key_value(pdf, "Source", item.get("source"))
    else:
        add_key_value(pdf, "IOCs", "No IOCs extracted.")

    add_section(pdf, "6. Recommended Action")
    category = email.get("category")
    if category == "Phishing":
        action = "Do not click links or open attachments. Block sender, report phishing, review IOCs, and preserve evidence."
    elif category == "Spam":
        action = "Move to spam. Do not reply or interact with links."
    elif category == "Marketing":
        action = "Review normally. Unsubscribe only if sender is trusted."
    elif category == "Suspicious":
        action = "Investigate sender, links, and attachments before taking action."
    else:
        action = "No major suspicious indicators detected."
    add_key_value(pdf, "Action", action)

    add_section(pdf, "7. Email Body Preview")
    safe_multicell(pdf, clean_text(email.get("body_preview"), 2500), height=5, font_size=8)

    output = pdf.output(dest="S")
    if isinstance(output, str):
        return output.encode("latin-1", errors="replace")
    return bytes(output)


def create_case_text(details):
    email = details.get("email") or {}
    urls = details.get("urls") or []
    attachments = details.get("attachments") or []
    iocs = details.get("iocs") or []

    lines = []
    lines.append("PHISHGUARD EMAIL FORENSIC REPORT")
    lines.append("=" * 60)
    lines.append(f"Generated: {datetime.now().strftime('%Y-%m-%d %H:%M:%S')}")
    lines.append("")
    lines.append("CASE SUMMARY")
    lines.append("-" * 60)

    for key in [
        "id", "subject", "sender", "sender_email", "recipient",
        "email_date", "category", "sub_tag", "risk_score",
        "risk_level", "main_reason", "evidence_file"
    ]:
        lines.append(f"{key}: {clean_text(email.get(key))}")

    lines.append("")
    lines.append("URL ANALYSIS")
    lines.append("-" * 60)
    if urls:
        for item in urls:
            lines.append(f"- {clean_text(item.get('url'))} | {clean_text(item.get('risk_level'))} | {clean_text(item.get('reason'))}")
    else:
        lines.append("No URLs found.")

    lines.append("")
    lines.append("ATTACHMENT ANALYSIS")
    lines.append("-" * 60)
    if attachments:
        for item in attachments:
            lines.append(f"- {clean_text(item.get('filename'))} | {clean_text(item.get('risk_level'))} | {clean_text(item.get('reason'))}")
            lines.append(f"  SHA256: {clean_text(item.get('sha256'))}")
    else:
        lines.append("No attachments found.")

    lines.append("")
    lines.append("IOCS")
    lines.append("-" * 60)
    if iocs:
        for item in iocs:
            lines.append(f"- {clean_text(item.get('ioc_type'))}: {clean_text(item.get('ioc_value'))} | {clean_text(item.get('severity'))}")
    else:
        lines.append("No IOCs extracted.")

    return "\n".join(lines)
