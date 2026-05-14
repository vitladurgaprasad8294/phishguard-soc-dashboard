def generate_explanation(email, urls=None, attachments=None, iocs=None):
    urls = urls or []
    attachments = attachments or []
    iocs = iocs or []

    category = email.get("category", "Unknown")
    risk = email.get("risk_score", 0)
    reason = email.get("main_reason", "")

    lines = []

    lines.append(f"This email was classified as {category} with a risk score of {risk}/100.")

    if reason:
        lines.append(f"The main reason is: {reason}")

    if urls:
        risky_urls = [u for u in urls if u.get("risk_level") in ["Medium", "High"]]
        if risky_urls:
            lines.append(f"It contains {len(risky_urls)} suspicious URL(s), so links should not be opened until verified.")
        else:
            lines.append("URLs were found, but no major URL risk was identified by local rules.")

    if attachments:
        risky_attachments = [a for a in attachments if a.get("risk_level") in ["Medium", "High"]]
        if risky_attachments:
            lines.append(f"It contains {len(risky_attachments)} risky attachment(s). Do not open them on your main system.")
        else:
            lines.append("Attachments were found, but no major attachment risk was identified by local rules.")

    if iocs:
        lines.append(f"{len(iocs)} indicator(s) of compromise were extracted for investigation.")

    if category == "Phishing":
        lines.append("Recommended action: report phishing, block sender if needed, and preserve the raw evidence file.")
    elif category == "Spam":
        lines.append("Recommended action: move to spam and avoid replying.")
    elif category == "Marketing":
        lines.append("Recommended action: review normally. Use unsubscribe only if the sender is trusted.")
    elif category == "Suspicious":
        lines.append("Recommended action: review sender, links, and attachments before taking action.")
    else:
        lines.append("Recommended action: no urgent action required unless the content looks unusual.")

    return " ".join(lines)
