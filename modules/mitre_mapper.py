def map_to_mitre(classification):
    mappings = []
    category = classification.get("category", "")
    sub_tag = classification.get("sub_tag", "")
    url_results = classification.get("url_results", []) or []
    attachment_results = classification.get("attachment_results", []) or []

    if category == "Phishing":
        mappings.append({
            "tactic": "Initial Access",
            "technique_id": "T1566",
            "technique": "Phishing",
            "reason": "Email classified as phishing or high-risk phishing attempt"
        })

    if any(u.get("risk_level") in ["Medium", "High"] for u in url_results):
        mappings.append({
            "tactic": "Initial Access",
            "technique_id": "T1566.002",
            "technique": "Spearphishing Link",
            "reason": "Suspicious link found in email body"
        })

    if any(a.get("risk_level") in ["Medium", "High"] for a in attachment_results):
        mappings.append({
            "tactic": "Initial Access",
            "technique_id": "T1566.001",
            "technique": "Spearphishing Attachment",
            "reason": "Suspicious attachment found"
        })

    if sub_tag == "Credential Theft":
        mappings.append({
            "tactic": "Credential Access",
            "technique_id": "T1556",
            "technique": "Modify Authentication Process / Credential Abuse Indicator",
            "reason": "Email appears to request login, password reset, or account verification"
        })

    if attachment_results or url_results:
        mappings.append({
            "tactic": "Execution",
            "technique_id": "T1204",
            "technique": "User Execution",
            "reason": "Email attempts to make user click a link or open an attachment"
        })

    return deduplicate(mappings)


def deduplicate(mappings):
    seen = set()
    unique = []
    for item in mappings:
        key = item.get("technique_id")
        if key not in seen:
            seen.add(key)
            unique.append(item)
    return unique
