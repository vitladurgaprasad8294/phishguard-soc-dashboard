def analyze_authentication(email_data):
    headers = email_data.get("headers", {}) or {}
    lower_headers = {str(k).lower(): str(v).lower() for k, v in headers.items()}

    auth_text = lower_headers.get("authentication-results", "")
    received_spf = lower_headers.get("received-spf", "")
    combined = auth_text + " " + received_spf

    result = {
        "spf": "Unknown",
        "dkim": "Unknown",
        "dmarc": "Unknown",
        "spoofing_risk": "Unknown",
        "score": 0,
        "reasons": []
    }

    if "spf=pass" in combined or "pass" in received_spf:
        result["spf"] = "Pass"
    elif "spf=fail" in combined or "fail" in received_spf:
        result["spf"] = "Fail"
        result["score"] += 15
        result["reasons"].append("SPF failed")

    if "dkim=pass" in combined:
        result["dkim"] = "Pass"
    elif "dkim=fail" in combined:
        result["dkim"] = "Fail"
        result["score"] += 10
        result["reasons"].append("DKIM failed")

    if "dmarc=pass" in combined:
        result["dmarc"] = "Pass"
    elif "dmarc=fail" in combined:
        result["dmarc"] = "Fail"
        result["score"] += 20
        result["reasons"].append("DMARC failed")

    if result["score"] >= 25:
        result["spoofing_risk"] = "High"
    elif result["score"] >= 10:
        result["spoofing_risk"] = "Medium"
    elif result["spf"] == "Pass" or result["dkim"] == "Pass" or result["dmarc"] == "Pass":
        result["spoofing_risk"] = "Low"

    if not result["reasons"]:
        result["reasons"].append("No explicit authentication failure found in parsed headers")

    return result
