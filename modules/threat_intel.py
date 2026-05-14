import base64
import time
import requests

from modules.config import get_config


VT_BASE = "https://www.virustotal.com/api/v3"


def get_vt_key():
    return get_config("VIRUSTOTAL_API_KEY", "").strip()


def is_vt_configured():
    return bool(get_vt_key())


def vt_headers():
    return {"x-apikey": get_vt_key()}


def vt_url_id(url):
    value = base64.urlsafe_b64encode(url.encode()).decode().strip("=")
    return value


def summarize_stats(stats):
    stats = stats or {}
    malicious = int(stats.get("malicious", 0) or 0)
    suspicious = int(stats.get("suspicious", 0) or 0)
    harmless = int(stats.get("harmless", 0) or 0)
    undetected = int(stats.get("undetected", 0) or 0)

    if malicious > 0:
        verdict = "Malicious"
    elif suspicious > 0:
        verdict = "Suspicious"
    else:
        verdict = "Clean/Unknown"

    return {
        "verdict": verdict,
        "malicious": malicious,
        "suspicious": suspicious,
        "harmless": harmless,
        "undetected": undetected
    }


def lookup_url(url):
    if not is_vt_configured():
        return disabled_result(url, "URL")

    endpoint = f"{VT_BASE}/urls/{vt_url_id(url)}"
    return vt_get(endpoint, url, "URL")


def lookup_domain(domain):
    if not is_vt_configured():
        return disabled_result(domain, "Domain")

    endpoint = f"{VT_BASE}/domains/{domain}"
    return vt_get(endpoint, domain, "Domain")


def lookup_ip(ip):
    if not is_vt_configured():
        return disabled_result(ip, "IP Address")

    endpoint = f"{VT_BASE}/ip_addresses/{ip}"
    return vt_get(endpoint, ip, "IP Address")


def lookup_hash(hash_value):
    if not is_vt_configured():
        return disabled_result(hash_value, "Hash")

    endpoint = f"{VT_BASE}/files/{hash_value}"
    return vt_get(endpoint, hash_value, "Hash")


def vt_get(endpoint, indicator, indicator_type):
    try:
        response = requests.get(endpoint, headers=vt_headers(), timeout=20)

        if response.status_code == 404:
            return make_result(indicator, indicator_type, "Not Found", 0, 0, 0, 0, "not_found")

        if response.status_code == 429:
            return make_result(indicator, indicator_type, "Rate Limited", 0, 0, 0, 0, "rate_limited")

        response.raise_for_status()
        data = response.json()
        stats = data.get("data", {}).get("attributes", {}).get("last_analysis_stats", {})
        summary = summarize_stats(stats)

        return make_result(
            indicator,
            indicator_type,
            summary["verdict"],
            summary["malicious"],
            summary["suspicious"],
            summary["harmless"],
            summary["undetected"],
            "ok"
        )

    except Exception as error:
        return make_result(indicator, indicator_type, "Error", 0, 0, 0, 0, str(error))


def make_result(indicator, indicator_type, verdict, malicious, suspicious, harmless, undetected, status):
    return {
        "indicator": indicator,
        "type": indicator_type,
        "source": "VirusTotal",
        "verdict": verdict,
        "malicious": malicious,
        "suspicious": suspicious,
        "harmless": harmless,
        "undetected": undetected,
        "status": status,
        "checked_at": time.strftime("%Y-%m-%d %H:%M:%S")
    }


def disabled_result(indicator, indicator_type):
    return make_result(
        indicator=indicator,
        indicator_type=indicator_type,
        verdict="API Key Not Configured",
        malicious=0,
        suspicious=0,
        harmless=0,
        undetected=0,
        status="disabled"
    )


def lookup_ioc(ioc_type, value):
    t = (ioc_type or "").lower()

    if t == "url":
        return lookup_url(value)

    if t == "domain":
        return lookup_domain(value)

    if t == "ip address":
        return lookup_ip(value)

    if t in ["sha256", "md5", "hash"]:
        return lookup_hash(value)

    return make_result(value, ioc_type, "Unsupported Type", 0, 0, 0, 0, "unsupported")
