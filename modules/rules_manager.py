from pathlib import Path


RULES_DIR = Path("rules")
TRUSTED_FILE = RULES_DIR / "trusted_domains.txt"
BLOCKED_FILE = RULES_DIR / "blocked_domains.txt"


def ensure_rule_files():
    RULES_DIR.mkdir(exist_ok=True)
    TRUSTED_FILE.touch(exist_ok=True)
    BLOCKED_FILE.touch(exist_ok=True)


def normalize_domain(domain):
    domain = (domain or "").strip().lower()
    domain = domain.replace("https://", "").replace("http://", "")
    domain = domain.replace("www.", "")
    domain = domain.split("/")[0]
    domain = domain.split(":")[0]
    return domain


def load_domains(file_path):
    ensure_rule_files()
    domains = []
    with open(file_path, "r", encoding="utf-8", errors="ignore") as f:
        for line in f:
            line = normalize_domain(line)
            if line and not line.startswith("#") and line not in domains:
                domains.append(line)
    return domains


def save_domains(file_path, domains):
    ensure_rule_files()
    cleaned = []
    for domain in domains:
        domain = normalize_domain(domain)
        if domain and domain not in cleaned:
            cleaned.append(domain)
    with open(file_path, "w", encoding="utf-8") as f:
        f.write("\n".join(sorted(cleaned)) + ("\n" if cleaned else ""))


def get_trusted_domains():
    return load_domains(TRUSTED_FILE)


def get_blocked_domains():
    return load_domains(BLOCKED_FILE)


def add_trusted_domain(domain):
    domain = normalize_domain(domain)
    domains = get_trusted_domains()
    if domain and domain not in domains:
        domains.append(domain)
    save_domains(TRUSTED_FILE, domains)
    return domain


def add_blocked_domain(domain):
    domain = normalize_domain(domain)
    domains = get_blocked_domains()
    if domain and domain not in domains:
        domains.append(domain)
    save_domains(BLOCKED_FILE, domains)
    return domain


def remove_trusted_domain(domain):
    domain = normalize_domain(domain)
    domains = [d for d in get_trusted_domains() if d != domain]
    save_domains(TRUSTED_FILE, domains)


def remove_blocked_domain(domain):
    domain = normalize_domain(domain)
    domains = [d for d in get_blocked_domains() if d != domain]
    save_domains(BLOCKED_FILE, domains)


def is_domain_or_parent_match(domain, rules):
    domain = normalize_domain(domain)
    if not domain:
        return False

    for rule in rules:
        rule = normalize_domain(rule)
        if domain == rule or domain.endswith("." + rule):
            return True

    return False
