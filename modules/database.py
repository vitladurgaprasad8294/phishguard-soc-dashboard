import os
import sqlite3
import json
from datetime import datetime


DB_PATH = "database/phishguard.db"


def get_connection():
    os.makedirs("database", exist_ok=True)
    conn = sqlite3.connect(DB_PATH)
    conn.row_factory = sqlite3.Row
    return conn


def table_columns(cur, table_name):
    cur.execute(f"PRAGMA table_info({table_name})")
    return {row["name"] for row in cur.fetchall()}


def add_column_if_missing(cur, table_name, column_name, column_definition):
    columns = table_columns(cur, table_name)
    if column_name not in columns:
        cur.execute(f"ALTER TABLE {table_name} ADD COLUMN {column_name} {column_definition}")


def init_db():
    conn = get_connection()
    cur = conn.cursor()

    cur.execute("""
    CREATE TABLE IF NOT EXISTS emails (
        id INTEGER PRIMARY KEY AUTOINCREMENT,
        message_id TEXT UNIQUE,
        subject TEXT,
        sender TEXT,
        recipient TEXT,
        sender_email TEXT,
        email_date TEXT,
        category TEXT,
        sub_tag TEXT,
        risk_score INTEGER,
        risk_level TEXT,
        main_reason TEXT,
        body_preview TEXT,
        raw_headers TEXT,
        evidence_file TEXT,
        source TEXT,
        reviewed INTEGER DEFAULT 0,
        analyst_note TEXT DEFAULT '',
        final_verdict TEXT DEFAULT '',
        quarantined INTEGER DEFAULT 0,
        risk_details TEXT DEFAULT '[]',
        auth_result TEXT DEFAULT '{}',
        ml_result TEXT DEFAULT '{}',
        mitre_results TEXT DEFAULT '[]',
        created_at TEXT
    )
    """)

    cur.execute("""
    CREATE TABLE IF NOT EXISTS urls (
        id INTEGER PRIMARY KEY AUTOINCREMENT,
        email_id INTEGER,
        url TEXT,
        domain TEXT,
        risk_level TEXT,
        reason TEXT,
        FOREIGN KEY(email_id) REFERENCES emails(id)
    )
    """)

    cur.execute("""
    CREATE TABLE IF NOT EXISTS attachments (
        id INTEGER PRIMARY KEY AUTOINCREMENT,
        email_id INTEGER,
        filename TEXT,
        content_type TEXT,
        size_bytes INTEGER,
        sha256 TEXT,
        md5 TEXT,
        risk_level TEXT,
        reason TEXT,
        extension TEXT,
        entropy REAL,
        is_risky INTEGER,
        is_double_extension INTEGER,
        FOREIGN KEY(email_id) REFERENCES emails(id)
    )
    """)

    cur.execute("""
    CREATE TABLE IF NOT EXISTS iocs (
        id INTEGER PRIMARY KEY AUTOINCREMENT,
        email_id INTEGER,
        ioc_value TEXT,
        ioc_type TEXT,
        severity TEXT,
        source TEXT,
        FOREIGN KEY(email_id) REFERENCES emails(id)
    )
    """)

    cur.execute("""
    CREATE TABLE IF NOT EXISTS threat_intel (
        id INTEGER PRIMARY KEY AUTOINCREMENT,
        email_id INTEGER,
        indicator TEXT,
        indicator_type TEXT,
        source TEXT,
        verdict TEXT,
        malicious INTEGER,
        suspicious INTEGER,
        harmless INTEGER,
        undetected INTEGER,
        status TEXT,
        checked_at TEXT,
        FOREIGN KEY(email_id) REFERENCES emails(id)
    )
    """)

    cur.execute("""
    CREATE TABLE IF NOT EXISTS timeline (
        id INTEGER PRIMARY KEY AUTOINCREMENT,
        email_id INTEGER,
        event_type TEXT,
        event_detail TEXT,
        created_at TEXT,
        FOREIGN KEY(email_id) REFERENCES emails(id)
    )
    """)

    for col, definition in {
        "sender_email": "TEXT",
        "source": "TEXT",
        "reviewed": "INTEGER DEFAULT 0",
        "analyst_note": "TEXT DEFAULT ''",
        "final_verdict": "TEXT DEFAULT ''",
        "quarantined": "INTEGER DEFAULT 0",
        "risk_details": "TEXT DEFAULT '[]'",
        "auth_result": "TEXT DEFAULT '{}'",
        "ml_result": "TEXT DEFAULT '{}'",
        "mitre_results": "TEXT DEFAULT '[]'",
        "created_at": "TEXT"
    }.items():
        add_column_if_missing(cur, "emails", col, definition)

    for col, definition in {
        "extension": "TEXT",
        "entropy": "REAL",
        "is_risky": "INTEGER DEFAULT 0",
        "is_double_extension": "INTEGER DEFAULT 0"
    }.items():
        add_column_if_missing(cur, "attachments", col, definition)

    conn.commit()
    conn.close()


def log_event(cur, email_id, event_type, event_detail):
    cur.execute("""
    INSERT INTO timeline (email_id, event_type, event_detail, created_at)
    VALUES (?, ?, ?, ?)
    """, (email_id, event_type, event_detail, datetime.now().strftime("%Y-%m-%d %H:%M:%S")))


def save_email(email_data, classification, evidence_file="", source="Upload"):
    init_db()
    conn = get_connection()
    cur = conn.cursor()

    raw_headers = json.dumps(email_data.get("headers", {}), indent=2)

    try:
        cur.execute("""
        INSERT INTO emails (
            message_id, subject, sender, recipient, sender_email, email_date,
            category, sub_tag, risk_score, risk_level, main_reason,
            body_preview, raw_headers, evidence_file, source, reviewed,
            analyst_note, final_verdict, quarantined, risk_details, auth_result,
            ml_result, mitre_results, created_at
        )
        VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)
        """, (
            email_data.get("message_id", ""),
            email_data.get("subject", ""),
            email_data.get("from", ""),
            email_data.get("to", ""),
            email_data.get("sender_email", ""),
            email_data.get("date", ""),
            classification.get("category", ""),
            classification.get("sub_tag", ""),
            classification.get("risk_score", 0),
            classification.get("risk_level", ""),
            classification.get("main_reason", ""),
            email_data.get("body", "")[:8000],
            raw_headers,
            evidence_file,
            source,
            0,
            "",
            "",
            0,
            json.dumps(classification.get("risk_details", [])),
            json.dumps(classification.get("auth_result", {})),
            json.dumps(classification.get("ml_result", {})),
            json.dumps(classification.get("mitre_results", [])),
            datetime.now().strftime("%Y-%m-%d %H:%M:%S")
        ))
        email_id = cur.lastrowid
        inserted = True
        log_event(cur, email_id, "Created", f"Email saved from {source}")

    except sqlite3.IntegrityError:
        cur.execute("SELECT id FROM emails WHERE message_id = ?", (email_data.get("message_id", ""),))
        existing = cur.fetchone()
        conn.close()
        return {"email_id": existing["id"] if existing else None, "inserted": False}

    insert_child_records(cur, email_id, classification)
    log_event(cur, email_id, "Classified", f"{classification.get('category')} | Score {classification.get('risk_score')}/100")

    conn.commit()
    conn.close()
    return {"email_id": email_id, "inserted": inserted}


def insert_child_records(cur, email_id, classification):
    for url_item in classification.get("url_results", []):
        cur.execute("""
        INSERT INTO urls (email_id, url, domain, risk_level, reason)
        VALUES (?, ?, ?, ?, ?)
        """, (email_id, url_item.get("url", ""), url_item.get("domain", ""), url_item.get("risk_level", ""), url_item.get("reason", "")))

    for attachment in classification.get("attachment_results", []):
        cur.execute("""
        INSERT INTO attachments (
            email_id, filename, content_type, size_bytes,
            sha256, md5, risk_level, reason, extension,
            entropy, is_risky, is_double_extension
        )
        VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)
        """, (
            email_id,
            attachment.get("filename", ""),
            attachment.get("content_type", ""),
            attachment.get("size_bytes", 0),
            attachment.get("sha256", ""),
            attachment.get("md5", ""),
            attachment.get("risk_level", ""),
            attachment.get("reason", ""),
            attachment.get("extension", ""),
            attachment.get("entropy", 0.0),
            int(bool(attachment.get("is_risky", False))),
            int(bool(attachment.get("is_double_extension", False)))
        ))

    for ioc in classification.get("ioc_results", []):
        cur.execute("""
        INSERT INTO iocs (email_id, ioc_value, ioc_type, severity, source)
        VALUES (?, ?, ?, ?, ?)
        """, (email_id, ioc.get("value", ""), ioc.get("type", ""), ioc.get("severity", ""), ioc.get("source", "")))


def replace_email_analysis(email_id, email_data, classification):
    init_db()
    conn = get_connection()
    cur = conn.cursor()

    raw_headers = json.dumps(email_data.get("headers", {}), indent=2)

    cur.execute("""
    UPDATE emails
    SET subject = ?, sender = ?, recipient = ?, sender_email = ?, email_date = ?,
        category = ?, sub_tag = ?, risk_score = ?, risk_level = ?, main_reason = ?,
        body_preview = ?, raw_headers = ?, risk_details = ?, auth_result = ?,
        ml_result = ?, mitre_results = ?
    WHERE id = ?
    """, (
        email_data.get("subject", ""),
        email_data.get("from", ""),
        email_data.get("to", ""),
        email_data.get("sender_email", ""),
        email_data.get("date", ""),
        classification.get("category", ""),
        classification.get("sub_tag", ""),
        classification.get("risk_score", 0),
        classification.get("risk_level", ""),
        classification.get("main_reason", ""),
        email_data.get("body", "")[:8000],
        raw_headers,
        json.dumps(classification.get("risk_details", [])),
        json.dumps(classification.get("auth_result", {})),
        json.dumps(classification.get("ml_result", {})),
        json.dumps(classification.get("mitre_results", [])),
        email_id
    ))

    cur.execute("DELETE FROM urls WHERE email_id = ?", (email_id,))
    cur.execute("DELETE FROM attachments WHERE email_id = ?", (email_id,))
    cur.execute("DELETE FROM iocs WHERE email_id = ?", (email_id,))
    insert_child_records(cur, email_id, classification)
    log_event(cur, email_id, "Reanalyzed", f"{classification.get('category')} | Score {classification.get('risk_score')}/100")

    conn.commit()
    conn.close()


def update_review(email_id, reviewed, analyst_note="", final_verdict=""):
    init_db()
    conn = get_connection()
    cur = conn.cursor()
    cur.execute("""
    UPDATE emails
    SET reviewed = ?, analyst_note = ?, final_verdict = ?
    WHERE id = ?
    """, (1 if reviewed else 0, analyst_note or "", final_verdict or "", email_id))
    log_event(cur, email_id, "Reviewed", f"Reviewed={reviewed}, Verdict={final_verdict}")
    conn.commit()
    conn.close()


def update_quarantine(email_id, quarantined):
    init_db()
    conn = get_connection()
    cur = conn.cursor()
    cur.execute("UPDATE emails SET quarantined = ? WHERE id = ?", (1 if quarantined else 0, email_id))
    log_event(cur, email_id, "Quarantine", f"Quarantine set to {quarantined}")
    conn.commit()
    conn.close()


def save_threat_intel_result(email_id, result):
    init_db()
    conn = get_connection()
    cur = conn.cursor()
    cur.execute("""
    INSERT INTO threat_intel (
        email_id, indicator, indicator_type, source, verdict,
        malicious, suspicious, harmless, undetected, status, checked_at
    )
    VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)
    """, (
        email_id,
        result.get("indicator", ""),
        result.get("type", ""),
        result.get("source", ""),
        result.get("verdict", ""),
        int(result.get("malicious", 0) or 0),
        int(result.get("suspicious", 0) or 0),
        int(result.get("harmless", 0) or 0),
        int(result.get("undetected", 0) or 0),
        result.get("status", ""),
        result.get("checked_at", "")
    ))
    log_event(cur, email_id, "Threat Intel", f"{result.get('indicator')} -> {result.get('verdict')}")
    conn.commit()
    conn.close()


def get_threat_intel_results(email_id):
    init_db()
    conn = get_connection()
    cur = conn.cursor()
    cur.execute("SELECT * FROM threat_intel WHERE email_id = ? ORDER BY id DESC", (email_id,))
    rows = [dict(row) for row in cur.fetchall()]
    conn.close()
    return rows


def get_timeline(email_id):
    init_db()
    conn = get_connection()
    cur = conn.cursor()
    cur.execute("SELECT * FROM timeline WHERE email_id = ? ORDER BY id DESC", (email_id,))
    rows = [dict(row) for row in cur.fetchall()]
    conn.close()
    return rows


def get_dashboard_counts():
    init_db()
    conn = get_connection()
    cur = conn.cursor()

    counts = {
        "Total": 0, "Phishing": 0, "Spam": 0, "Marketing": 0,
        "Suspicious": 0, "Safe": 0, "High Risk": 0, "Malware Attachment": 0,
        "Attachments": 0, "IOCs": 0, "Reviewed": 0, "Unreviewed": 0,
        "Quarantined": 0, "Threat Intel": 0
    }

    cur.execute("SELECT COUNT(*) AS total FROM emails")
    counts["Total"] = cur.fetchone()["total"]

    for category in ["Phishing", "Spam", "Marketing", "Suspicious", "Safe"]:
        cur.execute("SELECT COUNT(*) AS count FROM emails WHERE category = ?", (category,))
        counts[category] = cur.fetchone()["count"]

    cur.execute("SELECT COUNT(*) AS count FROM emails WHERE risk_score >= 70")
    counts["High Risk"] = cur.fetchone()["count"]

    cur.execute("SELECT COUNT(*) AS count FROM emails WHERE sub_tag = 'Malware Attachment'")
    counts["Malware Attachment"] = cur.fetchone()["count"]

    cur.execute("SELECT COUNT(*) AS count FROM attachments")
    counts["Attachments"] = cur.fetchone()["count"]

    cur.execute("SELECT COUNT(*) AS count FROM iocs")
    counts["IOCs"] = cur.fetchone()["count"]

    cur.execute("SELECT COUNT(*) AS count FROM emails WHERE reviewed = 1")
    counts["Reviewed"] = cur.fetchone()["count"]

    cur.execute("SELECT COUNT(*) AS count FROM emails WHERE reviewed = 0 OR reviewed IS NULL")
    counts["Unreviewed"] = cur.fetchone()["count"]

    cur.execute("SELECT COUNT(*) AS count FROM emails WHERE quarantined = 1")
    counts["Quarantined"] = cur.fetchone()["count"]

    cur.execute("SELECT COUNT(*) AS count FROM threat_intel")
    counts["Threat Intel"] = cur.fetchone()["count"]

    conn.close()
    return counts


def get_emails_by_category(category="All", search_text="", review_filter="All"):
    init_db()
    conn = get_connection()
    cur = conn.cursor()

    params = []
    conditions = []

    if category == "High Risk":
        conditions.append("risk_score >= 70")
    elif category == "Malware Attachment":
        conditions.append("sub_tag = 'Malware Attachment'")
    elif category == "Quarantined":
        conditions.append("quarantined = 1")
    elif category != "All":
        conditions.append("category = ?")
        params.append(category)

    if review_filter == "Reviewed":
        conditions.append("reviewed = 1")
    elif review_filter == "Unreviewed":
        conditions.append("(reviewed = 0 OR reviewed IS NULL)")

    if search_text:
        like = f"%{search_text.lower()}%"
        conditions.append("""
        (
            LOWER(COALESCE(subject, '')) LIKE ?
            OR LOWER(COALESCE(sender, '')) LIKE ?
            OR LOWER(COALESCE(sender_email, '')) LIKE ?
            OR LOWER(COALESCE(main_reason, '')) LIKE ?
            OR LOWER(COALESCE(category, '')) LIKE ?
            OR LOWER(COALESCE(sub_tag, '')) LIKE ?
            OR LOWER(COALESCE(final_verdict, '')) LIKE ?
            OR LOWER(COALESCE(analyst_note, '')) LIKE ?
        )
        """)
        params.extend([like] * 8)

    where_clause = "WHERE " + " AND ".join(conditions) if conditions else ""

    query = f"""
        SELECT id, subject, sender, sender_email, email_date, category,
               sub_tag, risk_score, risk_level, main_reason, source,
               reviewed, analyst_note, final_verdict, quarantined, created_at
        FROM emails
        {where_clause}
        ORDER BY quarantined DESC, reviewed ASC, risk_score DESC, id DESC
    """

    cur.execute(query, params)
    rows = [dict(row) for row in cur.fetchall()]
    conn.close()
    return rows


def get_email_details(email_id):
    init_db()
    conn = get_connection()
    cur = conn.cursor()

    cur.execute("SELECT * FROM emails WHERE id = ?", (email_id,))
    email = cur.fetchone()

    cur.execute("SELECT * FROM urls WHERE email_id = ?", (email_id,))
    urls = cur.fetchall()

    cur.execute("SELECT * FROM attachments WHERE email_id = ?", (email_id,))
    attachments = cur.fetchall()

    cur.execute("SELECT * FROM iocs WHERE email_id = ?", (email_id,))
    iocs = cur.fetchall()

    conn.close()
    return {
        "email": dict(email) if email else None,
        "urls": [dict(row) for row in urls],
        "attachments": [dict(row) for row in attachments],
        "iocs": [dict(row) for row in iocs],
    }


def get_all_iocs():
    init_db()
    conn = get_connection()
    cur = conn.cursor()
    cur.execute("""
        SELECT iocs.id, iocs.email_id, emails.subject, emails.category,
               iocs.ioc_value, iocs.ioc_type, iocs.severity, iocs.source
        FROM iocs
        LEFT JOIN emails ON iocs.email_id = emails.id
        ORDER BY iocs.id DESC
    """)
    rows = [dict(row) for row in cur.fetchall()]
    conn.close()
    return rows


def get_all_attachments():
    init_db()
    conn = get_connection()
    cur = conn.cursor()
    cur.execute("""
        SELECT attachments.*, emails.subject, emails.category, emails.risk_score
        FROM attachments
        LEFT JOIN emails ON attachments.email_id = emails.id
        ORDER BY attachments.id DESC
    """)
    rows = [dict(row) for row in cur.fetchall()]
    conn.close()
    return rows


def get_all_threat_intel():
    init_db()
    conn = get_connection()
    cur = conn.cursor()
    cur.execute("""
        SELECT threat_intel.*, emails.subject, emails.category
        FROM threat_intel
        LEFT JOIN emails ON threat_intel.email_id = emails.id
        ORDER BY threat_intel.id DESC
    """)
    rows = [dict(row) for row in cur.fetchall()]
    conn.close()
    return rows


def get_all_evidence_files():
    init_db()
    conn = get_connection()
    cur = conn.cursor()
    cur.execute("""
        SELECT id, evidence_file
        FROM emails
        WHERE evidence_file IS NOT NULL AND evidence_file != ''
        ORDER BY id ASC
    """)
    rows = [dict(row) for row in cur.fetchall()]
    conn.close()
    return rows


def clear_database():
    conn = get_connection()
    cur = conn.cursor()
    cur.execute("DELETE FROM threat_intel")
    cur.execute("DELETE FROM timeline")
    cur.execute("DELETE FROM iocs")
    cur.execute("DELETE FROM urls")
    cur.execute("DELETE FROM attachments")
    cur.execute("DELETE FROM emails")
    conn.commit()
    conn.close()
