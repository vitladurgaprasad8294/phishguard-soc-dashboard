import json
import os

import pandas as pd
import streamlit as st
from streamlit_autorefresh import st_autorefresh
from dotenv import load_dotenv
from modules.config import get_config, is_enabled

from modules.database import (
    init_db,
    save_email,
    replace_email_analysis,
    update_review,
    update_quarantine,
    save_threat_intel_result,
    get_threat_intel_results,
    get_timeline,
    get_dashboard_counts,
    get_emails_by_category,
    get_email_details,
    get_all_iocs,
    get_all_attachments,
    get_all_threat_intel,
    get_all_evidence_files,
    clear_database
)
from modules.email_parser import parse_eml_bytes
from modules.classifier import classify_email
from modules.imap_collector import fetch_unread_emails, is_mailbox_configured, get_imap_config
from modules.rules_manager import (
    get_trusted_domains,
    get_blocked_domains,
    add_trusted_domain,
    add_blocked_domain,
    remove_trusted_domain,
    remove_blocked_domain
)
from modules.explainer import generate_explanation
from modules.threat_intel import is_vt_configured, lookup_ioc


load_dotenv()
init_db()

st.set_page_config(
    page_title="PhishGuard SOC",
    page_icon="PG",
    layout="wide",
    initial_sidebar_state="expanded"
)

if "filter" not in st.session_state:
    st.session_state.filter = "All"

if "review_filter" not in st.session_state:
    st.session_state.review_filter = "All"

if "selected_email_id" not in st.session_state:
    st.session_state.selected_email_id = None

if "logged_in" not in st.session_state:
    st.session_state.logged_in = False


st.markdown("""
<style>
    .block-container { padding-top: 1.2rem; padding-bottom: 2rem; }
    .hero {
        background: linear-gradient(135deg, #111827 0%, #2563eb 45%, #059669 100%);
        padding: 30px;
        border-radius: 26px;
        color: white;
        box-shadow: 0 18px 45px rgba(15, 23, 42, 0.25);
        margin-bottom: 22px;
    }
    .hero h1 { font-size: 42px; margin: 0; font-weight: 850; color: white !important; }
    .hero p { color: #dbeafe !important; font-size: 17px; margin-top: 8px; }
    .metric-card {
        padding: 18px;
        border-radius: 20px;
        color: white !important;
        min-height: 118px;
        box-shadow: 0 12px 30px rgba(15, 23, 42, 0.18);
        margin-bottom: 12px;
    }
    .metric-card * { color: white !important; }
    .metric-title { font-size: 14px; opacity: 0.95; font-weight: 700; }
    .metric-number { font-size: 34px; font-weight: 850; margin-top: 8px; }
    .metric-help { font-size: 12px; opacity: 0.9; margin-top: 6px; }
    .blue { background: linear-gradient(135deg, #2563eb, #1d4ed8); }
    .red { background: linear-gradient(135deg, #ef4444, #b91c1c); }
    .orange { background: linear-gradient(135deg, #f97316, #c2410c); }
    .green { background: linear-gradient(135deg, #22c55e, #15803d); }
    .purple { background: linear-gradient(135deg, #8b5cf6, #6d28d9); }
    .slate { background: linear-gradient(135deg, #475569, #0f172a); }
    .teal { background: linear-gradient(135deg, #14b8a6, #0f766e); }
    .pink { background: linear-gradient(135deg, #ec4899, #be185d); }
    .case-box {
        border: 1px solid #cbd5e1;
        background: #f8fafc !important;
        padding: 18px;
        border-radius: 18px;
        margin: 12px 0;
    }
    .case-box, .case-box * { color: #0f172a !important; }
</style>
""", unsafe_allow_html=True)


def login_required():
    enabled = is_enabled("APP_LOGIN_ENABLED", "false")
    if not enabled:
        return False

    if st.session_state.logged_in:
        return False

    st.title("PhishGuard Login")
    username = st.text_input("Username")
    password = st.text_input("Password", type="password")

    if st.button("Login"):
        if username == get_config("APP_USERNAME", "admin") and password == get_config("APP_PASSWORD", "phishguard123"):
            st.session_state.logged_in = True
            st.rerun()
        else:
            st.error("Invalid username or password.")

    return True


if login_required():
    st.stop()


def save_evidence_file(raw_bytes, original_name):
    os.makedirs("live_emails", exist_ok=True)
    safe_name = original_name.replace(" ", "_")
    import datetime
    timestamp = datetime.datetime.now().strftime("%Y%m%d_%H%M%S")
    evidence_path = f"live_emails/{timestamp}_{safe_name}"
    with open(evidence_path, "wb") as f:
        f.write(raw_bytes)
    return evidence_path


def render_card(title, value, help_text, color_class, filter_value=None):
    st.markdown(
        f"""
        <div class="metric-card {color_class}">
            <div class="metric-title">{title}</div>
            <div class="metric-number">{value}</div>
            <div class="metric-help">{help_text}</div>
        </div>
        """,
        unsafe_allow_html=True
    )

    if filter_value:
        if st.button(f"Open {title}", key=f"open_{title}"):
            st.session_state.filter = filter_value
            st.rerun()


def dataframe_download(label, df, filename):
    if df is not None and not df.empty:
        st.download_button(
            label,
            data=df.to_csv(index=False).encode("utf-8"),
            file_name=filename,
            mime="text/csv",
            use_container_width=True
        )


def safe_json_load(value, fallback):
    try:
        if not value:
            return fallback
        return json.loads(value)
    except Exception:
        return fallback


def run_threat_intel_for_case(email_id, details):
    results = []
    for ioc in details.get("iocs", []):
        result = lookup_ioc(ioc.get("ioc_type"), ioc.get("ioc_value"))
        save_threat_intel_result(email_id, result)
        results.append(result)
    return results


def render_email_details(email_id):
    details = get_email_details(email_id)
    email = details["email"]

    if not email:
        st.error("Email not found.")
        return

    st.markdown(f"""
    <div class="case-box">
        <h3>Case #{email['id']} - {email['subject']}</h3>
        <p><b>Category:</b> {email['category']} | <b>Risk:</b> {email['risk_score']}/100 | <b>Level:</b> {email['risk_level']} | <b>Reviewed:</b> {'Yes' if email.get('reviewed') else 'No'} | <b>Quarantine:</b> {'Yes' if email.get('quarantined') else 'No'}</p>
    </div>
    """, unsafe_allow_html=True)

    tabs = st.tabs([
        "Summary",
        "Risk Explanation",
        "Authentication and MITRE",
        "IOCs and Threat Intel",
        "Attachments",
        "Review and Quarantine",
        "Timeline",
        "Raw Headers"
    ])

    with tabs[0]:
        c1, c2 = st.columns(2)
        with c1:
            st.write("Subject:", email["subject"])
            st.write("Sender:", email["sender"])
            st.write("Sender Email:", email["sender_email"])
            st.write("Recipient:", email["recipient"])
            st.write("Email Date:", email["email_date"])
            st.write("Source:", email["source"])
            st.write("Evidence File:")
            st.code(email["evidence_file"])
        with c2:
            st.metric("Category", email["category"])
            st.metric("Sub Tag", email["sub_tag"])
            st.metric("Risk Score", f"{email['risk_score']}/100")
            st.metric("Risk Level", email["risk_level"])

        st.info(email["main_reason"])
        explanation = generate_explanation(email, details["urls"], details["attachments"], details["iocs"])
        st.subheader("Plain Explanation")
        st.write(explanation)
        st.text_area("Email Body Preview", email["body_preview"], height=240)

    with tabs[1]:
        risk_details = safe_json_load(email.get("risk_details"), [])
        if risk_details:
            st.dataframe(pd.DataFrame(risk_details), use_container_width=True, hide_index=True)
        else:
            st.info("No detailed scoring records available. Reanalyze the email from Settings.")

    with tabs[2]:
        auth = safe_json_load(email.get("auth_result"), {})
        mitre = safe_json_load(email.get("mitre_results"), [])

        st.subheader("Email Authentication")
        if auth:
            st.json(auth)
        else:
            st.info("No authentication analysis available. Reanalyze the email.")

        st.subheader("MITRE ATT&CK Mapping")
        if mitre:
            st.dataframe(pd.DataFrame(mitre), use_container_width=True, hide_index=True)
        else:
            st.info("No MITRE mapping available.")

        ml = safe_json_load(email.get("ml_result"), {})
        st.subheader("ML Classifier Result")
        if ml:
            st.json(ml)
        else:
            st.info("No ML result available. Reanalyze the email.")

    with tabs[3]:
        st.subheader("IOCs")
        if details["iocs"]:
            ioc_df = pd.DataFrame(details["iocs"])
            st.dataframe(ioc_df, use_container_width=True, hide_index=True)
            dataframe_download("Download Case IOCs CSV", ioc_df, f"case_{email_id}_iocs.csv")
        else:
            st.info("No IOCs extracted.")

        st.subheader("VirusTotal Threat Intelligence")
        if is_vt_configured():
            st.success("VirusTotal API key configured.")
        else:
            st.warning("VirusTotal API key not configured. Add VIRUSTOTAL_API_KEY in .env to enable real lookups.")

        if st.button("Run Threat Intelligence for this Case", use_container_width=True):
            results = run_threat_intel_for_case(email_id, details)
            if results:
                st.dataframe(pd.DataFrame(results), use_container_width=True, hide_index=True)
            else:
                st.info("No supported IOCs found.")

        ti_results = get_threat_intel_results(email_id)
        if ti_results:
            st.write("Saved Threat Intelligence Results")
            st.dataframe(pd.DataFrame(ti_results), use_container_width=True, hide_index=True)

    with tabs[4]:
        if details["attachments"]:
            df = pd.DataFrame(details["attachments"])
            st.dataframe(df, use_container_width=True, hide_index=True)
            dataframe_download("Download Attachment Analysis CSV", df, f"case_{email_id}_attachments.csv")
        else:
            st.info("No attachments found.")

        if details["urls"]:
            st.subheader("URLs")
            df = pd.DataFrame(details["urls"])
            st.dataframe(df, use_container_width=True, hide_index=True)

    with tabs[5]:
        reviewed = st.checkbox("Mark as reviewed", value=bool(email.get("reviewed")), key=f"reviewed_{email_id}")
        quarantined = st.checkbox("Local quarantine", value=bool(email.get("quarantined")), key=f"quarantine_{email_id}")
        verdict_options = ["", "True Phishing", "False Positive", "Spam", "Marketing", "Safe", "Needs More Analysis"]
        current_verdict = email.get("final_verdict") or ""
        default_index = verdict_options.index(current_verdict) if current_verdict in verdict_options else 0
        final_verdict = st.selectbox("Final verdict", verdict_options, index=default_index, key=f"verdict_{email_id}")
        analyst_note = st.text_area("Analyst note", value=email.get("analyst_note") or "", height=130, key=f"note_{email_id}")

        if st.button("Save Review and Quarantine Status", use_container_width=True):
            update_review(email_id, reviewed, analyst_note, final_verdict)
            update_quarantine(email_id, quarantined)
            st.success("Saved.")
            st.rerun()

    with tabs[6]:
        timeline = get_timeline(email_id)
        if timeline:
            st.dataframe(pd.DataFrame(timeline), use_container_width=True, hide_index=True)
        else:
            st.info("No timeline events available.")

    with tabs[7]:
        st.code(email["raw_headers"])


st.markdown("""
<div class="hero">
    <h1>PhishGuard SOC Dashboard</h1>
    <p>Real-time mailbox monitoring, phishing detection, IOC extraction, MITRE mapping, ML scoring, authentication checks, threat intelligence, quarantine, and analyst workflow.</p>
</div>
""", unsafe_allow_html=True)


with st.sidebar:
    st.title("PhishGuard")

    page = st.radio(
        "Navigation",
        ["Command Center", "Intake", "Investigation", "Settings"]
    )

    st.divider()

    categories = ["All", "Phishing", "Spam", "Marketing", "Suspicious", "Safe", "High Risk", "Malware Attachment", "Quarantined"]
    st.session_state.filter = st.selectbox(
        "Category Filter",
        categories,
        index=categories.index(st.session_state.filter) if st.session_state.filter in categories else 0
    )

    review_filters = ["All", "Reviewed", "Unreviewed"]
    st.session_state.review_filter = st.selectbox(
        "Review Filter",
        review_filters,
        index=review_filters.index(st.session_state.review_filter) if st.session_state.review_filter in review_filters else 0
    )

    if st.button("Refresh"):
        st.rerun()


if page == "Command Center":
    counts = get_dashboard_counts()

    c1, c2, c3, c4 = st.columns(4)
    with c1:
        render_card("Total", counts["Total"], "All analyzed emails", "blue", "All")
    with c2:
        render_card("Phishing", counts["Phishing"], "Credential theft and fraud", "red", "Phishing")
    with c3:
        render_card("Suspicious", counts["Suspicious"], "Needs investigation", "purple", "Suspicious")
    with c4:
        render_card("Unreviewed", counts["Unreviewed"], "Pending analyst review", "pink", None)

    c5, c6, c7, c8 = st.columns(4)
    with c5:
        render_card("Spam", counts["Spam"], "Bulk unwanted emails", "orange", "Spam")
    with c6:
        render_card("Marketing", counts["Marketing"], "Promotions/newsletters", "green", "Marketing")
    with c7:
        render_card("Safe", counts["Safe"], "No major indicators", "teal", "Safe")
    with c8:
        render_card("Quarantined", counts["Quarantined"], "Locally quarantined cases", "slate", "Quarantined")

    st.subheader("Analytics")
    col1, col2 = st.columns(2)

    with col1:
        category_chart = pd.DataFrame({
            "Category": ["Phishing", "Spam", "Marketing", "Suspicious", "Safe"],
            "Count": [counts["Phishing"], counts["Spam"], counts["Marketing"], counts["Suspicious"], counts["Safe"]]
        })
        st.bar_chart(category_chart.set_index("Category"))

    with col2:
        ops_chart = pd.DataFrame({
            "Metric": ["High Risk", "Attachments", "IOCs", "Threat Intel", "Reviewed", "Unreviewed"],
            "Count": [counts["High Risk"], counts["Attachments"], counts["IOCs"], counts["Threat Intel"], counts["Reviewed"], counts["Unreviewed"]]
        })
        st.bar_chart(ops_chart.set_index("Metric"))

    st.divider()
    st.subheader("Cases")

    search_text = st.text_input("Search cases")
    emails = get_emails_by_category(st.session_state.filter, search_text, st.session_state.review_filter)

    if emails:
        df = pd.DataFrame(emails)
        st.dataframe(df, use_container_width=True, hide_index=True)
        dataframe_download("Download Case List CSV", df, "phishguard_cases.csv")

        options = {
            f"Case {email['id']} | {email['category']} | Score {email['risk_score']} | {email['subject']}": email["id"]
            for email in emails
        }
        selected_label = st.selectbox("Select a case for Investigation page", list(options.keys()))
        st.session_state.selected_email_id = options[selected_label]
    else:
        st.info("No matching cases found.")

    st.divider()
    st.subheader("Global Exports")
    export_tabs = st.tabs(["IOCs", "Attachments", "Threat Intelligence"])

    with export_tabs[0]:
        data = get_all_iocs()
        if data:
            df = pd.DataFrame(data)
            st.dataframe(df, use_container_width=True, hide_index=True)
            dataframe_download("Download All IOCs CSV", df, "phishguard_all_iocs.csv")
        else:
            st.info("No IOCs available.")

    with export_tabs[1]:
        data = get_all_attachments()
        if data:
            df = pd.DataFrame(data)
            st.dataframe(df, use_container_width=True, hide_index=True)
            dataframe_download("Download All Attachments CSV", df, "phishguard_all_attachments.csv")
        else:
            st.info("No attachments available.")

    with export_tabs[2]:
        data = get_all_threat_intel()
        if data:
            df = pd.DataFrame(data)
            st.dataframe(df, use_container_width=True, hide_index=True)
            dataframe_download("Download Threat Intelligence CSV", df, "phishguard_threat_intel.csv")
        else:
            st.info("No threat intelligence results saved yet.")


elif page == "Intake":
    st.header("Intake")
    intake_tabs = st.tabs(["Upload Email", "Live Mailbox"])

    with intake_tabs[0]:
        st.subheader("Upload .eml File")
        uploaded_file = st.file_uploader("Upload email file", type=["eml"])

        if uploaded_file is not None:
            st.write("File:", uploaded_file.name)
            st.write("Size:", uploaded_file.size, "bytes")

            if st.button("Analyze and Save Email", use_container_width=True):
                raw_bytes = uploaded_file.read()
                evidence_file = save_evidence_file(raw_bytes, uploaded_file.name)
                email_data = parse_eml_bytes(raw_bytes)
                classification = classify_email(email_data)

                save_result = save_email(
                    email_data=email_data,
                    classification=classification,
                    evidence_file=evidence_file,
                    source="Manual Upload"
                )

                if save_result["inserted"]:
                    st.success(f"Email saved. Case ID: {save_result['email_id']}")
                else:
                    st.warning(f"Duplicate email. Existing Case ID: {save_result['email_id']}")

                a, b, c = st.columns(3)
                a.metric("Category", classification["category"])
                b.metric("Risk Score", f"{classification['risk_score']}/100")
                c.metric("Risk Level", classification["risk_level"])
                st.info(classification["main_reason"])

    with intake_tabs[1]:
        st.subheader("Live Mailbox Monitor")
        config = get_imap_config()

        if is_mailbox_configured():
            st.success("Mailbox configuration found.")
            st.write("IMAP Server:", config["server"])
            st.write("User:", config["user"])
            st.write("Folder:", config["folder"])
            st.write("Gmail label automation:", "Enabled" if config["apply_gmail_labels"] else "Disabled")
        else:
            st.error("Mailbox not configured. Update .env with Gmail App Password.")

        st.warning("Use only your own mailbox or an authorized lab mailbox.")

        col1, col2, col3 = st.columns(3)
        with col1:
            mark_as_read = st.checkbox("Mark fetched emails as read", value=True)
        with col2:
            max_emails = st.number_input("Max unread emails per fetch", min_value=1, max_value=100, value=25)
        with col3:
            auto_monitor = st.checkbox("Auto monitor every 60 seconds", value=False)

        if auto_monitor:
            st_autorefresh(interval=60000, key="mailbox_auto_refresh")
            st.info("Auto monitor is enabled while this page is open.")

        if st.button("Fetch Unread Emails Now", use_container_width=True) or auto_monitor:
            try:
                results = fetch_unread_emails(mark_as_read=mark_as_read, max_emails=int(max_emails))
                if results:
                    st.success(f"Fetched {len(results)} email(s).")
                    st.dataframe(pd.DataFrame(results), use_container_width=True, hide_index=True)
                else:
                    st.info("No unread emails found.")
            except Exception as error:
                st.error(f"Mailbox error: {error}")


elif page == "Investigation":
    st.header("Investigation")
    emails = get_emails_by_category(st.session_state.filter, "", st.session_state.review_filter)

    if not emails:
        st.info("No emails available.")
    else:
        options = {
            f"Case {email['id']} | {email['category']} | Score {email['risk_score']} | {email['subject']}": email["id"]
            for email in emails
        }

        labels = list(options.keys())
        default_index = 0

        if st.session_state.selected_email_id:
            for idx, label in enumerate(labels):
                if options[label] == st.session_state.selected_email_id:
                    default_index = idx
                    break

        selected_label = st.selectbox("Select case", labels, index=default_index)
        render_email_details(options[selected_label])


elif page == "Settings":
    st.header("Settings")
    settings_tabs = st.tabs(["Rules", "Reanalysis", "Configuration", "Danger Zone"])

    with settings_tabs[0]:
        st.subheader("Trusted and Blocked Domains")
        st.write("Trusted domains reduce false positives. Blocked domains force higher risk.")

        trusted = get_trusted_domains()
        blocked = get_blocked_domains()

        col1, col2 = st.columns(2)

        with col1:
            st.subheader("Trusted Domains")
            new_trusted = st.text_input("Add trusted domain", placeholder="example.com")
            if st.button("Add Trusted Domain", use_container_width=True):
                added = add_trusted_domain(new_trusted)
                if added:
                    st.success(f"Added trusted domain: {added}")
                    st.rerun()

            st.dataframe(pd.DataFrame({"trusted_domains": trusted}), use_container_width=True, hide_index=True)
            remove_t = st.selectbox("Remove trusted domain", [""] + trusted)
            if st.button("Remove Selected Trusted Domain", use_container_width=True):
                if remove_t:
                    remove_trusted_domain(remove_t)
                    st.success(f"Removed: {remove_t}")
                    st.rerun()

        with col2:
            st.subheader("Blocked Domains")
            new_blocked = st.text_input("Add blocked domain", placeholder="bad-example.com")
            if st.button("Add Blocked Domain", use_container_width=True):
                added = add_blocked_domain(new_blocked)
                if added:
                    st.success(f"Added blocked domain: {added}")
                    st.rerun()

            st.dataframe(pd.DataFrame({"blocked_domains": blocked}), use_container_width=True, hide_index=True)
            remove_b = st.selectbox("Remove blocked domain", [""] + blocked)
            if st.button("Remove Selected Blocked Domain", use_container_width=True):
                if remove_b:
                    remove_blocked_domain(remove_b)
                    st.success(f"Removed: {remove_b}")
                    st.rerun()

    with settings_tabs[1]:
        st.subheader("Reanalyze Existing Emails")
        st.warning("This re-runs classification on saved evidence files using current rules and improved logic.")

        if st.button("Reanalyze All Saved Emails", use_container_width=True):
            rows = get_all_evidence_files()
            updated = 0
            skipped = 0

            for row in rows:
                path = row.get("evidence_file", "")
                email_id = row.get("id")

                if not path or not os.path.exists(path):
                    skipped += 1
                    continue

                try:
                    with open(path, "rb") as f:
                        raw_bytes = f.read()
                    email_data = parse_eml_bytes(raw_bytes)
                    classification = classify_email(email_data)
                    replace_email_analysis(email_id, email_data, classification)
                    updated += 1
                except Exception:
                    skipped += 1

            st.success(f"Reanalysis complete. Updated: {updated}, skipped: {skipped}")

    with settings_tabs[2]:
        st.subheader("Configuration")
        st.write("Edit `.env` in your phishguard folder for API keys and options.")

        st.code("""
IMAP_SERVER=imap.gmail.com
IMAP_PORT=993
IMAP_USER=vitladurgaprasadofficial@gmail.com
IMAP_PASSWORD=YOUR_16_CHARACTER_GMAIL_APP_PASSWORD
IMAP_FOLDER=INBOX

VIRUSTOTAL_API_KEY=PASTE_API_KEY_HERE
APPLY_GMAIL_LABELS=false

APP_LOGIN_ENABLED=false
APP_USERNAME=admin
APP_PASSWORD=phishguard123
""")

        st.write("Current feature status:")
        st.write("VirusTotal:", "Configured" if is_vt_configured() else "Not configured")
        st.write("Mailbox:", "Configured" if is_mailbox_configured() else "Not configured")

    with settings_tabs[3]:
        st.subheader("Danger Zone")
        st.warning("This deletes database records only. It does not delete saved evidence files.")

        confirm = st.checkbox("I understand. Delete all database records.")
        if confirm:
            if st.button("Clear Database"):
                clear_database()
                st.success("Database cleared.")
                st.rerun()


