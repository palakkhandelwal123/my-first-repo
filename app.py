# app.py
import re
import os
import requests
from urllib.parse import urlparse
import streamlit as st

# ---------------- Page Config ----------------
st.set_page_config(page_title="PhishGuard - Automatic URL Checker", layout="wide")

# ---------------- Helper functions ----------------

def extract_urls(text: str):
    """
    Regex-based URL extractor that finds:
      - explicit http/https links
      - bare domains like example.com or sub.example.co.in
    Returns unique list preserving order.
    """
    if not text:
        return []
    text = text.replace("\n", " ")
    # capture http/https links and bare domains
    pattern = r"(https?://[^\s,<>\)]+|(?:[A-Za-z0-9\-]+\.)+[A-Za-z]{2,}(?:/[^\s,<>\)]*)?)"
    matches = re.findall(pattern, text)
    seen = set()
    urls = []
    for m in matches:
        u = m.strip().rstrip('.,;:')  # strip punctuation around urls
        if u not in seen:
            seen.add(u)
            urls.append(u)
    return urls

def normalize_url(u: str):
    """
    Ensure URL has scheme. If bare domain given, prepend http:// for parsing only.
    Returns parsed components and a normalized url string.
    """
    if not u.startswith("http://") and not u.startswith("https://"):
        u_norm = "http://" + u
    else:
        u_norm = u
    parsed = urlparse(u_norm)
    domain = parsed.hostname or ""
    path = parsed.path or ""
    return u_norm, domain.lower(), path

SUSPICIOUS_TLDS = {".xyz", ".top", ".io", ".club", ".online", ".site", ".pw"}
SUSPICIOUS_KEYWORDS = {"login", "verify", "secure", "update", "account", "confirm", "bank", "password"}

def basic_url_risk_score(u: str):
    """
    Simple heuristic/rule-based scoring for a single URL.
    Returns (score_increment:int, reasons:list[str])
    """
    reasons = []
    score = 0
    u_norm, domain, path = normalize_url(u)

    # 1) suspicious TLD check
    for tld in SUSPICIOUS_TLDS:
        if domain.endswith(tld):
            reasons.append(f"🚨 Suspicious TLD '{tld}' in domain: {domain}")
            score += 20
            break

    # 2) suspicious keywords in domain/path
    for kw in SUSPICIOUS_KEYWORDS:
        if kw in domain or kw in path:
            reasons.append(f"⚠️ Suspicious keyword '{kw}' found in URL: {u}")
            score += 15

    # 3) IP address in domain (rare for legit websites)
    if re.match(r"^\d{1,3}(\.\d{1,3}){3}$", domain):
        reasons.append(f"⚠️ Domain is an IP address: {domain}")
        score += 20

    # 4) punycode (IDN trick) — "xn--" indicates punycode
    if domain.startswith("xn--") or "xn--" in domain:
        reasons.append("⚠️ Domain uses punycode (possible homograph attack).")
        score += 20

    # 5) long subdomain chains (e.g., account.google.example.com)
    if domain.count(".") >= 3:
        reasons.append("🔍 Long subdomain chain — may be deceptive.")
        score += 5

    # cap each url's contribution to 60 to avoid overpowering whole score
    score = min(score, 60)
    return score, reasons

# ---------------- Optional VirusTotal (or other) reputation check ----------------
def vt_url_report(url: str, api_key: str):
    """
    Query VirusTotal v3 URL report.
    Returns a tuple (success:bool, verdict:str or None, details: str or None)
    Note: requires VT API key in environment or user input. This is optional.
    """
    headers = {"x-apikey": api_key}
    # VirusTotal v3 requires submitting the URL to be hashed first;
    # but they accept /urls endpoint - we need to URL-encode and submit.
    try:
        submit_resp = requests.post("https://www.virustotal.com/api/v3/urls",
                                    headers=headers,
                                    data={"url": url},
                                    timeout=10)
        if submit_resp.status_code not in (200, 201):
            return False, None, f"VT submit error: {submit_resp.status_code}"
        data = submit_resp.json()
        # data['data']['id'] is the encoded id — use it to fetch analysis
        url_id = data["data"]["id"]
        fetch_resp = requests.get(f"https://www.virustotal.com/api/v3/analyses/{url_id}",
                                  headers=headers, timeout=10)
        if fetch_resp.status_code != 200:
            return False, None, f"VT fetch error: {fetch_resp.status_code}"
        analysis = fetch_resp.json()
        # check stats if available
        stats = analysis.get("data", {}).get("attributes", {}).get("stats", {})
        malicious = stats.get("malicious", 0)
        suspicious = stats.get("suspicious", 0)
        if malicious > 0 or suspicious > 0:
            verdict = "malicious"
        elif malicious == 0 and suspicious == 0:
            verdict = "clean"
        else:
            verdict = "unknown"
        details = f"VT stats: malicious={malicious}, suspicious={suspicious}"
        return True, verdict, details
    except Exception as e:
        return False, None, f"VT error: {e}"

# ---------------- Phishing check function (extended) ----------------
def check_phishing(subject: str, body: str, sender: str = "", use_vt=False, vt_api_key=""):
    text = (subject or "") + " " + (body or "")
    text_lower = text.lower()
    score = 0
    reasons = []

    # 1) Suspicious keywords in subject/body
    suspicious_words = ["urgent", "verify", "login", "password", "bank", "account", "update", "click", "confirm"]
    found_words = [w for w in suspicious_words if w in text_lower]
    if found_words:
        reasons.append(f"⚠️ Found suspicious words: {', '.join(found_words)}")
        score += len(found_words) * 8

    # 2) Sender heuristics (generic / mismatched domain)
    if sender:
        s = sender.lower()
        if any(x in s for x in ["no-reply", "noreply", "support@", "help@", "info@"]):
            reasons.append(f"📩 Sender looks generic: {sender}")
            score += 8
        # check if sender domain is suspicious (if present)
        try:
            sender_domain = s.split("@", 1)[1]
            for tld in SUSPICIOUS_TLDS:
                if sender_domain.endswith(tld):
                    reasons.append(f"📛 Sender domain suspicious TLD: {sender_domain}")
                    score += 10
                    break
        except Exception:
            pass

    # 3) Extract & analyze URLs automatically
    urls = extract_urls(text)
    if urls:
        reasons.append(f"🔗 Found links: {', '.join(urls[:5])}")
        score += 10
        for u in urls:
            add_score, u_reasons = basic_url_risk_score(u)
            score += add_score
            for r in u_reasons:
                reasons.append(r)

            # Optional: call VirusTotal if user requested and provided key
            if use_vt and vt_api_key:
                ok, verdict, details = vt_url_report(u, vt_api_key)
                if ok:
                    if verdict == "malicious":
                        reasons.append(f"🚨 VirusTotal reports MALICIOUS for {u} ({details})")
                        score += 40
                    elif verdict == "clean":
                        reasons.append(f"✅ VirusTotal: no detections for {u}.")
                        score -= 5  # reduce small amount if clean
                else:
                    reasons.append(f"ℹ️ VirusTotal check failed for {u}: {details}")

    # final score bounds
    score = max(0, min(score, 100))
    return score, list(dict.fromkeys(reasons))  # remove duplicate reasons preserving order

# ---------------- Streamlit UI ----------------
st.markdown("<h1 style='text-align:center; color:#00FF00;'>🛡️ PhishGuard</h1>", unsafe_allow_html=True)
st.markdown("<h4 style='text-align:center; color:#00FF88;'>Automatic URL extraction & phishing checker</h4>", unsafe_allow_html=True)
st.markdown("---")

with st.form("email_form"):
    sender = st.text_input("Sender Email (optional)", help="जैसे: no-reply@bank.com")
    subject = st.text_input("Email Subject", help="मेल का subject")
    body = st.text_area("Email Body", height=220, help="पूरा ईमेल यहाँ पेस्ट करो (headers डालो अगर हैं)")
    use_vt = st.checkbox("Use VirusTotal URL reputation check (optional)", value=False)
    vt_api_key = ""
    if use_vt:
        vt_api_key = st.text_input("VirusTotal API Key (paste here)", type="password",
                                   help="यदि आप VirusTotal API key नहीं देना चाहते तो छोड़ दें — करेंट run local heuristics ही काम करेंगे.")
    submitted = st.form_submit_button("🔍 Analyze Email")

if submitted:
    if not subject and not body:
        st.warning("कृपया subject या body डालें।")
    else:
        with st.spinner("Analyzing..."):
            score, reasons = check_phishing(subject, body, sender, use_vt=use_vt, vt_api_key=vt_api_key)
        # Result card
        if score >= 70:
            color = "#FF4B4B"
            status = "🚨 High Risk Phishing Email"
            st.balloons()
        elif score >= 40:
            color = "#FFA500"
            status = "⚠️ Potential Phishing Email"
        else:
            color = "#32CD32"
            status = "✅ Email looks Legitimate"

        st.markdown(f"""
            <div style='background-color:#1e1e1e; padding:20px; border-radius:10px; border-left:10px solid {color}; text-align:center;'>
                <h3 style='color:{color}; margin:0'>{status} ({score}/100)</h3>
            </div>
            """, unsafe_allow_html=True)

        # Gradient progress bar
        st.markdown(f"""
        <div style='background-color:#333333; border-radius:10px; height:20px; margin-top:10px;'>
            <div style='width:{score}%; background: linear-gradient(90deg, #00FF00, #00FFFF); height:20px; border-radius:10px;'></div>
        </div>
        """, unsafe_allow_html=True)

        # Reasons
        with st.expander("🔍 Why this result?"):
            if reasons:
                for r in reasons:
                    st.write(r)
            else:
                st.write("No suspicious elements found!")

        # Show extracted URLs in a table-like way
        urls = extract_urls((subject or "") + " " + (body or ""))
        if urls:
            st.markdown("**Extracted URLs:**")
            for i, u in enumerate(urls, 1):
                st.write(f"{i}. {u}")

st.markdown("---")
st.markdown("<div style='text-align:center; color:#00FF88;'>Made by Team - Error420</div>", unsafe_allow_html=True)
