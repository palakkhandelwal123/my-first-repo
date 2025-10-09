import re
import streamlit as st

# ---- Page Config ----
st.set_page_config(page_title="🛡️ PhishGuard - Simple Phishing Detector", layout="wide")

# ---- Header ----
st.markdown("""
<div style='
    text-align:center;
    padding:20px;
    border-radius:10px;
    background: linear-gradient(90deg, #00FF00, #00FFFF);
    color:#000000;
    font-family:sans-serif;
'>
    <h1>🛡️ PhishGuard</h1>
    <h4>Simple Phishing Email Detector</h4>
    <h6>Team Members: Yuvraj Tyagi, Shivam, Palak Khandelwal, Palak Agrawal</h6>
</div>
""", unsafe_allow_html=True)

st.markdown("---")

# ---- Centered Input Section ----
st.markdown("<h4 style='text-align:center; color:#00FF88;'>Enter Email Details</h4>", unsafe_allow_html=True)

sender = st.text_input("📧 Sender Email (optional)")
subject = st.text_input("✉️ Email Subject")
body = st.text_area("📝 Email Body", height=200)
analyze_btn = st.button("🔍 Analyze Email")

# ---- Phishing Detection Function ----
def check_phishing(subject, body, sender=""):
    text = (subject + " " + body).lower()
    score = 0
    reasons = []

    # Suspicious words
    suspicious_words = ["urgent", "verify", "login", "password", "bank", "account", "update", "click", "confirm"]
    found_words = [w for w in suspicious_words if w in text]
    if found_words:
        reasons.append(f"⚠️ Found suspicious words: {', '.join(found_words)}")
        score += len(found_words) * 10

    # URLs
    urls = re.findall(r"(https?://[^\s]+|[A-Za-z0-9.-]+\.[A-Za-z]{2,})", text)
    if urls:
        reasons.append(f"🔗 Found links: {', '.join(urls[:3])}")
        score += 20
        for u in urls:
            if any(ext in u for ext in [".xyz", ".top", ".io", "login", "secure", "verify"]):
                reasons.append(f"🚨 Suspicious link: {u}")
                score += 15

    # Generic sender
    if sender and any(x in sender.lower() for x in ["no-reply", "support@", "noreply", "help@", "info@"]):
        reasons.append(f"📩 Sender looks generic: {sender}")
        score += 5

    score = min(score, 100)
    return score, reasons

# ---- Analyze Button Logic ----
if analyze_btn:
    if not subject and not body:
        st.warning("Please enter email subject or body.")
    else:
        score, reasons = check_phishing(subject, body, sender)

        # ---- Result Card ----
        if score >= 70:
            color = "#FF4B4B"
            status = "⚠️ High Risk Phishing Email"
            st.balloons()
        elif score >= 40:
            color = "#FFA500"
            status = "⚠️ Potential Phishing Email"
        else:
            color = "#32CD32"
            status = "✅ Email looks Legitimate"

        st.markdown(f"""
            <div style='
                background-color:#1e1e1e;
                padding:20px;
                border-radius:10px;
                border-left:10px solid {color};
                text-align:center;
                font-family:sans-serif;
            '>
                <h3 style='color:{color}'>{status} ({score}/100)</h3>
            </div>
        """, unsafe_allow_html=True)

        # ---- Gradient Progress Bar ----
        st.markdown(f"""
        <div style='
            background-color:#333333;
            border-radius:10px;
            height:25px;
            margin-top:10px;
        '>
            <div style='
                width:{score}%;
                background: linear-gradient(90deg, #00FF00, #00FFFF);
                height:25px;
                border-radius:10px;
            '></div>
        </div>
        """, unsafe_allow_html=True)

        # ---- Reasons Section ----
        with st.expander("🔍 Why this result?"):
            if reasons:
                for r in reasons:
                    st.write(r)
            else:
                st.write("No suspicious elements found!")

# ---- Footer ----
st.markdown("---")
st.markdown("""
<div style='text-align:center; color:#00FF00; margin-top:20px; font-family:sans-serif;'>
    <strong>Made by Team - Error420</strong><br>
    Team Members: Yuvraj Tyagi, Shivam, Palak Khandelwal, Palak Agrawal
</div>
""", unsafe_allow_html=True)

st.info("🧠 Note: Beginner-friendly prototype. Future improvements: AI-based analysis, metadata checks, advanced phishing detection.")
