#!/usr/bin/env python3
# email_phish_cli.py
import imaplib
import email
from email.header import decode_header
import getpass
import re
import sys

# ---------------- Phishing checker (simple heuristics) ----------------
def check_phishing(subject, body, sender=""):
    text = (subject + " " + body).lower()
    score = 0
    reasons = []

    suspicious_words = ["urgent", "verify", "login", "password", "bank", "account", "update", "click", "confirm"]
    found_words = [w for w in suspicious_words if w in text]
    if found_words:
        reasons.append(f"Found suspicious words: {', '.join(found_words)}")
        score += len(found_words) * 10

    urls = re.findall(r"(https?://[^\s]+|[A-Za-z0-9.-]+\.[A-Za-z]{2,})", text)
    if urls:
        reasons.append(f"Found links: {', '.join(urls[:3])}")
        score += 20
        for u in urls:
            if any(ext in u for ext in [".xyz", ".top", ".io", "login", "secure", "verify"]):
                reasons.append(f"Suspicious link: {u}")
                score += 15

    if sender and any(x in sender.lower() for x in ["no-reply", "support@", "noreply", "help@", "info@"]):
        reasons.append(f"Sender looks generic: {sender}")
        score += 5

    score = min(score, 100)
    return score, reasons

# ---------------- Helpers to decode headers and extract body ----------------
def decode_mime_words(s):
    if not s:
        return ""
    parts = decode_header(s)
    decoded = ""
    for part, enc in parts:
        if isinstance(part, bytes):
            try:
                decoded += part.decode(enc or "utf-8", errors="ignore")
            except:
                decoded += part.decode("utf-8", errors="ignore")
        else:
            decoded += part
    return decoded

def get_body_from_msg(msg):
    if msg.is_multipart():
        # prefer text/plain
        for part in msg.walk():
            ctype = part.get_content_type()
            disp = str(part.get("Content-Disposition"))
            if ctype == "text/plain" and "attachment" not in disp:
                try:
                    return part.get_payload(decode=True).decode(part.get_content_charset() or "utf-8", errors="ignore")
                except:
                    return part.get_payload(decode=True).decode("utf-8", errors="ignore")
        # fallback to first text part
        for part in msg.walk():
            if part.get_content_type().startswith("text/"):
                try:
                    return part.get_payload(decode=True).decode(part.get_content_charset() or "utf-8", errors="ignore")
                except:
                    return part.get_payload(decode=True).decode("utf-8", errors="ignore")
        return ""
    else:
        try:
            return msg.get_payload(decode=True).decode(msg.get_content_charset() or "utf-8", errors="ignore")
        except:
            return msg.get_payload(decode=True).decode("utf-8", errors="ignore")

# ---------------- Fetch emails via IMAP ----------------
def fetch_emails(host, username, password, folder="INBOX", limit=10, ssl=True):
    mails = []
    try:
        if ssl:
            M = imaplib.IMAP4_SSL(host)
        else:
            M = imaplib.IMAP4(host)
        M.login(username, password)
    except Exception as e:
        print("Failed to connect/login:", e)
        return mails

    try:
        M.select(folder)
        typ, data = M.search(None, "ALL")
        if typ != "OK":
            print("Failed to search mailbox:", typ)
            return mails
        id_list = data[0].split()
        if not id_list:
            return mails
        # take last 'limit' ids
        recent_ids = id_list[-limit:]
        for eid in reversed(recent_ids):
            typ, msg_data = M.fetch(eid, "(RFC822)")
            if typ != "OK":
                continue
            raw = msg_data[0][1]
            msg = email.message_from_bytes(raw)
            subj = decode_mime_words(msg.get("Subject", ""))
            frm = decode_mime_words(msg.get("From", ""))
            date = msg.get("Date", "")
            body = get_body_from_msg(msg) or ""
            mails.append({
                "id": eid.decode() if isinstance(eid, bytes) else str(eid),
                "subject": subj,
                "from": frm,
                "date": date,
                "body": body
            })
    finally:
        try:
            M.logout()
        except:
            pass

    return mails

# ---------------- CLI UI ----------------
def main():
    print("=== Simple Email Phishing CLI ===")
    host = input("IMAP Host (e.g. imap.gmail.com): ").strip() or "imap.gmail.com"
    user = input("Email (username): ").strip()
    if not user:
        print("Email required. Exiting.")
        return
    pwd = getpass.getpass("Password or App Password (input hidden): ")

    try:
        limit = int(input("How many recent emails to fetch (default 10): ") or "10")
    except:
        limit = 10

    print("\nConnecting... (this uses IMAP and keeps credentials locally on your machine)\n")
    mails = fetch_emails(host, user, pwd, limit=limit)
    if not mails:
        print("No emails fetched (or failed). Check credentials / IMAP settings.")
        return

    # show list
    print(f"\nFetched {len(mails)} emails:\n")
    for i, m in enumerate(mails, 1):
        subj = (m['subject'][:80] + "..") if len(m['subject'])>80 else m['subject']
        frm = m['from']
        date = m['date']
        print(f"[{i}] {subj}\n     From: {frm}\n     Date: {date}\n")

    while True:
        choice = input("Enter email number to analyze (or 'q' to quit): ").strip().lower()
        if choice in ("q", "quit", "exit"):
            print("Goodbye.")
            break
        if not choice.isdigit():
            print("Enter a valid number.")
            continue
        idx = int(choice) - 1
        if idx < 0 or idx >= len(mails):
            print("Number out of range.")
            continue

        sel = mails[idx]
        subject = sel['subject']
        sender = sel['from']
        body = sel['body']
        snippet = (body[:800] + "...") if len(body) > 800 else body

        score, reasons = check_phishing(subject, body, sender)
        print("\n--- Analysis Result ---")
        print("Subject:", subject)
        print("From:", sender)
        print("Date:", sel['date'])
        print("Score:", score, "/100")
        if score >= 70:
            print("=> HIGH RISK (Likely phishing)")
        elif score >= 40:
            print("=> POTENTIAL PHISHING")
        else:
            print("=> Likely Legitimate")
        print("\nReasons:")
        if reasons:
            for r in reasons:
                print(" -", r)
        else:
            print(" - No suspicious cues found.")
        print("\nBody preview:\n")
        print(snippet)
        print("\n------------------------\n")

if _name_ == "_main_":
    try:
        main()
    except KeyboardInterrupt:
        print("\nInterrupted. Exiting.")
        sys.exit(0)
