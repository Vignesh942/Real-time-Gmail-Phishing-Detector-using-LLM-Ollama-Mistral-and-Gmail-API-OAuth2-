# Real time Gmail Phishing Detector (Ollama Mistral + Gmail API OAuth2)

**A privacy Gmail phishing detector** that runs fully on your local system  no data leaves your computer.  
It monitors your Gmail inbox in real-time, scans unread emails, and uses both **smart rules** and **local AI (LLM)** to detect phishing attempts quickly and accurately.

---

##  Overview

This project automatically checks your Gmail for new unread emails and flags any suspicious ones as **phishing**.  
It uses a mix of:

- **Local AI (Ollama + Dolphin-Mistral)**  for deeper understanding and context.
- **Heuristics** —simple checks for bad links, urgent language, or strange senders.

If an email looks dangerous, it can:
- Move it to Trash or apply a special label (like ⚠️Phishing-Alert).  
- Mark safe emails as ✓-Verified-Safe.  
- Log all details locally for later review.

Everything runs offline after setup  **no cloud services** or data sharing.

---

## Tech Stack

- **Language:** Python 3.8+
- **Email Access:** Gmail API (OAuth2, secure)
- **AI Engine:** Ollama (Dolphin-Mistral model)
- **Data Handling:** Pandas, JSON, Pickle
- **Utilities:** `email`, `re`, `base64`, `win10toast` for notifications
---

## Features

###  Hybrid Detection
- **Heuristics:** Finds risky URLs, urgent words, password requests, or misspellings.
- **AI Analysis:** Uses the local LLM for smarter decisions (like “This looks like a fake Gmail warning”).

### Real-Time Monitoring
- Checks for new unread emails every 20 seconds.
- Processes one email at a time (avoids rate limits).

###  Automated Actions
- Labels emails as `⚠️-Phishing-Alert`, `✓-Verified-Safe`, or `Processed-By-Ollama`.
- Optionally deletes phishing emails automatically.
- Maintains whitelist and blacklist (trusted or blocked senders).

###  Privacy & Security
- 100% local — no email data leaves your computer.
- Uses Google OAuth2 for secure login.
- Detects advanced tricks like lookalike domains and fake URLs.

###  Logging & Stats
- Saves every result to a CSV log.
- Tracks accuracy, detection rate, and daily stats.
- Lets you review false positives and improve detection later.

---

##  How It Works

1. **Setup**
   - Log in with Gmail (OAuth2) once.
   - Automatically creates labels and loads whitelist/blacklist.
   - Starts Ollama AI and logging system.

2. **Email Scanning**
   - Fetches the newest unread email.
   - Parses sender, subject, and body.

3. **Detection Pipeline**
   - Checks if the sender is in whitelist/blacklist.
   - Runs heuristic scan → gives a risk score (0–1).
   - If score ≥ 0.08 → sends email data to Ollama for AI verdict.
   - Combines both results for a final decision.

4. **Post Actions**
   - Adds labels or moves phishing emails to Trash.
   - Logs everything and shows color-coded output in the terminal.
   - Optionally sends desktop notifications.

5. **Exit**
   - Graceful shutdown with final stats summary.
   - (Optional) Generates daily report with accuracy and trends.
  
<img width="900" height="660" alt="Real-time Gmail Phishing Detection using LLM (Ollama Mistral + Gmail API OAuth2) - visual selection" src="https://github.com/user-attachments/assets/7d9adfa1-811f-4dfc-a796-db282ba19c7a" />

---

##  Why Use This

Gmail’s default filters can miss modern phishing tricks.  
This tool gives you **control, transparency, and privacy** — powered by **local AI** that never uploads your emails anywhere.

Perfect for developers, security enthusiasts, how wants privacy.

## Check out the Demo for more Information!!
---


