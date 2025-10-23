#  Gmail Ollama Phishing Detector  
### Real-time Gmail Phishing Detection using LLM (Ollama Mistral + Gmail API OAuth2)

> ⚡ A **local, privacy-first phishing detector** that connects to Gmail using OAuth2, scans unread emails, and classifies them as **Safe** or **Phishing** using a hybrid of **Heuristic + Local LLM (Ollama Mistral)**.

---

##  Features

- 📥 Fetches the **latest unread email** from Gmail (Primary tab)  
- ⚙️ **Heuristic pre-checks** to avoid unnecessary LLM calls  
- 🤖 **Local AI inference** using **Ollama + Dolphin-Mistral**  
- 📨 Automatically labels processed emails (`Processed-By-Ollama`)  
- 🧾 Logs all detections in `gmail_phish_log.csv`  
- 🔒 **Fully offline** – no cloud or third-party API calls  

---

##  Tech Stack

| Component | Technology |
|------------|-------------|
| Language | Python 3.10+ |
| AI Model | Ollama (Dolphin-Mistral) |
| API | Gmail API (OAuth 2.0) |
| Libraries | `google-api-python-client`, `ollama`, `pandas`, `re`, `email` |

---

##  How It Works

1. Authenticate your Gmail via OAuth2  
2. Fetch the latest unread message from the **Primary tab**  
3. Parse subject, sender, and email body  
4. Run **heuristic checks** (keywords, URLs, urgency, tone)  
5. If suspicious → send summary to **Ollama Mistral** for LLM analysis  
6. Combine both results → 🟢 *Safe* or 🔴 *Phishing*  
7. Mark processed emails and log everything into `gmail_phish_log.csv`  

---

## 🧾 Example Output

