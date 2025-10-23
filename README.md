# Real-time-Gmail-Phishing-Detector-using-LLM-Ollama-Mistral-and-Gmail-API-OAuth2-

# Gmail Ollama Phishing Detector

**Gmail Ollama Phishing Detector** — a local, privacy-preserving phishing detection that integrates Gmail (via API) with a local LLM (`dolphin-mistral`) running through Ollama.  
it reads the latest Primary unread email, runs fast heuristics, queries the LLM only when suspicious, and logs results.

> ⚠️ **Security note:** This repo contains no credentials. Do **not** commit `credentials.json` or `token.pickle`. Use `credentials.example.json` as a template.

---

## Features
- Fetches the **latest unread email from Gmail Primary** tab (OAuth)
- Fast **heuristic short-circuit** to avoid unnecessary LLM calls
- Local LLM inference using **Ollama + dolphin-mistral** (no cloud API keys)
- Marks processed emails (removes `UNREAD`, adds label)
- CSV logging for analysis
- Demo-friendly: quick setup for recruiters/interviewers

---
## Tech Stack
-Python 3.10+
-Ollama (running Mistral or Dolphin-Mistral model)
-Google Gmail API (OAuth 2.0)
-Pandas for structured logging
-Regex-based heuristic engine
