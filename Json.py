{
  "CREDENTIALS_FILE": "Yourcredentials.json_name",
  "TOKEN_FILE": "token.pickle",
  "SCOPES": [
    "https://www.googleapis.com/auth/gmail.modify",
    "https://www.googleapis.com/auth/gmail.labels"
  ],
  "OLLAMA_MODEL": "dolphin-mistral",
  "LOG_CSV": "gmail_phish_log.csv",
  "PROCESSED_LABEL": "Processed-By-Ollama",
  "PHISHING_LABEL": "⚠️-Phishing-Alert",
  "SAFE_LABEL": "✓-Verified-Safe",
  "POLL_INTERVAL_SECS": 20,
  "HEURISTIC_THRESHOLD": 0.5,
  "LLM_SKIP_THRESHOLD": 0.08,
  "AUTO_QUARANTINE": true,
  "WHITELIST_FILE": "trusted_senders.txt",
  "BLACKLIST_FILE": "blocked_senders.txt",
  "STATS_FILE": "detection_stats.json",
  "ENABLE_NOTIFICATIONS": false,
  "ENABLE_EMAIL_REPORTS": false,
  "REPORT_EMAIL": "your-email@gmail.com",
  "ENABLE_LEARNING": true,
  "TRAINING_DATA_FILE": "training_data.csv",
  "URL_PATTERN": "https?://[^\\s<>\"'\\)]+|www\\.[^\\s<>\"'\\)]+",
  "URGENT_KEYWORDS": [
    "urgent",
    "immediately",
    "asap",
    "suspend",
    "suspended",
    "verify",
    "verify your",
    "click here",
    "update",
    "expired",
    "act now",
    "confirm",
    "secure your account"
  ],
  "SENSITIVE_INFO_KEYWORDS": [
    "password",
    "account number",
    "ssn",
    "social security",
    "card",
    "cvv",
    "pin",
    "bank details",
    "credit card"
  ],
  "PHISHING_INDICATORS": [
    "phish",
    "suspicious",
    "malicious",
    "scam",
    "fraud",
    "fake"
  ],
  "SAFE_INDICATORS": [
    "legitimate",
    "safe",
    "authentic",
    "genuine",
    "valid"
  ],
  "MAX_RETRIES": 3,
  "RETRY_DELAY": 2
}
