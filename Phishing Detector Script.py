




"""
Gmail Phishing Detection Daemon 
Modify the script according to your needs
Note : Most of this script is created by multiple LLM's 
"""

import os
import time
import base64
import re
import pickle
import json
import sys
import platform
from email import message_from_bytes
from typing import Tuple, Dict, List, Optional, Set
from dataclasses import dataclass, asdict
from datetime import datetime, timedelta
from collections import defaultdict

import pandas as pd  
from googleapiclient.discovery import build
from google_auth_oauthlib.flow import InstalledAppFlow
from google.auth.transport.requests import Request
from google.auth.exceptions import RefreshError  # Added for token refresh errors
from ollama import Client


# ============================================================================
# CONFIGURATION
# ============================================================================

class Config:
    """Application configuration"""
    CREDENTIALS_FILE = "Yourcredentials.json_name"
    TOKEN_FILE = "token.pickle"
    SCOPES = [""]
    
    OLLAMA_MODEL = "dolphin-mistral" # You can use any LLM
    LOG_CSV = "gmail_phish_log.csv" # Logs the Scan results in this csv file
    PROCESSED_LABEL = "Processed-By-Ollama"
    PHISHING_LABEL = "⚠️-Phishing-Alert"
    SAFE_LABEL = "✓-Verified-Safe"
    POLL_INTERVAL_SECS = 20         # scans Gmail inbox in real time for every 20 secs
    
    # Heuristic thresholds
    HEURISTIC_THRESHOLD = 0.5
    LLM_SKIP_THRESHOLD = 0.08
    
    # Advanced features
    AUTO_QUARANTINE = True
    WHITELIST_FILE = "trusted_senders.txt"
    BLACKLIST_FILE = "blocked_senders.txt"
    STATS_FILE = "detection_stats.json"
    ENABLE_NOTIFICATIONS = False
    ENABLE_EMAIL_REPORTS = False
    REPORT_EMAIL = "your-email@gmail.com"
    
    # Machine Learning
    ENABLE_LEARNING = True
    TRAINING_DATA_FILE = "training_data.csv"
    
    # Improved URL pattern to handle more edge cases
    URL_PATTERN = re.compile(r'https?://[^\s<>"\'\)]+|www\.[^\s<>"\'\)]+')
    
    URGENT_KEYWORDS = [
        "urgent", "immediately", "asap", "suspend", "suspended",
        "verify", "verify your", "click here", "update", 
        "expired", "act now", "confirm", "secure your account"
    ]
    SENSITIVE_INFO_KEYWORDS = [
        "password", "account number", "ssn", "social security", 
        "card", "cvv", "pin", "bank details", "credit card"
    ]
    PHISHING_INDICATORS = [
        "phish", "suspicious", "malicious", "scam", "fraud", "fake"
    ]
    SAFE_INDICATORS = [
        "legitimate", "safe", "authentic", "genuine", "valid"
    ]
    
    # Added retry configuration
    MAX_RETRIES = 3
    RETRY_DELAY = 2  # seconds


# ============================================================================
# DATA MODELS
# ============================================================================

@dataclass
class EmailData:
    """Email message data"""
    msg_id: str
    subject: str
    body: str
    sender: str
    snippet: str
    
    @property
    def full_text(self) -> str:
        return f"{self.subject} {self.body}"


@dataclass
class HeuristicResult:
    """Heuristic analysis result"""
    score: float
    reason: str
    details: Dict[str, bool]


@dataclass
class LLMResult:
    """LLM analysis result"""
    label: str
    reason: str
    score: float
    recommendation: str


@dataclass
class AnalysisResult:
    """Complete analysis result"""
    email: EmailData
    heuristic: HeuristicResult
    llm: Optional[LLMResult]
    final_label: str
    timestamp: str
    
    def is_phishing(self) -> bool:
        return self.final_label == "phishing"


# ============================================================================
# CONSOLE OUTPUT UTILITIES
# ============================================================================

class Console:
    """Colored console output"""
    
    @staticmethod
    def green(text: str) -> str:
        return f"\033[92m{text}\033[0m"
    
    @staticmethod
    def red(text: str) -> str:
        return f"\033[91m{text}\033[0m"
    
    @staticmethod
    def yellow(text: str) -> str:
        return f"\033[93m{text}\033[0m"
    
    @staticmethod
    def blue(text: str) -> str:
        return f"\033[94m{text}\033[0m"
    
    @staticmethod
    def cyan(text: str) -> str:
        return f"\033[96m{text}\033[0m"
    
    @staticmethod
    def bold(text: str) -> str:
        return f"\033[1m{text}\033[0m"
    
    @staticmethod
    def print_banner():
        """Print application banner"""
        banner = """
╔═══════════════════════════════════════════════════════════════╗
║                                                               ║
║        Gmail Phishing Detection Daemon                        ║
║        Powered by Ollama LLM + Heuristic Analysis             ║
║                                                               ║
╚═══════════════════════════════════════════════════════════════╝
        """
        print(Console.cyan(banner))
    
    @staticmethod
    def print_result(result: AnalysisResult):
        """Print formatted analysis result"""
        print("\n" + "="*80)
        
        if result.is_phishing():
            status = Console.red("⚠️  PHISHING DETECTED")
        else:
            status = Console.green("✓ SAFE EMAIL")
        
        print(Console.bold(status))
        print("="*80)
        
        print(f"\n{Console.bold('Email Details:')}")
        print(f"  Time:     {result.timestamp}")
        print(f"  From:     {result.email.sender}")
        print(f"  Subject:  {result.email.subject[:70]}...")
        
        print(f"\n{Console.bold('Heuristic Analysis:')}")
        print(f"  Score:    {result.heuristic.score:.2f} / 1.00")
        print(f"  Reason:   {result.heuristic.reason}")
        
        details = result.heuristic.details
        indicators = []
        if details.get('has_url'):
            indicators.append("URLs found")
        if details.get('has_urgency'):
            indicators.append("Urgent language")
        if details.get('asks_info'):
            indicators.append("Requests sensitive info")
        if details.get('short_suspicious_subject'):
            indicators.append("Suspicious subject")
        
        if indicators:
            print(f"  Flags:    {', '.join(indicators)}")
        
        if result.llm:
            print(f"\n{Console.bold('LLM Analysis:')}")
            print(f"  Label:    {result.llm.label.upper()}")
            print(f"  Score:    {result.llm.score}/10")
            print(f"  Reason:   {result.llm.reason}")
            print(f"  Action:   {result.llm.recommendation}")
        else:
            print(f"\n{Console.bold('LLM Analysis:')} {Console.yellow('SKIPPED (low risk)')}")
        
        print(f"\n{Console.bold('Final Verdict:')} ", end="")
        if result.is_phishing():
            print(Console.red(f"{result.final_label.upper()} - Email marked as suspicious"))
        else:
            print(Console.green(f"{result.final_label.upper()} - Email appears legitimate"))
        
        print("="*80 + "\n")


# ============================================================================
# GMAIL INTEGRATION
# ============================================================================

class GmailService:
    """Handles Gmail API interactions with proper error handling"""
    
    def __init__(self, config: Config):
        self.config = config
        self.service = self._authenticate()
        self.processed_label_id = self._get_or_create_label()
        self._label_cache = {}  # FIXED: Cache to prevent race conditions
    
    def _authenticate(self):
        """Authenticate with Gmail API with proper error handling"""
        creds = None
        
        if os.path.exists(self.config.TOKEN_FILE):
            try:
                with open(self.config.TOKEN_FILE, "rb") as f:
                    creds = pickle.load(f)
            except Exception as e:
                print(Console.yellow(f"Warning: Could not load token: {e}"))
                creds = None
        
        # FIXED: Handle expired/invalid credentials properly
        if not creds or not creds.valid:
            if creds and creds.expired and creds.refresh_token:
                try:
                    creds.refresh(Request())
                except RefreshError:
                    print(Console.yellow("Token refresh failed, re-authenticating..."))
                    os.remove(self.config.TOKEN_FILE)
                    creds = None
            
            if not creds:
                if not os.path.exists(self.config.CREDENTIALS_FILE):
                    raise FileNotFoundError(
                        f"credentials.json not found! Please download it from Google Cloud Console."
                    )
                
                flow = InstalledAppFlow.from_client_secrets_file(
                    self.config.CREDENTIALS_FILE, 
                    self.config.SCOPES
                )
                creds = flow.run_local_server(port=0)
            
            with open(self.config.TOKEN_FILE, "wb") as f:
                pickle.dump(creds, f)
        
        # Added cache_discovery=False to avoid intermittent issues
        return build("gmail", "v1", credentials=creds, cache_discovery=False)
    
    def _get_or_create_label(self) -> str:
        """Get or create the processed label"""
        try:
            labels_res = self.service.users().labels().list(userId="me").execute()
            
            for label in labels_res.get("labels", []):
                if label.get("name") == self.config.PROCESSED_LABEL:
                    return label["id"]
            
            label_body = {
                "name": self.config.PROCESSED_LABEL,
                "labelListVisibility": "labelShow",
                "messageListVisibility": "show"
            }
            
            created = self.service.users().labels().create(
                userId="me", 
                body=label_body
            ).execute()
            
            return created["id"]
        except Exception as e:
            print(Console.red(f"Error creating label: {e}"))
            raise
    
    def get_label_id(self, label_name: str) -> str:
        """Get or create a label and return its ID (with caching)"""
        #  Added caching to prevent race conditions
        if label_name in self._label_cache:
            return self._label_cache[label_name]
        
        try:
            labels_res = self.service.users().labels().list(userId="me").execute()
            
            for label in labels_res.get("labels", []):
                if label.get("name") == label_name:
                    self._label_cache[label_name] = label["id"]
                    return label["id"]
            
            label_body = {
                "name": label_name,
                "labelListVisibility": "labelShow",
                "messageListVisibility": "show"
            }
            
            created = self.service.users().labels().create(
                userId="me", 
                body=label_body
            ).execute()
            
            self._label_cache[label_name] = created["id"]
            return created["id"]
        except Exception as e:
            print(Console.yellow(f"Warning: Could not get/create label {label_name}: {e}"))
            return ""
    
    def fetch_latest_unread(self) -> Optional[str]:
        """Fetch the most recent unread email with retry logic"""
        # FIXED: Added retry logic for intermittent Gmail API issues
        for attempt in range(self.config.MAX_RETRIES):
            try:
                result = self.service.users().messages().list(
                    userId='me',
                    q="is:unread category:primary",
                    maxResults=5
                ).execute()
                
                messages = result.get('messages', [])
                if not messages:
                    return None
                
                msgs_with_date = []
                for msg in messages:
                    msg_detail = self.service.users().messages().get(
                        userId='me',
                        id=msg['id'],
                        format='metadata',
                        metadataHeaders=['Date']  #  Only fetch needed headers
                    ).execute()
                    msgs_with_date.append((msg['id'], int(msg_detail['internalDate'])))
                
                latest_msg_id = max(msgs_with_date, key=lambda x: x[1])[0]
                return latest_msg_id
            
            except Exception as e:
                if attempt < self.config.MAX_RETRIES - 1:
                    print(Console.yellow(f"Retry {attempt + 1}/{self.config.MAX_RETRIES}: {e}"))
                    time.sleep(self.config.RETRY_DELAY)
                else:
                    print(Console.red(f"Failed to fetch messages after {self.config.MAX_RETRIES} attempts: {e}"))
                    return None
        
        return None
    
    def parse_message(self, msg_id: str) -> EmailData:
        """Parse email message and extract content"""
        msg = self.service.users().messages().get(
            userId="me",
            id=msg_id,
            format="raw"
        ).execute()
        
        # : Handle base64 decoding properly
        raw_bytes = base64.urlsafe_b64decode(msg["raw"].replace('-', '+').replace('_', '/'))
        email_msg = message_from_bytes(raw_bytes)
        
        subject = email_msg.get("Subject", "")
        sender = email_msg.get("From", "")
        body = self._extract_body(email_msg)
        snippet = body[:1000] if body else ""
        
        return EmailData(
            msg_id=msg_id,
            subject=subject,
            body=body,
            sender=sender,
            snippet=snippet
        )
    
    def _extract_body(self, email_msg) -> str:
        """Extract email body text"""
        body = ""
        
        if email_msg.is_multipart():
            for part in email_msg.walk():
                content_type = part.get_content_type()
                disposition = str(part.get("Content-Disposition", ""))
                
                if content_type == "text/plain" and "attachment" not in disposition:
                    try:
                        body = part.get_payload(decode=True).decode(errors="ignore")
                        break
                    except:
                        body = str(part.get_payload())
                        break
            
            if not body:
                for part in email_msg.walk():
                    if part.get_content_type() == "text/html":
                        try:
                            body = part.get_payload(decode=True).decode(errors="ignore")
                            break
                        except:
                            body = str(part.get_payload())
                            break
        else:
            try:
                body = email_msg.get_payload(decode=True).decode(errors="ignore")
            except:
                body = str(email_msg.get_payload())
        
        return body
    
    def mark_as_processed(self, msg_id: str):
        """Mark message as processed"""
        try:
            body = {
                "removeLabelIds": ["UNREAD"],
                "addLabelIds": [self.processed_label_id]
            }
            self.service.users().messages().modify(
                userId="me",
                id=msg_id,
                body=body
            ).execute()
        except Exception as e:
            print(Console.yellow(f"Warning: Could not mark as processed: {e}"))
    
    def apply_label(self, msg_id: str, label_name: str):
        """Apply a specific label to a message"""
        try:
            label_id = self.get_label_id(label_name)
            if label_id:
                body = {"addLabelIds": [label_id]}
                self.service.users().messages().modify(
                    userId="me",
                    id=msg_id,
                    body=body
                ).execute()
        except Exception as e:
            print(Console.yellow(f"Warning: Could not apply label: {e}"))
    
    def move_to_spam(self, msg_id: str):
        """Move message to trash"""
        try:
            self.service.users().messages().trash(
                userId="me",
                id=msg_id
            ).execute()
        except Exception as e:
            print(Console.yellow(f"Warning: Could not move to trash: {e}"))
    
    def extract_sender_email(self, sender: str) -> str:
        """Extract email address from sender field"""
        match = re.search(r'<(.+?)>', sender)
        if match:
            return match.group(1).lower()
        return sender.lower()


# ============================================================================
# WHITELIST/BLACKLIST MANAGER
# ============================================================================

class ListManager:
    """Manages trusted and blocked sender lists"""
    
    def __init__(self, config: Config):
        self.config = config
        self.whitelist = self._load_list(config.WHITELIST_FILE)
        self.blacklist = self._load_list(config.BLACKLIST_FILE)
    
    def _load_list(self, filepath: str) -> Set[str]:
        """Load sender list from file"""
        if not os.path.exists(filepath):
            return set()
        
        try:
            with open(filepath, 'r') as f:
                return {line.strip().lower() for line in f if line.strip()}
        except Exception as e:
            print(Console.yellow(f"Warning: Could not load {filepath}: {e}"))
            return set()
    
    def _save_list(self, filepath: str, items: Set[str]):
        """Save sender list to file"""
        try:
            with open(filepath, 'w') as f:
                for item in sorted(items):
                    f.write(f"{item}\n")
        except Exception as e:
            print(Console.yellow(f"Warning: Could not save {filepath}: {e}"))
    
    def is_whitelisted(self, sender: str) -> bool:
        """Check if sender is whitelisted"""
        sender_email = self._extract_email(sender)
        return sender_email in self.whitelist
    
    def is_blacklisted(self, sender: str) -> bool:
        """Check if sender is blacklisted"""
        sender_email = self._extract_email(sender)
        return sender_email in self.blacklist
    
    def add_to_whitelist(self, sender: str):
        """Add sender to whitelist"""
        sender_email = self._extract_email(sender)
        self.whitelist.add(sender_email)
        self._save_list(self.config.WHITELIST_FILE, self.whitelist)
        print(Console.green(f"✓ Added {sender_email} to whitelist"))
    
    def add_to_blacklist(self, sender: str):
        """Add sender to blacklist"""
        sender_email = self._extract_email(sender)
        self.blacklist.add(sender_email)
        self._save_list(self.config.BLACKLIST_FILE, self.blacklist)
        print(Console.red(f"⚠ Added {sender_email} to blacklist"))
    
    def _extract_email(self, sender: str) -> str:
        """Extract email from sender string"""
        match = re.search(r'<(.+?)>', sender)
        if match:
            return match.group(1).lower()
        return sender.lower()


# ============================================================================
# STATISTICS TRACKER
# ============================================================================

class StatsTracker:
    """Tracks detection statistics"""
    
    def __init__(self, config: Config):
        self.config = config
        self.stats = self._load_stats()
    
    def _load_stats(self) -> Dict:
        """Load statistics from file"""
        if os.path.exists(self.config.STATS_FILE):
            try:
                with open(self.config.STATS_FILE, 'r') as f:
                    return json.load(f)
            except Exception as e:
                print(Console.yellow(f"Warning: Could not load stats: {e}"))
        
        return {
            "total_emails": 0,
            "phishing_detected": 0,
            "safe_emails": 0,
            "false_positives": 0,
            "false_negatives": 0,
            "last_updated": None,
            "detection_rate": 0.0,
            "daily_stats": {}
        }
    
    def _save_stats(self):
        """Save statistics to file"""
        try:
            self.stats["last_updated"] = datetime.now().isoformat()
            with open(self.config.STATS_FILE, 'w') as f:
                json.dump(self.stats, f, indent=2)
        except Exception as e:
            print(Console.yellow(f"Warning: Could not save stats: {e}"))
    
    def record_detection(self, result: AnalysisResult):
        """Record a detection result"""
        self.stats["total_emails"] += 1
        
        if result.is_phishing():
            self.stats["phishing_detected"] += 1
        else:
            self.stats["safe_emails"] += 1
        
        today = datetime.now().strftime("%Y-%m-%d")
        if today not in self.stats["daily_stats"]:
            self.stats["daily_stats"][today] = {
                "total": 0, "phishing": 0, "safe": 0
            }
        
        self.stats["daily_stats"][today]["total"] += 1
        if result.is_phishing():
            self.stats["daily_stats"][today]["phishing"] += 1
        else:
            self.stats["daily_stats"][today]["safe"] += 1
        
        if self.stats["total_emails"] > 0:
            self.stats["detection_rate"] = (
                self.stats["phishing_detected"] / self.stats["total_emails"]
            ) * 100
        
        self._save_stats()
    
    def record_feedback(self, is_false_positive: bool = False, is_false_negative: bool = False):
        """Record user feedback"""
        if is_false_positive:
            self.stats["false_positives"] += 1
        if is_false_negative:
            self.stats["false_negatives"] += 1
        self._save_stats()
    
    def get_summary(self) -> str:
        """Get statistics summary"""
        return f"""
📊 Detection Statistics:
   Total Emails:       {self.stats['total_emails']}
   Phishing Detected:  {self.stats['phishing_detected']}
   Safe Emails:        {self.stats['safe_emails']}
   Detection Rate:     {self.stats['detection_rate']:.2f}%
   False Positives:    {self.stats['false_positives']}
   False Negatives:    {self.stats['false_negatives']}
"""
    
    def get_daily_summary(self, days: int = 7) -> str:
        """Get summary for last N days"""
        summary = "\n📅 Last 7 Days:\n"
        today = datetime.now()
        
        for i in range(days):
            date = (today - timedelta(days=i)).strftime("%Y-%m-%d")
            if date in self.stats["daily_stats"]:
                day_stats = self.stats["daily_stats"][date]
                summary += f"   {date}: {day_stats['total']} emails ({day_stats['phishing']} phishing)\n"
        
        return summary


# ============================================================================
# URL ANALYZER
# ============================================================================

class URLAnalyzer:
    """Advanced URL analysis for phishing detection"""
    
    SUSPICIOUS_TLDS = ['.tk', '.ml', '.ga', '.cf', '.gq', '.xyz', '.top']
    TRUSTED_DOMAINS = ['google.com', 'microsoft.com', 'apple.com', 'amazon.com']
    
    @staticmethod
    def extract_urls(text: str) -> List[str]:
        """Extract all URLs from text"""
        url_pattern = re.compile(r'https?://[^\s<>"\'\)]+|www\.[^\s<>"\'\)]+')
        return url_pattern.findall(text)
    
    @staticmethod
    def is_suspicious_url(url: str) -> Tuple[bool, str]:
        """Check if URL is suspicious"""
        reasons = []
        
        if any(url.endswith(tld) for tld in URLAnalyzer.SUSPICIOUS_TLDS):
            reasons.append("Suspicious TLD")
        
        ip_pattern = re.compile(r'https?://\d{1,3}\.\d{1,3}\.\d{1,3}\.\d{1,3}')
        if ip_pattern.match(url):
            reasons.append("Uses IP address")
        
        shorteners = ['bit.ly', 'tinyurl.com', 't.co', 'goo.gl', 'ow.ly']
        if any(short in url for short in shorteners):
            reasons.append("URL shortener")
        
        domain_part = url.split('//')[1].split('/')[0] if '//' in url else url
        if domain_part.count('.') > 3:
            reasons.append("Too many subdomains")
        
        suspicious_chars = ['р', 'а', 'с', 'о', 'е', 'х']
        if any(char in url for char in suspicious_chars):
            reasons.append("Homograph attack")
        
        return (len(reasons) > 0, ", ".join(reasons) if reasons else "")
    
    @staticmethod
    def get_domain(url: str) -> str:
        """Extract domain from URL"""
        try:
            if '//' in url:
                domain = url.split('//')[1].split('/')[0]
            else:
                domain = url.split('/')[0]
            return domain
        except:
            return url


# ============================================================================
# REST OF THE CODE (HeuristicAnalyzer, LLMAnalyzer, etc.)
# ============================================================================

class HeuristicAnalyzer:
    """Analyzes emails using heuristic rules"""
    
    def __init__(self, config: Config):
        self.config = config
        self.url_analyzer = URLAnalyzer()
    
    def analyze(self, email: EmailData) -> HeuristicResult:
        """Perform heuristic analysis on email"""
        score = 0.0
        reasons = []
        details = {}
        
        text_lower = email.full_text.lower()
        
        urls = self.url_analyzer.extract_urls(email.full_text)
        if urls:
            details['has_url'] = True
            details['url_count'] = len(urls)
            score += 0.25
            
            suspicious_count = 0
            for url in urls:
                is_sus, reason = self.url_analyzer.is_suspicious_url(url)
                if is_sus:
                    suspicious_count += 1
                    score += 0.15
            
            if suspicious_count > 0:
                details['suspicious_urls'] = suspicious_count
                reasons.append("SUSPICIOUS_URL")
            else:
                reasons.append("URL")
        else:
            details['has_url'] = False
        
        if any(kw in text_lower for kw in self.config.URGENT_KEYWORDS):
            score += 0.18
            if not reasons:
                reasons.append("URGENT")
            details['has_urgency'] = True
        else:
            details['has_urgency'] = False
        
        if any(kw in text_lower for kw in self.config.SENSITIVE_INFO_KEYWORDS):
            score += 0.20
            if not reasons:
                reasons.append("ASKS_INFO")
            details['asks_info'] = True
        else:
            details['asks_info'] = False
        
        suspicious_words = ["urgent", "verify", "payment", "reset", "suspended"]
        if (len(email.subject.strip()) < 20 and 
            any(w in email.subject.lower() for w in suspicious_words)):
            score += 0.12
            if not reasons:
                reasons.append("SHORT_SUBJ")
            details['short_suspicious_subject'] = True
        else:
            details['short_suspicious_subject'] = False
        
        misspellings = ['acount', 'verifiy', 'urgnt', 'immediatly', 'suspened']
        if any(word in text_lower for word in misspellings):
            score += 0.10
            details['has_misspellings'] = True
        else:
            details['has_misspellings'] = False
        
        score = min(round(score, 4), 1.0)
        reason = reasons[0] if reasons else "NONE"
        
        return HeuristicResult(score=score, reason=reason, details=details)


# ============================================================================
# LLM ANALYZER 
# ============================================================================

class LLMAnalyzer:
    """Analyzes emails using Ollama LLM"""
    
    def __init__(self, config: Config):
        self.config = config
        try:
            self.client = Client()
        except Exception as e:
            print(Console.red(f"Error initializing Ollama client: {e}"))
            self.client = None
    
    def analyze(self, email: EmailData) -> LLMResult:
        """Perform LLM analysis on email"""
        # Check if client is available
        if self.client is None:
            return self._fallback_analysis("Ollama client not available")
        
        prompt = self._build_prompt(email)
        
        try:
            response = self.client.chat(
                model=self.config.OLLAMA_MODEL,
                messages=[{"role": "user", "content": prompt}],
                stream=False,
                options={
                    "temperature": 0.1,
                    "num_predict": 150,
                }
            )
            
            text = self._extract_response_text(response)
            
            print(Console.cyan(f"🤖 LLM Raw Response: {text[:200]}"))
            
            return self._parse_response(text)
            
        except Exception as e:
            print(Console.yellow(f"⚠ LLM error: {e}"))
            return self._fallback_analysis(str(e))
    
    def _build_prompt(self, email: EmailData) -> str:
        """Build analysis prompt for LLM"""
        return f"""Analyze this email for phishing. Respond with ONLY valid JSON, nothing else.

Subject: {email.subject}
Content: {email.snippet}

Required JSON format (copy exactly):
{{"label": "phishing", "reason": "why suspicious", "score": 8, "recommendation": "do not click links"}}

OR if safe:
{{"label": "safe", "reason": "appears legitimate", "score": 3, "recommendation": "no action needed"}}

Your JSON response:"""
    
    def _extract_response_text(self, response) -> str:
        """Extract text from Ollama response"""
        if isinstance(response, dict):
            return response.get("message", {}).get("content", "")
        return str(response)
    
    def _parse_response(self, text: str) -> LLMResult:
        """Parse LLM JSON response"""
        text = re.sub(r'```json\s*', '', text)
        text = re.sub(r'```\s*', '', text)
        text = text.strip()
        
        start = text.find("{")
        end = text.rfind("}") + 1
        
        if start == -1 or end == 0:
            return self._fallback_analysis(text)
        
        json_text = text[start:end]
        json_text = (
            json_text
            .replace("'", '"')
            .replace("\n", " ")
            .replace("\r", " ")
            .replace("\t", " ")
        )
        json_text = re.sub(r',\s*}', '}', json_text)
        json_text = re.sub(r',\s*]', ']', json_text)
        
        try:
            data = json.loads(json_text)
            
            label = str(data.get("label", "safe")).lower().strip()
            if "phish" in label:
                label = "phishing"
            elif "safe" in label or "legitimate" in label:
                label = "safe"
            else:
                label = "safe"
            
            reason = str(data.get("reason", "No reason provided")).strip()
            score = max(1, min(10, float(data.get("score", 5))))
            recommendation = str(data.get("recommendation", "Review manually")).strip()
            
            return LLMResult(
                label=label,
                reason=reason,
                score=score,
                recommendation=recommendation
            )
            
        except json.JSONDecodeError as e:
            print(Console.yellow(f"JSON parse error: {e}"))
            return self._fallback_analysis(text)
    
    def _fallback_analysis(self, text: str) -> LLMResult:
        """Fallback analysis when JSON parsing fails"""
        text_lower = text.lower()
        
        phishing_count = sum(
            1 for word in self.config.PHISHING_INDICATORS 
            if word in text_lower
        )
        safe_count = sum(
            1 for word in self.config.SAFE_INDICATORS 
            if word in text_lower
        )
        
        if phishing_count > safe_count:
            return LLMResult(
                label="phishing",
                reason="LLM indicated suspicious content (JSON parse failed)",
                score=7.0,
                recommendation="Manual review recommended"
            )
        else:
            return LLMResult(
                label="safe",
                reason="LLM analysis unclear (JSON parse failed)",
                score=3.0,
                recommendation="Manual review recommended"
            )


# ============================================================================
# ANALYSIS COORDINATOR
# ============================================================================

class PhishingDetector:
    """Coordinates analysis and determines final verdict"""
    
    def __init__(self, config: Config):
        self.config = config
        self.heuristic_analyzer = HeuristicAnalyzer(config)
        self.llm_analyzer = LLMAnalyzer(config)
        self.list_manager = ListManager(config)
    
    def analyze(self, email: EmailData) -> AnalysisResult:
        """Perform complete analysis on email"""
        if self.list_manager.is_whitelisted(email.sender):
            return self._create_whitelisted_result(email)
        
        if self.list_manager.is_blacklisted(email.sender):
            return self._create_blacklisted_result(email)
        
        heuristic_result = self.heuristic_analyzer.analyze(email)
        
        llm_result = None
        if heuristic_result.score >= self.config.LLM_SKIP_THRESHOLD:
            llm_result = self.llm_analyzer.analyze(email)
        
        final_label = self._determine_label(heuristic_result, llm_result)
        
        timestamp = datetime.now().strftime("%Y-%m-%d %H:%M:%S")
        
        return AnalysisResult(
            email=email,
            heuristic=heuristic_result,
            llm=llm_result,
            final_label=final_label,
            timestamp=timestamp
        )
    
    def _create_whitelisted_result(self, email: EmailData) -> AnalysisResult:
        """Create result for whitelisted sender"""
        timestamp = datetime.now().strftime("%Y-%m-%d %H:%M:%S")
        return AnalysisResult(
            email=email,
            heuristic=HeuristicResult(score=0.0, reason="WHITELISTED", details={}),
            llm=None,
            final_label="safe",
            timestamp=timestamp
        )
    
    def _create_blacklisted_result(self, email: EmailData) -> AnalysisResult:
        """Create result for blacklisted sender"""
        timestamp = datetime.now().strftime("%Y-%m-%d %H:%M:%S")
        return AnalysisResult(
            email=email,
            heuristic=HeuristicResult(score=1.0, reason="BLACKLISTED", details={}),
            llm=None,
            final_label="phishing",
            timestamp=timestamp
        )
    
    def _determine_label(
        self, 
        heuristic: HeuristicResult, 
        llm: Optional[LLMResult]
    ) -> str:
        """Determine final phishing/safe label"""
        if llm and llm.label == "phishing":
            return "phishing"
        
        if heuristic.score >= self.config.HEURISTIC_THRESHOLD:
            return "phishing"
        
        return "safe"


# ============================================================================
# LOGGER
# ============================================================================

class Logger:
    """Logs analysis results to CSV"""
    
    def __init__(self, config: Config):
        self.config = config
        self._ensure_csv_exists()
    
    def _ensure_csv_exists(self):
        """Create CSV file with headers if it doesn't exist"""
        if not os.path.exists(self.config.LOG_CSV):
            df = pd.DataFrame(columns=[
                "msg_id", "subject", "sender", "timestamp",
                "heuristic_score", "heuristic_reason",
                "llm_label", "llm_reason", "llm_score", "llm_recommendation",
                "combined_label"
            ])
            df.to_csv(self.config.LOG_CSV, index=False)
    
    def log_result(self, result: AnalysisResult):
        """Log analysis result to CSV"""
        try:
            row = {
                "msg_id": result.email.msg_id,
                "subject": result.email.subject,
                "sender": result.email.sender,
                "timestamp": result.timestamp,
                "heuristic_score": result.heuristic.score,
                "heuristic_reason": result.heuristic.reason,
                "llm_label": result.llm.label if result.llm else "skipped",
                "llm_reason": result.llm.reason if result.llm else "",
                "llm_score": result.llm.score if result.llm else 0,
                "llm_recommendation": result.llm.recommendation if result.llm else "",
                "combined_label": result.final_label
            }
            
            pd.DataFrame([row]).to_csv(
                self.config.LOG_CSV,
                mode="a",
                header=False,
                index=False
            )
        except Exception as e:
            print(Console.yellow(f"Logging error: {e}"))


# ============================================================================
# NOTIFICATION SYSTEM (FIXED)
# ============================================================================

class NotificationSystem:
    """Send notifications for phishing detections"""
    
    def __init__(self, config: Config):
        self.config = config
        self.enabled = config.ENABLE_NOTIFICATIONS
    
    def notify_phishing_detected(self, result: AnalysisResult):
        """Send notification when phishing is detected"""
        if not self.enabled:
            return
        
        try:
            self._send_system_notification(
                "⚠️ Phishing Detected!",
                f"From: {result.email.sender}\nSubject: {result.email.subject[:50]}..."
            )
        except:
            pass
    
    def _send_system_notification(self, title: str, message: str):
        """Send system notification (platform-specific)"""
        try:
            system = platform.system()
            
            # FIXED: Properly escape quotes for shell commands
            title_escaped = title.replace('"', '\\"')
            message_escaped = message.replace('"', '\\"')
            
            if system == "Darwin":  # macOS
                os.system(f'osascript -e \'display notification "{message_escaped}" with title "{title_escaped}"\'')
            elif system == "Linux":
                os.system(f'notify-send "{title_escaped}" "{message_escaped}"')
            elif system == "Windows":
                try:
                    from win10toast import ToastNotifier
                    toaster = ToastNotifier()
                    toaster.show_toast(title, message, duration=10)
                except:
                    pass
        except:
            pass


# ============================================================================
# REPORT GENERATOR (FIXED)
# ============================================================================

class ReportGenerator:
    """Generate email reports and summaries"""
    
    def __init__(self, config: Config, stats: StatsTracker):
        self.config = config
        self.stats = stats
    
    def generate_daily_report(self) -> str:
        """Generate daily summary report"""
        today = datetime.now().strftime("%Y-%m-%d")
        
        report = f"""
╔═══════════════════════════════════════════════════════════════╗
║           DAILY PHISHING DETECTION REPORT                     ║
║                  {today}                            ║
╚═══════════════════════════════════════════════════════════════╝

{self.stats.get_summary()}

{self.stats.get_daily_summary(7)}

🎯 Detection Performance:
   Accuracy: {self._calculate_accuracy():.1f}%
   
🔍 Top Phishing Indicators:
   {self._get_top_indicators()}

📋 Recommendations:
   • Review false positives to refine detection
   • Update whitelist with trusted senders
   • Check suspicious URLs in quarantined emails

Report generated: {datetime.now().strftime("%Y-%m-%d %H:%M:%S")}
        """
        return report
    
    def _calculate_accuracy(self) -> float:
        """Calculate detection accuracy"""
        total = self.stats.stats["total_emails"]
        false_pos = self.stats.stats["false_positives"]
        false_neg = self.stats.stats["false_negatives"]
        
        if total == 0:
            return 100.0
        
        correct = total - false_pos - false_neg
        return (correct / total) * 100
    
    def _get_top_indicators(self) -> str:
        """Get top phishing indicators from recent detections"""
        try:
            # FIXED: Check if file exists before reading
            if not os.path.exists(self.config.LOG_CSV):
                return "No data yet"
            
            df = pd.read_csv(self.config.LOG_CSV)
            if len(df) == 0:
                return "No data yet"
            
            phishing_df = df[df['combined_label'] == 'phishing']
            if len(phishing_df) == 0:
                return "No phishing detected yet"
            
            top_reasons = phishing_df['heuristic_reason'].value_counts().head(3)
            result = []
            for reason, count in top_reasons.items():
                result.append(f"• {reason}: {count} times")
            
            return "\n   ".join(result)
        except Exception as e:
            print(Console.yellow(f"Warning: Could not analyze indicators: {e}"))
            return "Unable to analyze indicators"
    
    def save_report(self, filename: str = None):
        """Save report to file"""
        if filename is None:
            filename = f"phishing_report_{datetime.now().strftime('%Y%m%d')}.txt"
        
        report = self.generate_daily_report()
        try:
            with open(filename, 'w') as f:
                f.write(report)
            print(Console.green(f"✓ Report saved to {filename}"))
        except Exception as e:
            print(Console.red(f"Error saving report: {e}"))


# ============================================================================
# COMMAND HANDLER (FIXED - Now properly integrated)
# ============================================================================

class CommandHandler:
    """Handles interactive commands during monitoring"""
    
    def __init__(self, daemon):
        self.daemon = daemon
    
    def handle_command(self, cmd: str, result: AnalysisResult):
        """Handle user command"""
        cmd = cmd.lower().strip()
        
        if cmd == 'w':
            self.daemon.list_manager.add_to_whitelist(result.email.sender)
        elif cmd == 'b':
            self.daemon.list_manager.add_to_blacklist(result.email.sender)
        elif cmd == 'f':
            self.daemon.stats.record_feedback(is_false_positive=True)
            print(Console.green("✓ Feedback recorded"))
        elif cmd == 'r':
            self.daemon.stats.record_feedback(is_false_negative=True)
            print(Console.red("⚠ Phishing missed - feedback recorded"))
        elif cmd == 's' or cmd == 'stats':
            print(self.daemon.stats.get_summary())
            print(self.daemon.stats.get_daily_summary())
        elif cmd == 'help':
            self._show_help()
    
    def _show_help(self):
        """Show help message"""
        help_text = """
╔═══════════════════════════════════════════════════════════════╗
║                        HELP & COMMANDS                        ║
╚═══════════════════════════════════════════════════════════════╝

📧 Email Processing:
   • Daemon automatically scans new emails in Primary inbox
   • Emails are analyzed using heuristics + LLM
   • Results are logged to CSV

🏷️  Labels Applied:
   • ⚠️-Phishing-Alert: Suspected phishing emails
   • ✓-Verified-Safe: Legitimate emails
   • Processed-By-Ollama: All processed emails

⚡ Quick Actions (after each email):
   W - Add sender to whitelist (always trust)
   B - Add sender to blacklist (always block)
   F - Mark as false positive (not actually phishing)
   R - Report missed phishing (was actually phishing)
   S - Show statistics dashboard
   
🛡️  Advanced Features:
   • Auto-quarantine moves phishing to trash
   • Whitelist/blacklist for trusted/blocked senders
   • URL analysis detects suspicious links
   • Statistics tracking for performance monitoring

📂 Files Created:
   • gmail_phish_log.csv - Detection log
   • detection_stats.json - Statistics data
   • trusted_senders.txt - Whitelisted emails
   • blocked_senders.txt - Blacklisted emails

💡 Tips:
   • Review false positives to improve accuracy
   • Check stats regularly to monitor performance
   • Whitelist known contacts to skip analysis
   
Press Ctrl+C to stop the daemon
        """
        print(Console.cyan(help_text))


# ============================================================================
# MAIN DAEMON
# ============================================================================

class PhishingDaemon:
    """Main daemon that monitors Gmail inbox"""
    
    def __init__(self, config: Config):
        self.config = config
        self.gmail = GmailService(config)
        self.detector = PhishingDetector(config)
        self.logger = Logger(config)
        self.stats = StatsTracker(config)
        self.list_manager = self.detector.list_manager
    
    def run(self):
        """Run the monitoring daemon"""
        Console.print_banner()
        print(Console.cyan(f"📧 Monitoring Gmail inbox..."))
        print(Console.cyan(f"⏱️  Poll interval: {self.config.POLL_INTERVAL_SECS}s"))
        print(Console.cyan(f"📊 Logging to: {self.config.LOG_CSV}"))
        
        if self.config.AUTO_QUARANTINE:
            print(Console.yellow(f"🛡️  Auto-quarantine: ENABLED"))
        
        print(Console.cyan(f"\n💡 Commands: Type 'stats' for statistics, 'help' for help"))
        print(Console.cyan(f"Press Ctrl+C to stop\n"))
        
        try:
            while True:
                self._process_next_email()
                time.sleep(self.config.POLL_INTERVAL_SECS)
                
        except KeyboardInterrupt:
            print(Console.yellow("\n\n" + "="*80))
            print(self.stats.get_summary())
            print(Console.yellow("="*80))
            print(Console.yellow("\n👋 Daemon stopped by user. Goodbye!"))
    
    def _process_next_email(self):
        """Process the next unread email"""
        try:
            msg_id = self.gmail.fetch_latest_unread()
            
            if not msg_id:
                return
            
            email = self.gmail.parse_message(msg_id)
            result = self.detector.analyze(email)
            
            Console.print_result(result)
            self.logger.log_result(result)
            self.stats.record_detection(result)
            
            if result.is_phishing():
                self.gmail.apply_label(msg_id, self.config.PHISHING_LABEL)
                
                if self.config.AUTO_QUARANTINE:
                    print(Console.red("🗑️  Moving to Trash..."))
                    self.gmail.move_to_spam(msg_id)
            else:
                self.gmail.apply_label(msg_id, self.config.SAFE_LABEL)
            
            self.gmail.mark_as_processed(msg_id)
            self._show_quick_actions(result)
            
        except Exception as e:
            print(Console.red(f"Error processing email: {e}"))
    
    def _show_quick_actions(self, result: AnalysisResult):
        """Show quick action options for the email"""
        print(Console.blue("\n💬 Quick Actions:"))
        if result.is_phishing():
            print(Console.blue("   [B] Add sender to blacklist"))
            print(Console.blue("   [F] Report as false positive"))
        else:
            print(Console.blue("   [W] Add sender to whitelist"))
            print(Console.blue("   [R] Report as phishing (missed)"))
        print(Console.blue("   [S] Show statistics"))
        print(Console.blue("   [Enter] Continue monitoring\n"))


# ============================================================================
# ENHANCED DAEMON (FIXED)
# ============================================================================

class EnhancedPhishingDaemon(PhishingDaemon):
    """Enhanced daemon with interactive features"""
    
    def __init__(self, config: Config):
        super().__init__(config)
        self.notification_system = NotificationSystem(config)
        self.report_generator = ReportGenerator(config, self.stats)
        self.last_result = None
    
    def run(self):
        """Run the enhanced monitoring daemon"""
        Console.print_banner()
        print(Console.cyan(f"📧 Monitoring Gmail inbox..."))
        print(Console.cyan(f"⏱️  Poll interval: {self.config.POLL_INTERVAL_SECS}s"))
        print(Console.cyan(f"📊 Logging to: {self.config.LOG_CSV}"))
        
        if self.config.AUTO_QUARANTINE:
            print(Console.yellow(f"🛡️  Auto-quarantine: ENABLED"))
        
        if self.config.ENABLE_NOTIFICATIONS:
            print(Console.yellow(f"🔔 Notifications: ENABLED"))
        
        print(Console.cyan(f"\n💡 Type 'help' for commands"))
        print(Console.cyan(f"Press Ctrl+C to stop\n"))
        
        if self.stats.stats["total_emails"] > 0:
            print(self.stats.get_summary())
        
        try:
            while True:
                self._process_next_email_interactive()
                time.sleep(self.config.POLL_INTERVAL_SECS)
                
        except KeyboardInterrupt:
            self._shutdown()
    
    def _process_next_email_interactive(self):
        """Process email with interactive prompts"""
        try:
            msg_id = self.gmail.fetch_latest_unread()
            
            if not msg_id:
                return
            
            email = self.gmail.parse_message(msg_id)
            result = self.detector.analyze(email)
            self.last_result = result
            
            Console.print_result(result)
            
            if result.is_phishing():
                self.notification_system.notify_phishing_detected(result)
            
            self.logger.log_result(result)
            self.stats.record_detection(result)
            
            if result.is_phishing():
                self.gmail.apply_label(msg_id, self.config.PHISHING_LABEL)
                
                if self.config.AUTO_QUARANTINE:
                    print(Console.red("🗑️  Auto-quarantine: Moving to Trash..."))
                    self.gmail.move_to_spam(msg_id)
            else:
                self.gmail.apply_label(msg_id, self.config.SAFE_LABEL)
            
            self.gmail.mark_as_processed(msg_id)
            self._show_quick_actions(result)
            
        except Exception as e:
            print(Console.red(f"Error processing email: {e}"))
    
    def _shutdown(self):
        """Clean shutdown with final reports"""
        print(Console.yellow("\n\n" + "="*80))
        print(Console.bold("📊 FINAL SESSION REPORT"))
        print("="*80)
        print(self.stats.get_summary())
        print(self.stats.get_daily_summary())
        
        # FIXED: Proper cross-platform input handling
        print(Console.cyan("\n💾 Generate full report? (y/n): "), end="", flush=True)
        try:
            # Try to get input in a cross-platform way
            if platform.system() != "Windows":
                # Unix-like systems
                try:
                    import tty
                    import termios
                    fd = sys.stdin.fileno()
                    old_settings = termios.tcgetattr(fd)
                    try:
                        tty.setraw(sys.stdin.fileno())
                        choice = sys.stdin.read(1).lower()
                    finally:
                        termios.tcsetattr(fd, termios.TCSADRAIN, old_settings)
                except:
                    choice = input().lower()
            else:
                # Windows
                import msvcrt
                choice = msvcrt.getch().decode('utf-8').lower()
            
            if choice == 'y':
                self.report_generator.save_report()
        except Exception as e:
            print(Console.yellow(f"\nCould not get input: {e}"))
        
        print(Console.yellow("="*80))
        print(Console.yellow("\n👋 Daemon stopped. Stay safe online!"))


# ============================================================================
# ENTRY POINT
# ============================================================================

def main():
    """Application entry point"""
    try:
        config = Config()
        daemon = EnhancedPhishingDaemon(config)
        daemon.run()
    except FileNotFoundError as e:
        print(Console.red(f"\n❌ Error: {e}"))
        print(Console.yellow("\nPlease ensure you have:"))
        print(Console.yellow("1. Downloaded credentials.json from Google Cloud Console"))
        print(Console.yellow("2. Enabled Gmail API for your project"))
        print(Console.yellow("3. Installed Ollama and pulled the dolphin-mistral model"))
    except KeyboardInterrupt:
        print(Console.yellow("\n\n👋 Exiting..."))
    except Exception as e:
        print(Console.red(f"\n❌ Fatal error: {e}"))
        import traceback
        traceback.print_exc()


if __name__ == "__main__":
    main()
