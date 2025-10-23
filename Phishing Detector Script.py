"""
Gmail Phishing Detection Daemon
Monitors Gmail inbox for potential phishing emails using heuristics and LLM analysis
"""

import os
import time
import base64
import re
import pickle
import json
from email import message_from_bytes
from typing import Tuple, Dict, List, Optional
from dataclasses import dataclass
from datetime import datetime

import pandas as pd
from googleapiclient.discovery import build
from google_auth_oauthlib.flow import InstalledAppFlow
from google.auth.transport.requests import Request
from ollama import Client


# ============================================================================
# CONFIGURATION
# ============================================================================

class Config:
    """Application configuration"""
    CREDENTIALS_FILE = "credentialsDemo.json" 
    TOKEN_FILE = "token.pickleDemo"
    SCOPES = []
    
    OLLAMA_MODEL = "dolphin-mistral"
    LOG_CSV = "gmail_phish_log.csv"
    PROCESSED_LABEL = "Processed-By-Ollama"
    POLL_INTERVAL_SECS = 20
    
    # Heuristic thresholds
    HEURISTIC_THRESHOLD = 0.5  # Score above this = phishing
    LLM_SKIP_THRESHOLD = 0.08  # Skip LLM if score below this
    
    # Detection patterns
    URL_PATTERN = re.compile(r"https?://[^\s'\"]+")
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
        
        # Header with status
        if result.is_phishing():
            status = Console.red("⚠️  PHISHING DETECTED")
        else:
            status = Console.green("✓ SAFE EMAIL")
        
        print(Console.bold(status))
        print("="*80)
        
        # Email details
        print(f"\n{Console.bold('Email Details:')}")
        print(f"  Time:     {result.timestamp}")
        print(f"  From:     {result.email.sender}")
        print(f"  Subject:  {result.email.subject[:70]}...")
        
        # Heuristic analysis
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
        
        # LLM analysis
        if result.llm:
            print(f"\n{Console.bold('LLM Analysis:')}")
            print(f"  Label:    {result.llm.label.upper()}")
            print(f"  Score:    {result.llm.score}/10")
            print(f"  Reason:   {result.llm.reason}")
            print(f"  Action:   {result.llm.recommendation}")
        else:
            print(f"\n{Console.bold('LLM Analysis:')} {Console.yellow('SKIPPED (low risk)')}")
        
        # Final verdict
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
    """This Handles Gmail API interactions"""
    
    def __init__(self, config: Config):
        self.config = config
        self.service = self._authenticate()
        self.processed_label_id = self._get_or_create_label()
    
    def _authenticate(self):
        """Authenticate with Gmail API"""
        creds = None
        
        if os.path.exists(self.config.TOKEN_FILE):
            with open(self.config.TOKEN_FILE, "rb") as f:
                creds = pickle.load(f)
        
        if not creds or not creds.valid:
            if creds and creds.expired and creds.refresh_token:
                creds.refresh(Request())
            else:
                flow = InstalledAppFlow.from_client_secrets_file(
                    self.config.CREDENTIALS_FILE, 
                    self.config.SCOPES
                )
                creds = flow.run_local_server(port=0)
            
            with open(self.config.TOKEN_FILE, "wb") as f:
                pickle.dump(creds, f)
        
        return build("gmail", "v1", credentials=creds)
    
    def _get_or_create_label(self) -> str:
        """Get or create the processed label"""
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
    
    def fetch_latest_unread(self) -> Optional[str]:
        """Fetch the most recent unread email from primary inbox"""
        try:
            result = self.service.users().messages().list(
                userId='me',
                q="is:unread category:primary",
                maxResults=5
            ).execute()
            
            messages = result.get('messages', [])
            if not messages:
                return None
            
            # Get internal dates and find latest
            msgs_with_date = []
            for msg in messages:
                msg_detail = self.service.users().messages().get(
                    userId='me',
                    id=msg['id'],
                    format='metadata'
                ).execute()
                msgs_with_date.append((msg['id'], int(msg_detail['internalDate'])))
            
            latest_msg_id = max(msgs_with_date, key=lambda x: x[1])[0]
            return latest_msg_id
            
        except Exception as e:
            print(Console.yellow(f"Error fetching messages: {e}"))
            return None
    
    def parse_message(self, msg_id: str) -> EmailData:
        """Parse email message and extract content"""
        msg = self.service.users().messages().get(
            userId="me",
            id=msg_id,
            format="raw"
        ).execute()
        
        raw_bytes = base64.urlsafe_b64decode(msg["raw"])
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
            # Try plain text first
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
            
            # Fallback to HTML
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


# ============================================================================
# HEURISTIC ANALYZER
# ============================================================================

class HeuristicAnalyzer:
    """Analyzes emails using heuristic rules"""
    
    def __init__(self, config: Config):
        self.config = config
    
    def analyze(self, email: EmailData) -> HeuristicResult:
        """Perform heuristic analysis on email"""
        score = 0.0
        reasons = []
        details = {}
        
        text_lower = email.full_text.lower()
        
        # Check for URLs
        if self.config.URL_PATTERN.search(text_lower):
            score += 0.35
            reasons.append("URL")
            details['has_url'] = True
        else:
            details['has_url'] = False
        
        # Check for urgent language
        if any(kw in text_lower for kw in self.config.URGENT_KEYWORDS):
            score += 0.18
            if not reasons:
                reasons.append("URGENT")
            details['has_urgency'] = True
        else:
            details['has_urgency'] = False
        
        # Check for requests for sensitive information
        if any(kw in text_lower for kw in self.config.SENSITIVE_INFO_KEYWORDS):
            score += 0.20
            if not reasons:
                reasons.append("ASKS_INFO")
            details['asks_info'] = True
        else:
            details['asks_info'] = False
        
        # Check for suspicious short subject
        suspicious_words = ["urgent", "verify", "payment", "reset", "suspended"]
        if (len(email.subject.strip()) < 20 and 
            any(w in email.subject.lower() for w in suspicious_words)):
            score += 0.12
            if not reasons:
                reasons.append("SHORT_SUBJ")
            details['short_suspicious_subject'] = True
        else:
            details['short_suspicious_subject'] = False
        
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
        self.client = Client()
    
    def analyze(self, email: EmailData) -> LLMResult:
        """Perform LLM analysis on email"""
        prompt = self._build_prompt(email)
        
        try:
            response = self.client.chat(
                model=self.config.OLLAMA_MODEL,
                messages=[{"role": "user", "content": prompt}],
                stream=False
            )
            
            text = self._extract_response_text(response)
            return self._parse_response(text)
            
        except Exception as e:
            print(Console.yellow(f"LLM error: {e}"))
            return self._fallback_analysis(str(e))
    
    def _build_prompt(self, email: EmailData) -> str:
        """Build analysis prompt for LLM"""
        return f"""You are a cybersecurity assistant. Analyze this email for phishing indicators.

Email Subject: {email.subject}
Email Content: {email.snippet}

Respond with ONLY a valid JSON object (no markdown, no explanation):
{{"label": "phishing or safe", "reason": "brief explanation", "score": 1-10, "recommendation": "action"}}"""
    
    def _extract_response_text(self, response) -> str:
        """Extract text from Ollama response"""
        if isinstance(response, dict):
            return response.get("message", {}).get("content", "")
        return str(response)
    
    def _parse_response(self, text: str) -> LLMResult:
        """Parse LLM JSON response"""
        # Remove markdown code blocks
        text = re.sub(r'```json\s*', '', text)
        text = re.sub(r'```\s*', '', text)
        text = text.strip()
        
        # Extract JSON
        start = text.find("{")
        end = text.rfind("}") + 1
        
        if start == -1 or end == 0:
            return self._fallback_analysis(text)
        
        json_text = text[start:end]
        
        # Clean JSON
        json_text = (
            json_text
            .replace("'", '"')
            .replace("\n", " ")
            .replace("\r", " ")
            .replace("\t", " ")
        )
        
        # Remove trailing commas
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
    
    def analyze(self, email: EmailData) -> AnalysisResult:
        """Perform complete analysis on email"""
        # Heuristic analysis
        heuristic_result = self.heuristic_analyzer.analyze(email)
        
        # LLM analysis (skip if low risk)
        llm_result = None
        if heuristic_result.score >= self.config.LLM_SKIP_THRESHOLD:
            llm_result = self.llm_analyzer.analyze(email)
        
        # Determine final label
        final_label = self._determine_label(heuristic_result, llm_result)
        
        timestamp = datetime.now().strftime("%Y-%m-%d %H:%M:%S")
        
        return AnalysisResult(
            email=email,
            heuristic=heuristic_result,
            llm=llm_result,
            final_label=final_label,
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
# MAIN DAEMON
# ============================================================================

class PhishingDaemon:
    """Main daemon that monitors Gmail inbox"""
    
    def __init__(self, config: Config):
        self.config = config
        self.gmail = GmailService(config)
        self.detector = PhishingDetector(config)
        self.logger = Logger(config)
    
    def run(self):
        """Run the monitoring daemon"""
        Console.print_banner()
        print(Console.cyan(f"📧 Monitoring Gmail inbox..."))
        print(Console.cyan(f"⏱️  Poll interval: {self.config.POLL_INTERVAL_SECS}s"))
        print(Console.cyan(f"📊 Logging to: {self.config.LOG_CSV}"))
        print(Console.cyan(f"\nPress Ctrl+C to stop\n"))
        
        try:
            while True:
                self._process_next_email()
                time.sleep(self.config.POLL_INTERVAL_SECS)
                
        except KeyboardInterrupt:
            print(Console.yellow("\n\n👋 Daemon stopped by user. Goodbye!"))
    
    def _process_next_email(self):
        """Process the next unread email"""
        try:
            msg_id = self.gmail.fetch_latest_unread()
            
            if not msg_id:
                return
            
            # Parse email
            email = self.gmail.parse_message(msg_id)
            
            # Analyze
            result = self.detector.analyze(email)
            
            # Display results
            Console.print_result(result)
            
            # Log to CSV
            self.logger.log_result(result)
            
            # Mark as processed
            self.gmail.mark_as_processed(msg_id)
            
        except Exception as e:
            print(Console.red(f"Error processing email: {e}"))


# ============================================================================
# ENTRY POINT
# ============================================================================

def main():
    """Application entry point"""
    config = Config()
    daemon = PhishingDaemon(config)
    daemon.run()


if __name__ == "__main__":
    main()
