# phishing_detector.py
# Main Python script (runs the detector)

import os
import time
import sys
import platform
import json
import pandas as pd
from datetime import datetime, timedelta
from collections import defaultdict
from typing import Tuple, Dict, List, Optional, Set
from dataclasses import dataclass, asdict

from heuristics import HeuristicAnalyzer, URLAnalyzer
from gmail_utils import GmailService
from ollama_client import LLMAnalyzer

# Note: config.json should be loaded here
with open('config.json', 'r') as f:
    config_data = json.load(f)

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


class Config:
    """Application configuration loaded from JSON"""
    def __init__(self):
        self.CREDENTIALS_FILE = config_data.get("CREDENTIALS_FILE", "Yourcredentials.json_name")
        self.TOKEN_FILE = config_data.get("TOKEN_FILE", "token.pickle")
        self.SCOPES = config_data.get("SCOPES", [])
        
        self.OLLAMA_MODEL = config_data.get("OLLAMA_MODEL", "dolphin-mistral")
        self.LOG_CSV = config_data.get("LOG_CSV", "gmail_phish_log.csv")
        self.PROCESSED_LABEL = config_data.get("PROCESSED_LABEL", "Processed-By-Ollama")
        self.PHISHING_LABEL = config_data.get("PHISHING_LABEL", "⚠️-Phishing-Alert")
        self.SAFE_LABEL = config_data.get("SAFE_LABEL", "✓-Verified-Safe")
        self.POLL_INTERVAL_SECS = config_data.get("POLL_INTERVAL_SECS", 20)
        
        self.HEURISTIC_THRESHOLD = config_data.get("HEURISTIC_THRESHOLD", 0.5)
        self.LLM_SKIP_THRESHOLD = config_data.get("LLM_SKIP_THRESHOLD", 0.08)
        
        self.AUTO_QUARANTINE = config_data.get("AUTO_QUARANTINE", True)
        self.WHITELIST_FILE = config_data.get("WHITELIST_FILE", "trusted_senders.txt")
        self.BLACKLIST_FILE = config_data.get("BLACKLIST_FILE", "blocked_senders.txt")
        self.STATS_FILE = config_data.get("STATS_FILE", "detection_stats.json")
        self.ENABLE_NOTIFICATIONS = config_data.get("ENABLE_NOTIFICATIONS", False)
        self.ENABLE_EMAIL_REPORTS = config_data.get("ENABLE_EMAIL_REPORTS", False)
        self.REPORT_EMAIL = config_data.get("REPORT_EMAIL", "your-email@gmail.com")
        
        self.ENABLE_LEARNING = config_data.get("ENABLE_LEARNING", True)
        self.TRAINING_DATA_FILE = config_data.get("TRAINING_DATA_FILE", "training_data.csv")
        
        self.URL_PATTERN = config_data.get("URL_PATTERN", r'https?://[^\s<>"\'\)]+|www\.[^\s<>"\'\)]+')
        
        self.URGENT_KEYWORDS = config_data.get("URGENT_KEYWORDS", [
            "urgent", "immediately", "asap", "suspend", "suspended",
            "verify", "verify your", "click here", "update", 
            "expired", "act now", "confirm", "secure your account"
        ])
        self.SENSITIVE_INFO_KEYWORDS = config_data.get("SENSITIVE_INFO_KEYWORDS", [
            "password", "account number", "ssn", "social security", 
            "card", "cvv", "pin", "bank details", "credit card"
        ])
        self.PHISHING_INDICATORS = config_data.get("PHISHING_INDICATORS", [
            "phish", "suspicious", "malicious", "scam", "fraud", "fake"
        ])
        self.SAFE_INDICATORS = config_data.get("SAFE_INDICATORS", [
            "legitimate", "safe", "authentic", "genuine", "valid"
        ])
        
        self.MAX_RETRIES = config_data.get("MAX_RETRIES", 3)
        self.RETRY_DELAY = config_data.get("RETRY_DELAY", 2)


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
        import re
        match = re.search(r'<(.+?)>', sender)
        if match:
            return match.group(1).lower()
        return sender.lower()


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


class EnhancedPhishingDaemon(PhishingDaemon):
    """Enhanced daemon with interactive features"""
    
    def __init__(self, config: Config):
        super().__init__(config)
        self.notification_system = NotificationSystem(config)
        self.report_generator = ReportGenerator(config, self.stats)
        self.last_result = None
        self.command_handler = CommandHandler(self)
    
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
            
            # Interactive command input (simplified; in full impl, use select or threading for non-blocking)
            try:
                cmd = input("Enter command (w/b/f/r/s/help/enter): ").strip()
                if cmd:
                    self.command_handler.handle_command(cmd, result)
            except:
                pass  # Continue on input error
            
        except Exception as e:
            print(Console.red(f"Error processing email: {e}"))
    
    def _shutdown(self):
        """Clean shutdown with final reports"""
        print(Console.yellow("\n\n" + "="*80))
        print(Console.bold("📊 FINAL SESSION REPORT"))
        print("="*80)
        print(self.stats.get_summary())
        print(self.stats.get_daily_summary())
        
        print(Console.cyan("\n💾 Generate full report? (y/n): "), end="", flush=True)
        try:
            choice = input().lower()
            if choice == 'y':
                self.report_generator.save_report()
        except:
            pass
        
        print(Console.yellow("="*80))
        print(Console.yellow("\n👋 Daemon stopped. Stay safe online!"))


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
