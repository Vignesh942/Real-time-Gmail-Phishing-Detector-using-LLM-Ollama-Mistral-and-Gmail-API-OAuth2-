# heuristics.py
# Optional: contains URL/keyword heuristic functions

import re
from typing import List, Tuple, Dict

from phishing_detector import Config  # Assuming Config is available; adjust import if needed


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


class HeuristicAnalyzer:
    """Analyzes emails using heuristic rules"""
    
    def __init__(self, config: Config):
        self.config = config
        self.url_analyzer = URLAnalyzer()
    
    def analyze(self, email) -> 'HeuristicResult':  # Forward ref to HeuristicResult
        """Perform heuristic analysis on email"""
        from phishing_detector import HeuristicResult  # Import here to avoid circular
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
