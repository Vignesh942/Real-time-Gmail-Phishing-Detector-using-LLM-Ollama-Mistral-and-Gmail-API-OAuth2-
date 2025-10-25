# ollama_client.py
# Wrapper for Ollama LLM calls

import json
import re

from ollama import Client

from phishing_detector import Config, Console, LLMResult


class LLMAnalyzer:
    """Analyzes emails using Ollama LLM"""
    
    def __init__(self, config: Config):
        self.config = config
        try:
            self.client = Client()
        except Exception as e:
            print(Console.red(f"Error initializing Ollama client: {e}"))
            self.client = None
    
    def analyze(self, email) -> LLMResult:
        """Perform LLM analysis on email"""
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
    
    def _build_prompt(self, email) -> str:
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
