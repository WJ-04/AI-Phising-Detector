import re
import json
from typing import Dict, List, Tuple
import requests
from bs4 import BeautifulSoup
import os
from email.utils import parseaddr
import urllib.parse

class PhishingDetector:
    def __init__(self, api_key: str):
        self.api_key = api_key
        self.base_url = "https://api.deepseek.com/v1/chat/completions"
        
        # Common phishing indicators
        self.phishing_keywords = [
            'urgent', 'immediately', 'verify', 'account suspended',
            'password expired', 'security alert', 'click here',
            'confirm your identity', 'unauthorized login attempt'
        ]
        
        self.suspicious_tlds = ['.tk', '.ml', '.ga', '.cf', '.xyz', '.top']
    
    def analyze_with_ai(self, email_content: str, metadata: Dict) -> Dict:
        """Use DeepSeek AI for advanced analysis"""
        
        prompt = f"""
        Analyze this email for phishing indicators. Be specific and technical.
        
        EMAIL METADATA:
        - From: {metadata.get('from', 'Unknown')}
        - Subject: {metadata.get('subject', 'No Subject')}
        - Has Links: {metadata.get('has_links', False)}
        - Has Attachments: {metadata.get('has_attachments', False)}
        
        EMAIL CONTENT (truncated):
        {email_content[:2000]}
        
        Analyze:
        1. Linguistic Analysis: Urgency, authority, emotional manipulation
        2. Technical Indicators: Suspicious links, sender mismatch, spoofing signs
        3. Social Engineering Tactics: Pretexting, baiting, scare tactics
        4. Overall Risk Score: 0-100 (with justification)
        5. Recommendations: What to check/do
        
        Return JSON format:
        {{
            "risk_score": 85,
            "risk_level": "HIGH",
            "indicators_found": ["urgent language", "suspicious link"],
            "technical_analysis": "Detailed explanation...",
            "social_engineering_analysis": "How attacker manipulates...",
            "recommendations": ["Don't click links", "Verify sender"],
            "confidence": 0.95
        }}
        """
        
        headers = {
            "Authorization": f"Bearer {self.api_key}",
            "Content-Type": "application/json"
        }
        
        payload = {
            "model": "deepseek-chat",
            "messages": [
                {"role": "system", "content": "You are a cybersecurity expert specializing in phishing detection. Be concise and technical."},
                {"role": "user", "content": prompt}
            ],
            "temperature": 0.3,
            "max_tokens": 1000
        }
        
        try:
            response = requests.post(self.base_url, headers=headers, json=payload)
            response.raise_for_status()
            
            ai_response = response.json()['choices'][0]['message']['content']
            
            # Extract JSON from response
            json_match = re.search(r'\{.*\}', ai_response, re.DOTALL)
            if json_match:
                return json.loads(json_match.group())
            else:
                # Fallback if AI doesn't return perfect JSON
                return self._parse_text_response(ai_response)
                
        except Exception as e:
            print(f"AI Analysis Error: {e}")
            return self._fallback_analysis(email_content, metadata)
    
    def extract_urls(self, text: str) -> List[Dict]:
        """Extract and analyze URLs from text"""
        url_pattern = r'https?://[^\s<>"]+|www\.[^\s<>"]+'
        urls = re.findall(url_pattern, text)
        
        analyzed_urls = []
        for url in urls:
            analyzed_urls.append({
                'url': url,
                'is_shortened': self._is_shortened_url(url),
                'suspicious_tld': self._has_suspicious_tld(url),
                'has_ip_address': bool(re.search(r'\d+\.\d+\.\d+\.\d+', url)),
                'redirect_depth': self._check_redirect_possibility(url)
            })
        
        return analyzed_urls
    
    def analyze_headers(self, headers: str) -> Dict:
        """Analyze email headers for spoofing"""
        analysis = {
            'spf_pass': False,
            'dkim_pass': False,
            'dmarc_pass': False,
            'sender_ip': None,
            'mail_server': None
        }
        
        # Simple header analysis (in real project, use email libraries)
        if 'spf=pass' in headers.lower():
            analysis['spf_pass'] = True
        if 'dkim=pass' in headers.lower():
            analysis['dkim_pass'] = True
            
        return analysis
    
    def _is_shortened_url(self, url: str) -> bool:
        """Check if URL uses shortening service"""
        shorteners = ['bit.ly', 'tinyurl.com', 'goo.gl', 'ow.ly', 'is.gd']
        return any(shortener in url.lower() for shortener in shorteners)
    
    def _has_suspicious_tld(self, url: str) -> bool:
        """Check for suspicious top-level domains"""
        parsed = urllib.parse.urlparse(url)
        domain = parsed.netloc
        return any(domain.endswith(tld) for tld in self.suspicious_tlds)
    
    def _check_redirect_possibility(self, url: str) -> int:
        """Estimate redirect likelihood"""
        redirect_keywords = ['redirect', 'login', 'verify', 'confirm', 'secure']
        return sum(1 for keyword in redirect_keywords if keyword in url.lower())
    
    def _parse_text_response(self, text: str) -> Dict:
        """Parse AI's text response when JSON fails"""
        # Extract risk score
        risk_match = re.search(r'risk[_\s]score[:\s]*(\d+)', text, re.IGNORECASE)
        risk_score = int(risk_match.group(1)) if risk_match else 50
        
        return {
            "risk_score": risk_score,
            "risk_level": "HIGH" if risk_score > 70 else "MEDIUM" if risk_score > 30 else "LOW",
            "indicators_found": ["AI Analysis Available"],
            "technical_analysis": text[:500],
            "recommendations": ["Review full analysis above"],
            "confidence": 0.8
        }
    
    def _fallback_analysis(self, email_content: str, metadata: Dict) -> Dict:
        """Fallback analysis if AI fails"""
        risk_score = 0
        
        # Basic keyword matching
        content_lower = email_content.lower()
        keyword_matches = sum(1 for keyword in self.phishing_keywords 
                            if keyword in content_lower)
        
        risk_score += min(keyword_matches * 15, 60)
        
        # URL analysis
        urls = self.extract_urls(email_content)
        suspicious_urls = sum(1 for url in urls if url['suspicious_tld'] or url['has_ip_address'])
        risk_score += min(suspicious_urls * 20, 40)
        
        return {
            "risk_score": min(risk_score, 100),
            "risk_level": "HIGH" if risk_score > 70 else "MEDIUM" if risk_score > 30 else "LOW",
            "indicators_found": [f"{keyword_matches} phishing keywords", 
                               f"{suspicious_urls} suspicious URLs"],
            "technical_analysis": "Basic analysis (AI unavailable)",
            "recommendations": ["Exercise caution", "Verify sender independently"],
            "confidence": 0.6
        }