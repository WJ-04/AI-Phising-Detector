import re
from typing import Dict, List, Tuple
import email
from email import policy
from email.parser import BytesParser
import html

def parse_email(raw_email: str) -> Dict:
    """Parse raw email into structured format"""
    try:
        msg = email.message_from_string(raw_email)
        
        parsed = {
            'headers': {},
            'body': '',
            'attachments': [],
            'links': []
        }
        
        # Extract headers
        for header in ['From', 'To', 'Subject', 'Date', 'Return-Path', 
                      'Received', 'Message-ID', 'Content-Type']:
            if header in msg:
                parsed['headers'][header] = msg[header]
        
        # Extract body
        if msg.is_multipart():
            for part in msg.walk():
                content_type = part.get_content_type()
                if content_type == 'text/plain':
                    parsed['body'] += part.get_payload(decode=True).decode(errors='ignore')
                elif content_type == 'text/html':
                    # Convert HTML to text
                    html_content = part.get_payload(decode=True).decode(errors='ignore')
                    parsed['body'] += html_to_text(html_content)
                elif part.get_filename():
                    parsed['attachments'].append(part.get_filename())
        else:
            parsed['body'] = msg.get_payload(decode=True).decode(errors='ignore')
        
        # Extract links
        parsed['links'] = extract_links(parsed['body'])
        
        return parsed
        
    except Exception as e:
        print(f"Error parsing email: {e}")
        return {'body': raw_email, 'headers': {}, 'attachments': [], 'links': []}

def extract_metadata(raw_email: str) -> Dict:
    """Extract basic metadata from email"""
    metadata = {
        'from': 'Unknown',
        'subject': 'No Subject',
        'has_links': False,
        'has_attachments': False,
        'date': None
    }
    
    # Simple regex extraction (for demo)
    from_match = re.search(r'From:\s*(.+)', raw_email, re.IGNORECASE)
    if from_match:
        metadata['from'] = from_match.group(1).strip()
    
    subject_match = re.search(r'Subject:\s*(.+)', raw_email, re.IGNORECASE)
    if subject_match:
        metadata['subject'] = subject_match.group(1).strip()
    
    # Check for links
    url_pattern = r'https?://[^\s<>"]+|www\.[^\s<>"]+'
    metadata['has_links'] = bool(re.search(url_pattern, raw_email))
    
    # Check for attachments
    metadata['has_attachments'] = 'Content-Disposition: attachment' in raw_email
    
    return metadata

def html_to_text(html_content: str) -> str:
    """Convert HTML to plain text"""
    try:
        # Remove scripts and styles
        html_content = re.sub(r'<script[^>]*>.*?</script>', '', html_content, flags=re.DOTALL)
        html_content = re.sub(r'<style[^>]*>.*?</style>', '', html_content, flags=re.DOTALL)
        
        # Convert HTML entities
        text = html.unescape(html_content)
        
        # Replace tags with spaces
        text = re.sub(r'<[^>]+>', ' ', text)
        
        # Collapse multiple spaces/newlines
        text = re.sub(r'\s+', ' ', text)
        
        return text.strip()
    except:
        return html_content

def extract_links(text: str) -> List[str]:
    """Extract all URLs from text"""
    url_pattern = r'https?://[^\s<>"]+|www\.[^\s<>"]+'
    return re.findall(url_pattern, text)

def calculate_risk_score(indicators: Dict) -> int:
    """Calculate risk score based on indicators"""
    score = 0
    
    # Content indicators
    phishing_keywords = ['urgent', 'verify', 'suspended', 'click', 'password']
    for keyword in phishing_keywords:
        if keyword in indicators.get('content', '').lower():
            score += 10
    
    # URL indicators
    suspicious_domains = ['.xyz', '.top', '.tk', '.ml']
    for url in indicators.get('urls', []):
        if any(domain in url for domain in suspicious_domains):
            score += 20
    
    # Sender indicators
    if 'mismatch' in indicators.get('sender_analysis', ''):
        score += 30
    
    return min(score, 100)