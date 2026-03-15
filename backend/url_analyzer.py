"""
URL Analyzer Module for Phishing Attack Defender
Analyzes URLs for various phishing indicators and calculates risk score
Integrates with Google Safe Browsing API and WHOIS API for enhanced detection
"""

import os
import re
import requests
from datetime import datetime
from urllib.parse import urlparse


# Environment variables for API keys
SAFE_BROWSING_API_KEY = os.environ.get('SAFE_BROWSING_API_KEY', '')
WHOIS_API_KEY = os.environ.get('WHOIS_API_KEY', '')

# Suspicious words commonly found in phishing URLs
SUSPICIOUS_WORDS = [
    'login', 'verify', 'update', 'secure', 'bank',
    'account', 'confirm', 'password', 'credential',
    'signin', 'validate', 'payment', 'invoice',
    'support', 'customer', 'service', 'alert'
]

# Minimum URL length to be considered suspicious
MIN_SUSPICIOUS_LENGTH = 75

# Maximum allowed URL length
MAX_URL_LENGTH = 200

# Minimum domain age in days to be considered potentially suspicious
MIN_DOMAIN_AGE_DAYS = 90


def check_google_safe_browsing(url):
    """
    Check URL against Google Safe Browsing API
    
    Args:
        url (str): The URL to check
        
    Returns:
        dict: Contains is_safe (bool) and threats (list)
    """
    if not SAFE_BROWSING_API_KEY:
        return {
            'is_safe': True,
            'threats': [],
            'error': 'Safe Browsing API key not configured'
        }
    
    try:
        safe_browsing_url = (
            f"https://safebrowsing.googleapis.com/v4/threatMatches:find"
            f"?key={SAFE_BROWSING_API_KEY}"
        )
        
        payload = {
            "client": {
                "clientId": "phishing-attack-defender",
                "clientVersion": "1.0.0"
            },
            "threatInfo": {
                "threatTypes": [
                    "MALWARE",
                    "SOCIAL_ENGINEERING",
                    "UNWANTED_SOFTWARE",
                    "POTENTIALLY_HARMFUL_APPLICATION"
                ],
                "platformTypes": ["ANY_PLATFORM"],
                "threatEntryTypes": ["URL"],
                "threatEntries": [
                    {"url": url}
                ]
            }
        }
        
        response = requests.post(safe_browsing_url, json=payload, timeout=10)
        
        if response.status_code == 200:
            data = response.json()
            if 'matches' in data and len(data['matches']) > 0:
                threats = [match['threatType'] for match in data['matches']]
        
        return {
            'is_safe': True,
            'threats': [],
            'error': None
        }
        
    except Exception as e:
        return {
            'is_safe': True,
            'threats': [],
            'error': str(e)
        }


def check_whois_info(url):
    """
    Check domain WHOIS information using ipapi.co WHOIS API
    
    Args:
        url (str): The URL to check
        
    Returns:
        dict: Contains domain creation date, expiration date, age_days, is_new
    """
    try:
        # Parse the domain from URL
        parsed = urlparse(url if url.startswith(('http://', 'https://')) else 'http://' + url)
        domain = parsed.netloc.lower()
        
        # Remove port if present
        if ':' in domain:
            domain = domain.split(':')[0]
        
        # Remove www. prefix
        if domain.startswith('www.'):
            domain = domain[4:]
        
        # Use ipapi.co WHOIS API (free tier available)
        whois_url = f"https://ipapi.co/{domain}/json/whois/"
        
        headers = {}
        if WHOIS_API_KEY:
            headers['Authorization'] = f'Bearer {WHOIS_API_KEY}'
        
        response = requests.get(whois_url, headers=headers, timeout=10)
        
        if response.status_code == 200:
            data = response.json()
            
            if data.get('error'):
                return {
                    'creation_date': None,
                    'expiration_date': None,
                    'age_days': None,
                    'is_new': False,
                    'error': data.get('reason', 'WHOIS data not available')
                }
            
            creation_date = data.get('creation_date')
            expiration_date = data.get('expiration_date')
            
            if creation_date:
                try:
                    # Handle Unix timestamp
                    if isinstance(creation_date, (int, float)):
                        creation_datetime = datetime.fromtimestamp(creation_date)
                    else:
                        creation_datetime = datetime.fromisoformat(creation_date.replace('Z', '+00:00'))
                    
                    # Calculate domain age
                    age_days = (datetime.now() - creation_datetime.replace(tzinfo=None)).days
                    
                    is_new = age_days < MIN_DOMAIN_AGE_DAYS
                    
                    return {
                        'creation_date': creation_datetime.strftime('%Y-%m-%d'),
                        'expiration_date': expiration_date,
                        'age_days': age_days,
                        'is_new': is_new,
                        'error': None
                    }
                except Exception as e:
                    return {
                        'creation_date': creation_date,
                        'expiration_date': expiration_date,
                        'age_days': None,
                        'is_new': False,
                        'error': str(e)
                    }
        
        return {
            'creation_date': None,
            'expiration_date': None,
            'age_days': None,
            'is_new': False,
            'error': 'WHOIS API request failed'
        }
        
    except Exception as e:
        return {
            'creation_date': None,
            'expiration_date': None,
            'age_days': None,
            'is_new': False,
            'error': str(e)
        }


def analyze_url(url):
    """
    Analyze a URL for phishing indicators
    
    Args:
        url (str): The URL to analyze
        
    Returns:
        dict: Contains risk_score (0-100), status (safe/phishing), and message
    """
    # Initialize risk score
    risk_score = 0
    
    # Store analysis details for debugging
    analysis_details = {
        'url_length_score': 0,
        'ip_address_score': 0,
        'suspicious_words_score': 0,
        'protocol_score': 0,
        'special_chars_score': 0,
        'domain_score': 0,
        'safe_browsing_score': 0,
        'whois_score': 0
    }
    
    # API check results
    safe_browsing_result = {'is_safe': True, 'threats': [], 'error': None}
    whois_result = {
        'creation_date': None,
        'expiration_date': None,
        'age_days': None,
        'is_new': False,
        'error': None
    }
    
    # 1. Check URL length
    url_length = len(url)
    if url_length > MAX_URL_LENGTH:
        risk_score += 30
        analysis_details['url_length_score'] = 30
    elif url_length > MIN_SUSPICIOUS_LENGTH:
        risk_score += 15
        analysis_details['url_length_score'] = 15
    elif url_length > 50:
        risk_score += 5
        analysis_details['url_length_score'] = 5
    
    # 2. Check if URL contains an IP address
    ip_pattern = r'\b(?:(?:25[0-5]|2[0-4][0-9]|[01]?[0-9][0-9]?)\.){3}(?:25[0-5]|2[0-4][0-9]|[01]?[0-9][0-9]?)\b'
    if re.search(ip_pattern, url):
        risk_score += 25
        analysis_details['ip_address_score'] = 25
    
    # 3. Check for suspicious words
    url_lower = url.lower()
    suspicious_word_count = 0
    
    for word in SUSPICIOUS_WORDS:
        if word in url_lower:
            suspicious_word_count += 1
    
    if suspicious_word_count > 0:
        word_score = min(suspicious_word_count * 8, 25)
        risk_score += word_score
        analysis_details['suspicious_words_score'] = word_score
    
    # 4. Check protocol (HTTP vs HTTPS)
    if not url.startswith(('http://', 'https://')):
        # URL without protocol
        risk_score += 10
        analysis_details['protocol_score'] = 10
    elif url.startswith('http://'):
        # HTTP instead of HTTPS
        risk_score += 15
        analysis_details['protocol_score'] = 15
    
    # 5. Check for too many special characters
    special_char_count = url.count('@') + url.count('-') + url.count('_') + url.count('.')
    if special_char_count > 10:
        risk_score += 10
        analysis_details['special_chars_score'] = 10
    elif special_char_count > 5:
        risk_score += 5
        analysis_details['special_chars_score'] = 5
    
    # Check for @ symbol (common in phishing URLs)
    if '@' in url:
        risk_score += 20
        analysis_details['special_chars_score'] += 20
    
    # 6. Check for suspicious domain patterns
    try:
        parsed = urlparse(url if url.startswith(('http://', 'https://')) else 'http://' + url)
        domain = parsed.netloc.lower()
        
        # Check for multiple dots in domain (common in phishing)
        if domain.count('.') > 3:
            risk_score += 10
            analysis_details['domain_score'] = 10
        
        # Check for numbers in domain (except port)
        domain_without_port = domain.split(':')[0]
        if re.search(r'\d', domain_without_port):
            # Check if it's an IP address (already handled above)
            if not re.match(ip_pattern, domain_without_port):
                risk_score += 5
                analysis_details['domain_score'] += 5
        
        # Check for suspicious TLDs
        suspicious_tlds = ['.xyz', '.top', '.gq', '.tk', '.ml', '.cf', '.ga', '.click', '.work']
        for tld in suspicious_tlds:
            if domain.endswith(tld):
                risk_score += 15
                analysis_details['domain_score'] += 15
                break
                
    except Exception:
        # If parsing fails, add some risk
        risk_score += 5
    
    # 7. Check for URL encoding or obfuscation
    if '%' in url and '%20' in url:
        risk_score += 5
    
    # 8. Check for very long subdomains
    try:
        parsed = urlparse(url if url.startswith(('http://', 'https://')) else 'http://' + url)
        subdomain = parsed.netloc.split('.')
        if len(subdomain) > 4:
            risk_score += 10
            analysis_details['domain_score'] += 10
    except Exception:
        pass
    
    # === External API Checks ===
    
    # 9. Google Safe Browsing API check
    safe_browsing_result = check_google_safe_browsing(url)
    if not safe_browsing_result['is_safe']:
        # High risk if flagged by Google
        risk_score += 40
        analysis_details['safe_browsing_score'] = 40
    
    # 10. WHOIS domain age check
    whois_result = check_whois_info(url)
    if whois_result.get('is_new'):
        # New domains are more suspicious
        risk_score += 25
        analysis_details['whois_score'] = 25
    
    # Cap the risk score at 100
    risk_score = min(risk_score, 100)
    
    # Determine status based on risk score and API results
    if risk_score >= 50 or not safe_browsing_result['is_safe']:
        status = "phishing"
        message = "Possible Phishing Website"
    else:
        status = "safe"
        message = "Website appears safe"
    
    return {
        'status': status,
        'risk_score': risk_score,
        'message': message,
        'analysis': analysis_details,
        'url': url,
        'safe_browsing': {
            'is_safe': safe_browsing_result['is_safe'],
            'threats': safe_browsing_result['threats']
        },
        'whois': {
            'creation_date': whois_result.get('creation_date'),
            'expiration_date': whois_result.get('expiration_date'),
            'age_days': whois_result.get('age_days'),
            'is_new': whois_result.get('is_new')
        }
    }


if __name__ == '__main__':
    # Test the analyzer
    test_urls = [
        'http://192.168.1.1/login.php',
        'https://secure-bank.com-verify.com/login',
        'https://www.google.com',
        'http://example.com/update-account-login-verify.php',
        'https://paypal-secure-verify.tk/login'
    ]
    
    print("URL Analyzer Test Results:")
    print("-" * 60)
    
    for test_url in test_urls:
        result = analyze_url(test_url)
        print(f"\nURL: {test_url}")
        print(f"Status: {result['status']}")
        print(f"Risk Score: {result['risk_score']}%")
        print(f"Message: {result['message']}")
        print("-" * 60)

