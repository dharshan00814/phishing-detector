"""
Flask backend for Phishing Attack Defender
API endpoint to check URLs for phishing indicators
"""

import os
import pickle
import re
import sys
from datetime import datetime
from difflib import SequenceMatcher
from urllib.parse import urlparse
from flask import Flask, request, jsonify, send_from_directory
from flask_cors import CORS
import pandas as pd
from url_analyzer import analyze_url, check_google_safe_browsing, check_whois_info, SUSPICIOUS_WORDS


# Make phishing_ml_model importable from backend/
PROJECT_ROOT = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
ML_MODEL_DIR = os.path.join(PROJECT_ROOT, 'phishing_ml_model')
FRONTEND_DIR = os.path.join(PROJECT_ROOT, 'frontend')
if ML_MODEL_DIR not in sys.path:
    sys.path.append(ML_MODEL_DIR)

from feature_extractor import FEATURE_NAMES, extract_features
from email_feature_extractor import EMAIL_FEATURE_NAMES, extract_email_features

app = Flask(__name__, static_folder=FRONTEND_DIR, static_url_path='')

# Enable CORS to allow frontend to communicate with backend
CORS(app)

MODEL_PATH = os.path.join(ML_MODEL_DIR, 'model.pkl')
EMAIL_MODEL_PATH = os.path.join(ML_MODEL_DIR, 'email_model.pkl')
_ML_MODEL = None
_EMAIL_MODEL = None


@app.get('/')
def serve_index():
    """Serve frontend entry page from backend root."""
    return send_from_directory(FRONTEND_DIR, 'index.html')


@app.get('/<path:asset_path>')
def serve_frontend_asset(asset_path):
    """Serve static frontend assets when running only Flask backend."""
    full_path = os.path.join(FRONTEND_DIR, asset_path)
    if os.path.isfile(full_path):
        return send_from_directory(FRONTEND_DIR, asset_path)
    return send_from_directory(FRONTEND_DIR, 'index.html')

# Public tunnel domains are frequently abused for short-lived phishing pages.
SUSPICIOUS_TUNNEL_DOMAINS = [
    'trycloudflare.com',
    'ngrok-free.app',
    'ngrok.io',
    'loca.lt',
    'localtunnel.me',
    'serveo.net',
]

SUSPICIOUS_DOMAIN_TLDS = [
    '.xyz', '.top', '.gq', '.tk', '.ml', '.cf', '.ga', '.click', '.work', '.zip', '.mov'
]

HIGH_VALUE_BRANDS = [
    'paypal', 'google', 'microsoft', 'apple', 'amazon', 'facebook', 'instagram',
    'whatsapp', 'telegram', 'netflix', 'coinbase', 'binance', 'icloud', 'chase',
    'bankofamerica', 'outlook', 'office365', 'gmail', 'yahoo', 'dropbox'
]

TRUSTED_BASE_DOMAINS = [
    'google.com',
    'microsoft.com',
    'live.com',
    'office.com',
    'apple.com',
    'paypal.com',
    'amazon.com',
    'github.com',
]


def load_ml_model():
    """Load URL ML model once and cache in memory."""
    global _ML_MODEL
    if _ML_MODEL is None:
        if not os.path.exists(MODEL_PATH):
            raise FileNotFoundError(
                f"model.pkl not found at {MODEL_PATH}. Run phishing_ml_model/train_models.py first."
            )
        with open(MODEL_PATH, 'rb') as f:
            _ML_MODEL = pickle.load(f)
    return _ML_MODEL


def load_email_ml_model():
    """Load email ML model once and cache in memory."""
    global _EMAIL_MODEL
    if _EMAIL_MODEL is None:
        if not os.path.exists(EMAIL_MODEL_PATH):
            raise FileNotFoundError(
                f"email_model.pkl not found at {EMAIL_MODEL_PATH}. Run phishing_ml_model/train_models.py first."
            )
        with open(EMAIL_MODEL_PATH, 'rb') as f:
            _EMAIL_MODEL = pickle.load(f)
    return _EMAIL_MODEL


def predict_url_ml(url):
    """Predict phishing vs legitimate from URL features using the trained model."""
    model = load_ml_model()
    features = extract_features(url)
    features_df = pd.DataFrame([features], columns=FEATURE_NAMES)

    prediction = int(model.predict(features_df)[0])
    probabilities = model.predict_proba(features_df)[0]
    confidence = round(float(probabilities[prediction]) * 100, 2)

    if prediction == 1:
        status = 'phishing'
        risk_score = confidence
        message = 'Possible Phishing Website (ML model)'
    else:
        status = 'safe'
        risk_score = round(100 - confidence, 2)
        message = 'Website appears safe (ML model)'

    return {
        'status': status,
        'risk_score': risk_score,
        'message': message,
        'prediction': prediction,
        'ml_confidence': confidence,
    }


def _get_domain(url):
    parsed = urlparse(url if url.startswith(('http://', 'https://')) else f'http://{url}')
    domain = parsed.netloc.lower().split(':')[0]
    return domain[4:] if domain.startswith('www.') else domain


def _is_trusted_domain(domain):
    domain = (domain or '').lower()
    return any(domain == base or domain.endswith(f'.{base}') for base in TRUSTED_BASE_DOMAINS)


def _has_www_typo_prefix(domain):
    """Detect common typo where ww. is used instead of www."""
    return (domain or '').lower().startswith('ww.')


def combine_scan_result(url):
    """Combine ML + rule-based output and apply hardening rules."""
    ml_result = predict_url_ml(url)
    rule_result = analyze_url(url)
    domain = _get_domain(url)

    # Start with the max of both scores so either detector can raise risk.
    risk_score = max(float(ml_result['risk_score']), float(rule_result['risk_score']))
    reason = []

    # Harden against known phishing-abused tunnel providers.
    if any(domain.endswith(tunnel) for tunnel in SUSPICIOUS_TUNNEL_DOMAINS):
        risk_score = max(risk_score, 85.0)
        reason.append('Known temporary tunnel domain')

    # Common typo pattern: ww.<brand>.com should not be treated as trusted www.
    if _has_www_typo_prefix(domain):
        risk_score = max(risk_score, 70.0)
        reason.append('Possible typo domain prefix (ww. instead of www.)')

    # Low-confidence ML safe prediction should not be treated as fully safe.
    if ml_result['prediction'] == 0 and ml_result['ml_confidence'] < 70:
        risk_score = max(risk_score, 60.0)
        reason.append('Low confidence safe prediction')

    # Prevent false positives on known trusted HTTPS domains unless threat intel flags them.
    safe_browsing_is_safe = rule_result.get('safe_browsing', {}).get('is_safe', True)
    if (
        url.startswith('https://')
        and _is_trusted_domain(domain)
        and not _has_www_typo_prefix(domain)
        and safe_browsing_is_safe is not False
        and not any(domain.endswith(tunnel) for tunnel in SUSPICIOUS_TUNNEL_DOMAINS)
    ):
        risk_score = min(risk_score, 20.0)
        reason = [item for item in reason if item != 'Low confidence safe prediction']
        reason.append('Trusted domain allowlist')

    risk_score = min(round(risk_score, 2), 100.0)

    if risk_score >= 70:
        status = 'phishing'
        message = 'Possible Phishing Website'
    elif risk_score >= 40:
        status = 'suspicious'
        message = 'Suspicious Website - proceed with caution'
    else:
        status = 'safe'
        message = 'Website appears safe'

    if reason:
        message = f"{message} ({'; '.join(reason)})"

    return {
        'status': status,
        'risk_score': risk_score,
        'message': message,
        'ml_confidence': ml_result['ml_confidence'],
        'ml': ml_result,
        'rule_based': rule_result,
    }


def _normalize_domain(value):
    value = (value or '').strip().lower()
    if not value:
        return ''
    parsed = urlparse(value if value.startswith(('http://', 'https://')) else f'http://{value}')
    domain = parsed.netloc or parsed.path
    domain = domain.split(':')[0]
    return domain[4:] if domain.startswith('www.') else domain


def _extract_urls_from_text(text):
    # Extract links from plain text emails:
    # 1) Explicit URLs (http/https, www)
    # 2) Bare domains like "paypa1.com/login" without protocol
    content = text or ''
    explicit_pattern = re.compile(r'(https?://[^\s<>"\']+|www\.[^\s<>"\']+)', re.IGNORECASE)
    bare_domain_pattern = re.compile(
        r'(?<!@)\b(?:[a-z0-9](?:[a-z0-9-]{0,61}[a-z0-9])?\.)+(?:[a-z]{2,24})(?:/[^\s<>"\']*)?',
        re.IGNORECASE,
    )

    found = explicit_pattern.findall(content)
    content_without_explicit = explicit_pattern.sub(' ', content)
    found.extend(bare_domain_pattern.findall(content_without_explicit))

    cleaned = []
    for item in found:
        candidate = str(item).strip().rstrip('.,);]}>"\'')
        if not candidate:
            continue
        if candidate.lower().startswith('www.'):
            candidate = f'http://{candidate}'
        elif not candidate.lower().startswith(('http://', 'https://')):
            candidate = f'http://{candidate}'
        cleaned.append(candidate)

    # Preserve order while removing duplicates.
    return list(dict.fromkeys(cleaned))


def _simple_domain_distance(a, b):
    # Levenshtein distance for typosquat similarity scoring.
    if a == b:
        return 0
    if not a:
        return len(b)
    if not b:
        return len(a)

    prev = list(range(len(b) + 1))
    for i, ca in enumerate(a, start=1):
        curr = [i]
        for j, cb in enumerate(b, start=1):
            ins = curr[j - 1] + 1
            dele = prev[j] + 1
            sub = prev[j - 1] + (ca != cb)
            curr.append(min(ins, dele, sub))
        prev = curr
    return prev[-1]


def _is_ipv4_domain(domain):
    return bool(re.fullmatch(r'(?:(?:25[0-5]|2[0-4][0-9]|[01]?[0-9][0-9]?)\.){3}(?:25[0-5]|2[0-4][0-9]|[01]?[0-9][0-9]?)', domain))


def _normalize_lookalike_label(value):
    substitutions = str.maketrans({
        '0': 'o',
        '1': 'l',
        '3': 'e',
        '4': 'a',
        '5': 's',
        '7': 't',
        '8': 'b',
        '9': 'g',
    })
    return value.translate(substitutions)


def evaluate_domain_checker(domain):
    normalized_domain = _normalize_domain(domain)
    if not normalized_domain:
        raise ValueError('domain is required')

    labels = [label for label in normalized_domain.split('.') if label]
    host_part = '.'.join(labels[:-1]) if len(labels) > 1 else normalized_domain
    comparable_host = host_part.replace('.', '')
    normalized_host = _normalize_lookalike_label(comparable_host)
    risk_score = 0
    indicators = []

    if _is_ipv4_domain(normalized_domain):
        risk_score += 60
        indicators.append('Domain is an IP address instead of a registered hostname')

    if any(label.startswith('xn--') for label in labels):
        risk_score += 35
        indicators.append('Punycode domain detected, possible homograph attack')

    if any(normalized_domain.endswith(tld) for tld in SUSPICIOUS_DOMAIN_TLDS):
        risk_score += 20
        indicators.append('High-risk top-level domain')

    if any(normalized_domain.endswith(tunnel) for tunnel in SUSPICIOUS_TUNNEL_DOMAINS):
        risk_score += 40
        indicators.append('Temporary tunnel domain commonly abused in phishing')

    hyphen_count = normalized_domain.count('-')
    if hyphen_count >= 2:
        risk_score += 12
        indicators.append('Multiple hyphens in domain name')
    elif hyphen_count == 1:
        risk_score += 5

    if len(normalized_domain) >= 45:
        risk_score += 12
        indicators.append('Unusually long domain name')
    elif len(normalized_domain) >= 30:
        risk_score += 6

    if len(labels) > 3:
        risk_score += 12
        indicators.append('Excessive subdomains')

    if labels and labels[0] == 'ww':
        risk_score += 35
        indicators.append('Typo prefix detected: ww. (expected www.)')

    digit_count = sum(char.isdigit() for char in host_part)
    if digit_count >= 2:
        risk_score += 8
        indicators.append('Multiple digits found in domain name')

    domain_keywords = [word for word in SUSPICIOUS_WORDS if word in normalized_domain]
    if domain_keywords:
        keyword_score = min(len(domain_keywords) * 6, 18)
        risk_score += keyword_score
        indicators.append(f"Suspicious keywords in domain: {', '.join(domain_keywords[:3])}")

    matched_brand = None
    for brand in HIGH_VALUE_BRANDS:
        if normalized_domain == brand or normalized_domain.endswith(f'.{brand}.com'):
            continue

        # Catch obfuscated brand names like g00gle.com where 0->o normalization matches.
        if normalized_host == brand and comparable_host != brand:
            risk_score += 60
            matched_brand = brand
            indicators.append(f'Lookalike domain using character substitution: {brand}')
            break

        if brand in normalized_host and normalized_host != brand:
            risk_score += 30
            matched_brand = brand
            indicators.append(f'Contains a high-value brand name: {brand}')
            break

        distance = _simple_domain_distance(normalized_host, brand)
        similarity = SequenceMatcher(None, normalized_host, brand).ratio()
        if normalized_host != brand and distance <= 2 and similarity >= 0.72:
            risk_score += 40
            matched_brand = brand
            indicators.append(f'Looks similar to brand domain: {brand}')
            break

    candidate_labels = [host_part, comparable_host, normalized_host]
    if not matched_brand:
        for label in candidate_labels:
            for brand in HIGH_VALUE_BRANDS:
                if label == brand:
                    continue
                if brand in label and label != brand:
                    risk_score += 22
                    matched_brand = brand
                    indicators.append(f'Embedded brand impersonation pattern: {brand}')
                    break
            if matched_brand:
                break

    safe_browsing = check_google_safe_browsing(f'https://{normalized_domain}')
    if safe_browsing.get('is_safe') is False:
        risk_score += 50
        indicators.append('Flagged by Google Safe Browsing')

    whois = check_whois_info(f'https://{normalized_domain}')
    if whois.get('is_new'):
        risk_score += 20
        indicators.append('Recently registered domain')

    # Blend ML output so retraining improves domain checker behavior.
    ml_result = predict_url_ml(f'https://{normalized_domain}')
    if ml_result['status'] == 'phishing':
        risk_score += min(30, max(12, int(ml_result['ml_confidence'] * 0.3)))
        indicators.append('ML model predicts phishing-like domain pattern')
    elif ml_result['ml_confidence'] < 65:
        risk_score += 8
        indicators.append('ML confidence is low for legitimate prediction')

    risk_score = min(risk_score, 100)

    if risk_score >= 65:
        status = 'phishing'
        verdict = 'phishing'
        message = 'The domain shows strong phishing indicators.'
    elif risk_score >= 40:
        status = 'suspicious'
        verdict = 'phishing'
        message = 'The domain looks suspicious and may be phishing.'
    else:
        status = 'safe'
        verdict = 'not_phishing'
        message = 'The domain does not show strong phishing indicators.'

    return {
        'domain': normalized_domain,
        'status': status,
        'verdict': verdict,
        'risk_score': risk_score,
        'message': message,
        'indicators': indicators,
        'safe_browsing': {
            'is_safe': safe_browsing.get('is_safe', True),
            'threats': safe_browsing.get('threats', []),
        },
        'whois': {
            'creation_date': whois.get('creation_date'),
            'expiration_date': whois.get('expiration_date'),
            'age_days': whois.get('age_days'),
            'is_new': whois.get('is_new'),
        },
        'ml_confidence': ml_result['ml_confidence'],
        'ml_status': ml_result['status'],
    }


@app.route('/scan-url', methods=['POST'])
def scan_url():
    """
    API endpoint to scan a URL for phishing indicators
    Accepts: POST request with JSON body containing 'url'
    Returns: JSON with status, risk_score, and message
    """
    try:
        data = request.get_json()
        
        if not data or 'url' not in data:
            return jsonify({
                'error': 'URL is required in the request body'
            }), 400
        
        url = data['url']
        
        if not url or not isinstance(url, str):
            return jsonify({
                'error': 'Invalid URL provided'
            }), 400
        
        # Use combined decision to reduce ML false negatives.
        result = combine_scan_result(url)

        # Also print a compact answer in the backend terminal for visibility.
        print(
            f"[SCAN] URL={url} | status={result['status']} | risk={result['risk_score']}% | "
            f"ml_confidence={result['ml_confidence']}%"
        )
        
        # Return the result in the required format
        return jsonify({
            'status': result['status'],
            'risk_score': result['risk_score'],
            'message': result['message'],
            'ml_confidence': result['ml_confidence'],
        })
    
    except Exception as e:
        return jsonify({
            'error': f'Server error: {str(e)}'
        }), 500


@app.route('/scan-url-detailed', methods=['POST'])
def scan_url_detailed():
    """
    API endpoint to scan a URL with detailed analysis results
    Accepts: POST request with JSON body containing 'url'
    Returns: JSON with full analysis details including Safe Browsing and WHOIS data
    """
    try:
        data = request.get_json()
        
        if not data or 'url' not in data:
            return jsonify({
                'error': 'URL is required in the request body'
            }), 400
        
        url = data['url']
        
        if not url or not isinstance(url, str):
            return jsonify({
                'error': 'Invalid URL provided'
            }), 400
        
        result = combine_scan_result(url)

        return jsonify({
            'url': url,
            'status': result['status'],
            'risk_score': result['risk_score'],
            'message': result['message'],
            'ml_confidence': result['ml_confidence'],
            'rule_based': result['rule_based'],
            'ml': result['ml'],
        })
    
    except Exception as e:
        return jsonify({
            'error': f'Server error: {str(e)}'
        }), 500


@app.route('/scan-email', methods=['POST'])
def scan_email():
    """Extract URLs from email content and scan each one."""
    try:
        data = request.get_json()
        email_text = (data or {}).get('email_text', '')

        if not isinstance(email_text, str) or not email_text.strip():
            return jsonify({'error': 'email_text is required'}), 400

        urls = _extract_urls_from_text(email_text)
        results = []
        for url in urls:
            scan = combine_scan_result(url)
            results.append({
                'url': url,
                'status': scan['status'],
                'risk_score': scan['risk_score'],
                'message': scan['message'],
                'ml_confidence': scan['ml_confidence'],
            })

        summary = {
            'total_urls': len(results),
            'phishing': sum(1 for r in results if r['status'] == 'phishing'),
            'suspicious': sum(1 for r in results if r['status'] == 'suspicious'),
            'safe': sum(1 for r in results if r['status'] == 'safe'),
        }

        return jsonify({
            'status': 'ok',
            'summary': summary,
            'results': results,
        })
    except Exception as e:
        return jsonify({'error': f'Server error: {str(e)}'}), 500


@app.route('/check-domain', methods=['POST'])
@app.route('/check-typosquat', methods=['POST'])
def check_typosquat():
    """Analyze one domain and return a phishing verdict for the domain checker."""
    try:
        data = request.get_json() or {}
        domain = data.get('domain') or data.get('candidate_domain')

        result = evaluate_domain_checker(domain)
        return jsonify(result)
    except ValueError as ve:
        return jsonify({'error': str(ve)}), 400
    except Exception as e:
        return jsonify({'error': f'Server error: {str(e)}'}), 500


@app.route('/generate-takedown', methods=['POST'])
def generate_takedown():
    """Generate a takedown email template for abuse/hosting providers."""
    try:
        data = request.get_json() or {}
        reported_url = data.get('reported_url', '').strip()
        brand = data.get('brand', '').strip()
        recipient_email = data.get('recipient_email', '').strip() or 'abuse@provider.com'
        evidence = data.get('evidence', '').strip() or 'Suspicious phishing behavior detected by automated scanner.'

        if not reported_url:
            return jsonify({'error': 'reported_url is required'}), 400

        if not brand:
            brand = 'our organization'

        today = datetime.utcnow().strftime('%Y-%m-%d')
        subject = f'Urgent Takedown Request - Phishing URL impersonating {brand}'
        body = (
            f'To: {recipient_email}\n\n'
            f'Subject: {subject}\n\n'
            f'Dear Abuse Team,\n\n'
            f'We request immediate review and takedown of the following phishing resource:\n'
            f'- Reported URL: {reported_url}\n'
            f'- Brand Impacted: {brand}\n'
            f'- Date Observed: {today}\n\n'
            f'Evidence:\n{evidence}\n\n'
            'This content appears to be used for credential harvesting and brand impersonation.\n'
            'Please investigate and disable the resource under your acceptable use policy.\n\n'
            'Regards,\nSecurity Team\n'
        )

        return jsonify({
            'status': 'ok',
            'subject': subject,
            'recipient_email': recipient_email,
            'body': body,
        })
    except Exception as e:
        return jsonify({'error': f'Server error: {str(e)}'}), 500


@app.route('/health', methods=['GET'])
def health_check():
    """Health check endpoint"""
    return jsonify({
        'status': 'healthy',
        'service': 'Phishing Attack Defender API'
    })


if __name__ == '__main__':
    # Get port from environment variable or default to 5000
    port = int(os.environ.get('PORT', 5000))
    app.run(debug=True, host='0.0.0.0', port=port)

