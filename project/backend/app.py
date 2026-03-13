"""
Flask backend for Phishing Attack Defender
API endpoint to check URLs for phishing indicators
"""

import os
import pickle
import sys
from urllib.parse import urlparse
from flask import Flask, request, jsonify
from flask_cors import CORS
import pandas as pd
from url_analyzer import analyze_url


# Make phishing_ml_model importable from backend/
PROJECT_ROOT = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
ML_MODEL_DIR = os.path.join(PROJECT_ROOT, 'phishing_ml_model')
if ML_MODEL_DIR not in sys.path:
    sys.path.append(ML_MODEL_DIR)

from feature_extractor import FEATURE_NAMES, extract_features

app = Flask(__name__)

# Enable CORS to allow frontend to communicate with backend
CORS(app)

MODEL_PATH = os.path.join(ML_MODEL_DIR, 'model.pkl')
_ML_MODEL = None

# Public tunnel domains are frequently abused for short-lived phishing pages.
SUSPICIOUS_TUNNEL_DOMAINS = [
    'trycloudflare.com',
    'ngrok-free.app',
    'ngrok.io',
    'loca.lt',
    'localtunnel.me',
    'serveo.net',
]


def load_ml_model():
    """Load the pickled ML model once and cache it in memory."""
    global _ML_MODEL
    if _ML_MODEL is None:
        if not os.path.exists(MODEL_PATH):
            raise FileNotFoundError(
                f"model.pkl not found at {MODEL_PATH}. Run phishing_ml_model/train_model.py first."
            )
        with open(MODEL_PATH, 'rb') as f:
            _ML_MODEL = pickle.load(f)
    return _ML_MODEL


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

    # Low-confidence ML safe prediction should not be treated as fully safe.
    if ml_result['prediction'] == 0 and ml_result['ml_confidence'] < 70:
        risk_score = max(risk_score, 60.0)
        reason.append('Low confidence safe prediction')

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

