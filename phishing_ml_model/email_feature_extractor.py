"""
email_feature_extractor.py
-------------------------
Extracts numerical features from email text for ML classification.
Designed to detect phishing emails based on content patterns.

Features capture urgency manipulation, spoofing indicators, and suspicious structure.
"""

import re

# Phishing email indicators
URGENCY_WORDS = [
    'urgent', 'immediate', 'critical', 'emergency', 'action required',
    'verify', 'confirm', 'update', 'validate', 'review', 'act now',
    'suspended', 'locked', 'disabled', 'expired', 'terminated',
    'security alert', 'account issue', 'problem detected'
]

SPOOF_BRANDS = [
    'paypal', 'bank', 'amazon', 'google', 'microsoft', 'apple',
    'netflix', 'chase', 'wells fargo', 'citibank'
]

GREETINGS = ['dear customer', 'dear user', 'dear member', 'hello valued customer']


def count_urgency_words(text):
    """Count urgency/phishing trigger words."""
    text_lower = text.lower()
    return sum(1 for word in URGENCY_WORDS if word in text_lower)


def has_spoofed_sender(text):
    """Detect sender impersonation via brand keywords without legit greeting."""
    text_lower = text.lower()
    brand_mentions = sum(1 for brand in SPOOF_BRANDS if brand in text_lower)
    generic_greetings = any(greeting in text_lower for greeting in GREETINGS)
    return 1 if brand_mentions > 0 and not generic_greetings else 0


def exclamation_question_ratio(text):
    """Ratio of !/? to total sentences (panic punctuation)."""
    sentences = re.split(r'[.!?]+', text)
    if not sentences:
        return 0
    exclamations = text.count('!')
    questions = text.count('?')
    panic_chars = exclamations + questions
    return round((panic_chars / len(sentences)) * 10, 1)  # Scale to ~0-10 range


def suspicious_url_mentions(text):
    """Count suspicious patterns like 'click here', 'visit link'."""
    patterns = [
        r'click (here|below|link|to verify)',
        r'visit (our site|this link|website)',
        r'(log in|sign in|login).*?(here|below)',
        r'update your (password|account|info)',
    ]
    count = 0
    for pattern in patterns:
        count += len(re.findall(pattern, text, re.IGNORECASE | re.DOTALL))
    return min(count, 5)  # Cap at 5


def email_length_category(text):
    """Categorize by length: short=0, normal=1, verbose=2."""
    length = len(text)
    if length < 200:
        return 0
    elif length < 800:
        return 1
    else:
        return 2


def attachment_mentions(text):
    """Detect suspicious attachment references."""
    suspicious = ['invoice', 'receipt', 'document', 'statement', 'update']
    text_lower = text.lower()
    return sum(1 for word in suspicious if word in text_lower)


def generic_greeting(text):
    """Generic greetings reduce phishing probability."""
    text_lower = text.lower()
    return 1 if any(greeting in text_lower for greeting in GREETINGS) else 0


def has_url_shorteners(text):
    """Common URL shorteners used in phishing."""
    shorteners = ['bit.ly', 'tinyurl', 't.co', 'goo.gl', 'buff.ly']
    text_lower = text.lower()
    return 1 if any(shortener in text_lower for shortener in shorteners) else 0


def extract_email_features(text):
    """
    Extract 8 numerical features from email text for ML model.

    Features:
        0. urgency_word_count     : Number of urgency trigger words
        1. spoofed_sender         : 1 if brand mention + no legit greeting
        2. panic_punctuation      : !/? ratio per sentence (scaled)
        3. suspicious_url_calls   : Count of 'click here' patterns (capped)
        4. length_category        : 0=short, 1=normal, 2=verbose
        5. attachment_mentions    : Count of suspicious attachments
        6. generic_greeting       : 1 if generic greeting present
        7. url_shorteners         : 1 if shortener domain detected

    Returns: list[float|int] of length 8
    """
    return [
        count_urgency_words(text),
        has_spoofed_sender(text),
        exclamation_question_ratio(text),
        suspicious_url_mentions(text),
        email_length_category(text),
        attachment_mentions(text),
        generic_greeting(text),
        has_url_shorteners(text),
    ]


# Column names matching feature order - used by train_models.py
EMAIL_FEATURE_NAMES = [
    'urgency_word_count',
    'spoofed_sender',
    'panic_punctuation',
    'suspicious_url_calls',
    'length_category',
    'attachment_mentions',
    'generic_greeting',
    'url_shorteners',
]

