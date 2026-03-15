"""
feature_extractor.py
--------------------
Extracts numerical features from a URL for use in the ML model.
Each feature is designed to capture common patterns found in phishing URLs.
"""

import re


# Keywords frequently abused in phishing URLs
SUSPICIOUS_KEYWORDS = ['login', 'verify', 'secure', 'bank', 'account',
                       'update', 'confirm', 'password', 'credential',
                       'signin', 'validate', 'payment', 'invoice', 'support']


def has_ip_address(url):
    """Return 1 if the URL contains an IPv4 address, 0 otherwise."""
    ip_pattern = r'(?:(?:25[0-5]|2[0-4]\d|[01]?\d\d?)\.){3}(?:25[0-5]|2[0-4]\d|[01]?\d\d?)'
    return 1 if re.search(ip_pattern, url) else 0


def count_subdomains(url):
    """
    Return the number of subdomains by counting dots in the hostname.
    e.g. secure.login.paypal.com has 3 dots → 3 subdomains.
    """
    try:
        # Strip scheme and path to isolate the hostname
        hostname = re.sub(r'https?://', '', url).split('/')[0]
        # Remove port if present
        hostname = hostname.split(':')[0]
        return hostname.count('.')
    except Exception:
        return 0


def has_suspicious_keyword(url):
    """Return 1 if any suspicious keyword is found in the URL, 0 otherwise."""
    url_lower = url.lower()
    return 1 if any(kw in url_lower for kw in SUSPICIOUS_KEYWORDS) else 0


def extract_features(url):
    """
    Extract a fixed-length feature vector from a URL.

    Features:
        0  - url_length        : Total character length of the URL
        1  - num_dots          : Number of '.' characters
        2  - has_at            : 1 if '@' is present (common phishing trick)
        3  - has_ip            : 1 if an IP address appears instead of a domain
        4  - has_https         : 1 if the URL uses HTTPS, 0 if HTTP or missing
        5  - num_subdomains    : Number of subdomains (dots in hostname)
        6  - has_suspicious_kw : 1 if any suspicious keyword is in the URL
        7  - num_hyphens       : Number of '-' characters (inflated in phishing)
        8  - url_depth         : Number of '/' after the domain (path depth)
        9  - has_at_in_domain  : 1 if '@' appears before the first '/'

    Returns:
        list[int | float]: Feature vector of length 10
    """
    url_length = len(url)
    num_dots = url.count('.')
    has_at = 1 if '@' in url else 0
    has_ip = has_ip_address(url)
    uses_https = 1 if url.lower().startswith('https') else 0
    num_subdomains = count_subdomains(url)
    has_kw = has_suspicious_keyword(url)
    num_hyphens = url.count('-')

    # Path depth: count '/' occurrences after removing the scheme
    stripped = re.sub(r'https?://', '', url)
    url_depth = stripped.count('/')

    # '@' in the domain portion only (before first '/')
    domain_part = stripped.split('/')[0]
    at_in_domain = 1 if '@' in domain_part else 0

    return [
        url_length,       # feature 0
        num_dots,         # feature 1
        has_at,           # feature 2
        has_ip,           # feature 3
        uses_https,       # feature 4
        num_subdomains,   # feature 5
        has_kw,           # feature 6
        num_hyphens,      # feature 7
        url_depth,        # feature 8
        at_in_domain,     # feature 9
    ]


# Column names that match the feature order above — used by train_model.py
FEATURE_NAMES = [
    'url_length',
    'num_dots',
    'has_at',
    'has_ip',
    'has_https',
    'num_subdomains',
    'has_suspicious_kw',
    'num_hyphens',
    'url_depth',
    'at_in_domain',
]
