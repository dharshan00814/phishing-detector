"""
predict.py
----------
Loads the trained model (model.pkl) and predicts whether a given URL
is phishing or legitimate.

Usage:
    python predict.py
    (you will be prompted to enter a URL)

Or pass a URL directly:
    python predict.py https://example.com
"""

import os
import pickle
import sys

import pandas as pd

# Import the same feature extractor used during training
from feature_extractor import FEATURE_NAMES, extract_features

# ── Load the saved model ─────────────────────────────────────────────────────
MODEL_PATH = os.path.join(os.path.dirname(__file__), 'model.pkl')

if not os.path.exists(MODEL_PATH):
    print("[!] model.pkl not found.")
    print("[!] Please run train_model.py first to generate the model.")
    sys.exit(1)

with open(MODEL_PATH, 'rb') as f:
    model = pickle.load(f)

print("[+] Model loaded successfully.\n")


def predict_url(url: str) -> dict:
    \"\"\"
    Predict whether a URL is phishing or legitimate (existing).
    \"\"\"

    """
    Predict whether a URL is phishing or legitimate.

    Args:
        url (str): The URL to analyse.

    Returns:
        dict with keys:
            - url         : the original URL
            - prediction  : 0 (legitimate) or 1 (phishing)
            - label       : human-readable label
            - confidence  : probability of the predicted class (0–100 %)
    """
    # Extract the same 10 features used during training
    features = extract_features(url)

    # Wrap in a DataFrame with named columns to match training data
    features_2d = pd.DataFrame([features], columns=FEATURE_NAMES)

    prediction = model.predict(features_2d)[0]
    probabilities = model.predict_proba(features_2d)[0]
    confidence = probabilities[prediction] * 100

    label = 'Phishing' if prediction == 1 else 'Legitimate'

    return {
        'input': url,  # Changed from 'url' for unified format
        'prediction': int(prediction),
        'label': label,
        'confidence': round(confidence, 2),
    }

    # Get predicted class (0 or 1)
    prediction = model.predict(features_2d)[0]

    # Get class probabilities: index 0 = legitimate, index 1 = phishing
    probabilities = model.predict_proba(features_2d)[0]
    confidence    = probabilities[prediction] * 100

    label = 'Phishing' if prediction == 1 else 'Legitimate'

    return {
        'url'        : url,
        'prediction' : int(prediction),
        'label'      : label,
        'confidence' : round(confidence, 2),
    }


def print_result(result: dict, result_type: str = "URL") -> None:
    \"\"\"
    Print prediction result with type label.
    \"\"\"
    border = '=' * 50
    print(border)
    print(f"  Type        : {result_type}")
    print(f"  Input       : {result['input']}")
    print(f"  Prediction  : {result['label']} ({result['prediction']})")
    print(f"  Confidence  : {result['confidence']}%")
    print(border)
    
    if result['prediction'] == 1:
        print("  [!] WARNING: PHISHING DETECTED!")
    else:
        print("  [OK] Appears LEGITIMATE.")
    print(border + '\\n')
    """Print the prediction result in a readable format."""
    border = '=' * 50
    print(border)
    print(f"  URL        : {result['url']}")
    print(f"  Prediction : {result['label']} ({result['prediction']})")
    print(f"  Confidence : {result['confidence']}%")
    print(border)

    if result['prediction'] == 1:
        print("  [!] WARNING: This URL appears to be a PHISHING site!")
    else:
        print("  [OK] This URL appears to be LEGITIMATE.")
    print(border + '\n')


# ── Main entry point ─────────────────────────────────────────────────────────
def predict_email(email_text: str) -> dict:
    \"\"\"
    Predict whether email text is phishing or legitimate.
    
    Returns unified format matching predict_url().
    \"\"\"
    try:
        from email_feature_extractor import extract_email_features
        import pandas as pd
        
        with open('email_model.pkl', 'rb') as f:
            model = pickle.load(f)
        
        features = extract_email_features(email_text)
        features_df = pd.DataFrame([features], columns=EMAIL_FEATURE_NAMES)
        
        prediction = model.predict(features_df)[0]
        probabilities = model.predict_proba(features_df)[0]
        confidence = probabilities[prediction] * 100
        
        label = 'Phishing Email' if prediction == 1 else 'Legitimate Email'
        
        return {
            'input': email_text[:100] + '...' if len(email_text) > 100 else email_text,
            'prediction': int(prediction),
            'label': label,
            'confidence': round(confidence, 2),
        }
    except FileNotFoundError:
        print("[!] email_model.pkl not found. Run train_models.py first.")
        return None
    except Exception as e:
        print(f"[!] Email prediction error: {e}")
        return None


if __name__ == '__main__':
    # Accept URL from command-line argument or prompt the user
    if len(sys.argv) > 1:
        urls = sys.argv[1:]          # support multiple URLs in one call
    else:
        raw = input("Enter a URL to check: ").strip()
        urls = [raw] if raw else []

    if not urls:
        print("[!] No URL provided. Exiting.")
        sys.exit(1)

    # Test URL prediction
    for url in urls:
        result = predict_url(url)
        print_result(result, "URL")

    for url in urls:
        result = predict_url(url)
        print_result(result)
