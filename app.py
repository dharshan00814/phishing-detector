"""
Root entry point for Phishing Attack Defender.
Allows running `python app.py` or `py app.py` directly from the project root.
"""
import os
import sys

PROJECT_ROOT = os.path.dirname(os.path.abspath(__file__))
BACKEND_DIR = os.path.join(PROJECT_ROOT, 'backend')
ML_MODEL_DIR = os.path.join(PROJECT_ROOT, 'phishing_ml_model')

for d in [PROJECT_ROOT, BACKEND_DIR, ML_MODEL_DIR]:
    if d not in sys.path:
        sys.path.insert(0, d)

from backend.app import app

if __name__ == '__main__':
    port = int(os.environ.get('PORT', 5000))
    app.run(debug=True, host='0.0.0.0', port=port)
