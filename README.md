# Phishing Attack Defender

Phishing Attack Defender is a **modern phishing detection web app** with a sleek, responsive interface, dark mode support, PWA capabilities, and comprehensive phishing analysis features.

## ✨ New Modern Features
- **Dark/Light Mode** toggle with system preference support
- **Progressive Web App (PWA)** - installable, offline-capable
- **Glassmorphism Design** - beautiful backdrop blurs and modern shadows
- **Confetti Celebrations** for safe URL scans 🎉
- **Enhanced Animations** and smooth transitions throughout
- **Fully Responsive** across all devices

Phishing Attack Defender combines rule-based URL inspection, machine learning model predictions, email link extraction, typosquat monitoring, and takedown request generation in a beautiful, production-ready package.

## Overview

The project is designed for quick phishing triage workflows:

- Scan a single URL and view a risk-oriented analysis dashboard
- Extract and scan links from suspicious email content
- Compare look-alike domains for typosquatting risk
- Generate a takedown request template for abuse teams or hosting providers

## Features

### 1. URL Scanner
- Accepts a URL and evaluates it using hybrid scoring
- Combines ML prediction with rule-based heuristics
- Returns `safe`, `suspicious`, or `phishing`
- Shows a visual analysis result with score, summary, and detailed checks
- Displays an `Open URL` action only when the URL is classified as safe

### 2. Email Scanner
- Accepts pasted email text
- Extracts URLs from the message body
- Scans each discovered link through the same URL pipeline
- Summarizes safe, suspicious, and phishing counts

### 3. Typosquat Monitoring
- Compares a brand domain against a suspicious candidate domain
- Uses similarity and edit-distance style matching
- Flags common impersonation patterns such as look-alike spelling and TLD changes

### 4. Takedown Generator
- Accepts a reported malicious URL and optional evidence
- Produces a formatted takedown request template
- Useful for reporting phishing infrastructure to abuse contacts

## Tech Stack

### Frontend
- HTML5
- CSS3
- Vanilla JavaScript (ES6)

### Backend
- Python 3
- Flask
- Flask-Cors
- requests

### Machine Learning
- scikit-learn
- pandas
- numpy
- RandomForestClassifier

### External/Data Sources
- Google Safe Browsing API integration support
- WHOIS lookup support via HTTP API
- CSV-based training dataset in `phishing_ml_model/dataset.csv`

## Architecture

The application uses a simple client-server architecture.

```text
Frontend (HTML/CSS/JS)
        |
        | HTTP fetch requests
        v
Flask API (backend/app.py)
        |
        |-- URL hybrid scan
        |     |-- ML model inference
        |     |-- Rule-based URL analysis
        |     |-- Safe Browsing / WHOIS enrichment
        |
        |-- Email scan
        |     |-- URL extraction
        |     |-- Reuse URL hybrid scan
        |
        |-- Typosquat evaluation
        |
        |-- Takedown template generation
```

## Request Flow

### URL Scan Flow
1. User submits a URL from the frontend
2. Frontend calls `/scan-url-detailed`
3. Backend loads the trained ML model if needed
4. Backend extracts features from the URL
5. Backend runs:
   - ML inference
   - Rule-based analysis
   - hardening logic for risky domains and low-confidence safe predictions
6. Backend returns combined status, score, and detailed analysis
7. Frontend renders the modern result dashboard

### Email Scan Flow
1. User pastes suspicious email content
2. Frontend calls `/scan-email`
3. Backend extracts all URLs from the text
4. Each URL is analyzed through the hybrid scan path
5. Frontend renders summary counts and detected links

## Project Structure

```text
project/
├── backend/
│   ├── app.py
│   └── url_analyzer.py
├── frontend/
│   ├── index.html
│   ├── script.js
│   └── style.css
├── phishing_ml_model/
│   ├── dataset.csv
│   ├── feature_extractor.py
│   ├── predict.py
│   ├── train_model.py
│   └── model.pkl
├── requirements.txt
├── README.md
└── TODO.md
```

## Key Modules

### `backend/app.py`
Main API server. Responsible for:
- request validation
- URL scan orchestration
- ML model loading and prediction
- email URL extraction
- typosquat checking
- takedown template generation

### `backend/url_analyzer.py`
Rule-based phishing inspection module. Responsible for:
- URL heuristic scoring
- protocol/domain pattern checks
- suspicious keyword scoring
- Safe Browsing lookup support
- WHOIS/domain age lookup support

### `phishing_ml_model/feature_extractor.py`
Extracts the numerical features used by the ML model.

### `phishing_ml_model/train_model.py`
Trains the Random Forest classifier from the CSV dataset and saves `model.pkl`.

### `frontend/script.js`
Handles tab switching, API requests, and result rendering for all modules.

## Installation

### Prerequisites
- Python 3.10+ recommended
- A modern browser

### Setup

```bash
python -m venv .venv
.venv\Scripts\activate
pip install -r requirements.txt
```

## Running the App

### 1. Start the backend

```bash
cd backend
python app.py
```

The API runs on `http://localhost:5000`.

### 2. Open the frontend

Open `frontend/index.html` directly in a browser, or serve it with a simple local server.

Example:

```bash
cd frontend
python -m http.server 8000
```

Then open `http://localhost:8000`.

## Training the ML Model

If `model.pkl` does not exist or you want to retrain it:

```bash
cd phishing_ml_model
python train_model.py
```

This will:
- load `dataset.csv`
- extract features for each URL
- train a Random Forest classifier
- print evaluation metrics
- save `model.pkl`

## API Endpoints

### `POST /scan-url`
Returns compact URL classification output.

Request:
```json
{
  "url": "https://example.com"
}
```

### `POST /scan-url-detailed`
Returns full hybrid analysis output used by the UI.

### `POST /scan-email`
Scans links extracted from email text.

Request:
```json
{
  "email_text": "Please verify your account at https://example.com/login"
}
```

### `POST /check-typosquat`
Checks domain similarity risk.

Request:
```json
{
  "brand_domain": "paypal.com",
  "candidate_domain": "paypa1.com"
}
```

### `POST /generate-takedown`
Generates a takedown message.

Request:
```json
{
  "reported_url": "http://malicious.example/login",
  "brand": "Example Brand",
  "recipient_email": "abuse@provider.com",
  "evidence": "Credential harvesting page impersonating our login portal."
}
```

### `GET /health`
Basic health check endpoint.

## Scoring Model

The final URL decision is based on hybrid scoring:

- ML classifier prediction and confidence
- Rule-based risk signals
- suspicious tunnel domain hardening
- low-confidence safe prediction adjustment

Status thresholds:
- `0-39`: safe
- `40-69`: suspicious
- `70-100`: phishing

## Example Use Cases

- Triage suspicious links from user-reported emails
- Check whether a new domain is impersonating a brand
- Generate quick takedown reports for phishing campaigns
- Demo a simple phishing-detection workflow locally

## Limitations

- This is not a replacement for enterprise-grade threat intelligence
- WHOIS and Safe Browsing checks depend on external services and configuration
- Typosquat detection is heuristic, not exhaustive
- The ML model quality depends on the dataset used for training

## Future Improvements

- Persist scan history
- Add screenshot capture for takedown reports
- Add domain reputation feeds
- Improve email parsing for HTML emails and headers
- Expand typosquat detection with homoglyph analysis

## License

This project is intended for educational and defensive use.
