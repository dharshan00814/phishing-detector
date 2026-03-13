# 🛡️ Phishing Attack Defender

A full-stack web application that analyzes URLs to detect potential phishing websites. The application uses a Flask backend to analyze various phishing indicators and provides a modern, user-friendly frontend interface.

## Features

- **URL Analysis**: Checks URLs for multiple phishing indicators
- **Risk Score**: Displays a phishing risk score from 0-100%
- **Real-time Results**: Instant analysis with visual feedback
- **Modern UI**: Clean, professional interface with responsive design
- **Detailed Analysis**: Shows specific factors that contribute to the risk score
- **Hybrid Detection**: Combines machine learning and rule-based checks

## Phishing Indicators Analyzed

- 🔍 URL length (unusually long URLs)
- 🌐 IP address in URL (instead of domain name)
- 🔐 Suspicious keywords (login, verify, update, secure, bank, etc.)
- 🔒 HTTP vs HTTPS protocol
- ⚠️ Excessive special characters
- 🎯 Suspicious domain patterns (suspicious TLDs, numbers in domain)
- 📝 URL encoding/obfuscation
- 🤖 ML confidence blending with heuristic scoring

## Project Structure

```
phishing-attack-defender/
├── frontend/
│   ├── index.html      # Main HTML file
│   ├── style.css       # CSS styling
│   └── script.js       # Frontend JavaScript
├── backend/
│   ├── app.py          # Flask API endpoints
│   └── url_analyzer.py # URL analysis logic
├── requirements.txt    # Python dependencies
└── README.md          # This file
```

## Prerequisites

- Python 3.8 or higher
- Modern web browser (Chrome, Firefox, Edge, Safari)

## Installation & Setup

### 1. Clone or Download the Project

Extract the project files to your desired location.

### 2. Create a Virtual Environment (Recommended)

```bash
# Navigate to the project directory
cd path/to/phishing-attack-defender

# Create a virtual environment
python -m venv venv

# Activate the virtual environment
# On Windows:
venv\Scripts\activate
# On macOS/Linux:
source venv/bin/activate
```

### 3. Install Dependencies

```bash
pip install -r requirements.txt
```

## Running the Application

### Step 1: Start the Backend Server

Open a terminal and run:

```bash
cd backend
python app.py
```

You should see output like:
```
 * Running on http://127.0.0.1:5000
 * Debug mode: on
```

The Flask server will start on `http://localhost:5000`.

### Step 2: Open the Frontend

Open the `frontend/index.html` file in your web browser:

- **Option 1**: Simply double-click the `index.html` file
- **Option 2**: Use a simple HTTP server:
  ```bash
  # In a new terminal, from the frontend directory
  cd frontend
  python -m http.server 8000
  ```
  Then open `http://localhost:8000` in your browser

## Usage

1. **Enter a URL**: Type or paste any website URL into the input field
2. **Click "Check URL"**: Click the button or press Enter
3. **View Results**: See the risk score and analysis

### Example URLs to Test

| URL | Expected Result |
|-----|-----------------|
| `https://www.google.com` | Safe |
| `http://192.168.1.1/login.php` | High Risk (IP address) |
| `https://secure-bank.com-verify.com/login` | High Risk (suspicious domain) |
| `http://example.com/update-account-login-verify.php` | Medium Risk (suspicious words) |
| `https://paypal-secure-verify.tk/login` | High Risk (suspicious TLD + keywords) |

## API Documentation

### Endpoint: `/scan-url`

**Method**: POST

**Request Body**:
```json
{
  "url": "https://example.com"
}
```

**Response**:
```json
{
  "status": "safe",
  "risk_score": 15,
  "message": "Website appears safe"
}
```

**Phishing Response**:
```json
{
  "status": "phishing",
  "risk_score": 75,
  "message": "Possible Phishing Website"
}
```

### Endpoint: `/scan-url-detailed`

**Method**: POST

Returns combined detailed analysis from the rule-based analyzer and ML model.

**Request Body**:
```json
{
  "url": "https://example.com"
}
```

**Response**:
```json
{
  "status": "phishing",
  "risk_score": 75,
  "message": "Possible Phishing Website",
  "ml_confidence": 91.0,
  "url": "https://example.com",
  "rule_based": {
    "status": "safe",
    "risk_score": 20,
    "message": "Website appears safe",
    "analysis": {
      "url_length_score": 0,
      "ip_address_score": 0,
      "suspicious_words_score": 16,
      "protocol_score": 0,
      "special_chars_score": 0,
      "domain_score": 4,
      "safe_browsing_score": 0,
      "whois_score": 0
    }
  },
  "ml": {
    "status": "phishing",
    "risk_score": 91.0,
    "message": "Possible Phishing Website (ML model)",
    "prediction": 1,
    "ml_confidence": 91.0
  }
}
```

### Endpoint: `/health`

**Method**: GET

Returns health status of the API.

**Response**:
```json
{
  "status": "healthy",
  "service": "Phishing Attack Defender API"
}
```

## Risk Score Interpretation

| Score | Status | Action |
|-------|--------|--------|
| 0-39% | ✅ Safe | Website appears legitimate |
| 40-69% | ⚠️ Suspicious | Proceed with caution |
| 70-100% | 🚨 Phishing | Do not proceed |

## Troubleshooting

### CORS Error

If you see a CORS error in the browser console:
- Make sure the Flask backend is running
- The `flask-cors` package should handle this automatically

### Connection Refused

If you can't connect to the backend:
- Verify Flask is running on port 5000
- Check that no other application is using port 5000
- Try restarting the Flask server

### Invalid URL Error

Make sure you're entering a valid URL format:
- Include the protocol (http:// or https://)
- Example: `https://www.example.com`

## Technologies Used

- **Frontend**: HTML5, CSS3, JavaScript (ES6+)
- **Backend**: Python 3, Flask
- **Detection Engine**: RandomForest ML + rule-based URL heuristics
- **CORS**: Flask-CORS

## License

This project is for educational purposes. Use responsibly.

## Contributing

Feel free to improve the URL analysis logic or UI by submitting pull requests.

## TODO List - Implementation Progress

### Completed Tasks:
- [x] 1. Plan the implementation
- [x] 2. Add ML training and prediction scripts
- [x] 3. Update backend with hybrid scoring (ML + rule-based)
- [x] 4. Improve false-negative handling for risky tunnel domains
- [x] 5. Update docs and dependencies

### Status: Completed

---

**Stay safe online!** 🔒 Always verify URLs before entering sensitive information.

