/**
 * Phishing Attack Defender - Frontend JavaScript
 * Handles URL checking via API and displays results
 */

// API endpoint
const API_URL = 'http://localhost:5000/scan-url';

// DOM Elements
const urlInput = document.getElementById('urlInput');
const checkBtn = document.getElementById('checkBtn');
const resultContainer = document.getElementById('resultContainer');
const resultHeader = document.getElementById('resultHeader');
const resultIcon = document.getElementById('resultIcon');
const resultTitle = document.getElementById('resultTitle');
const riskPercentage = document.getElementById('riskPercentage');
const riskBar = document.getElementById('riskBar');
const resultMessage = document.getElementById('resultMessage');
const analysisDetails = document.getElementById('analysisDetails');
const analysisList = document.getElementById('analysisList');
const loadingIndicator = document.getElementById('loadingIndicator');
const errorMessage = document.getElementById('errorMessage');

// Event Listeners
checkBtn.addEventListener('click', checkUrl);
urlInput.addEventListener('keypress', (e) => {
    if (e.key === 'Enter') {
        checkUrl();
    }
});

// Validate URL format
function isValidUrl(string) {
    try {
        const url = new URL(string);
        return url.protocol === 'http:' || url.protocol === 'https:';
    } catch (_) {
        // Try adding http:// prefix and check again
        try {
            const url = new URL('http://' + string);
            return url.protocol === 'http:';
        } catch (_) {
            return false;
        }
    }
}

// Normalize URL
function normalizeUrl(string) {
    if (!string.startsWith('http://') && !string.startsWith('https://')) {
        return 'http://' + string;
    }
    return string;
}

// Main function to check URL
async function checkUrl() {
    const url = urlInput.value.trim();
    
    // Hide previous results and errors
    hideResults();
    
    // Validate input
    if (!url) {
        showError('Please enter a URL to check');
        urlInput.focus();
        return;
    }
    
    // Normalize URL
    const normalizedUrl = normalizeUrl(url);
    
    if (!isValidUrl(normalizedUrl)) {
        showError('Please enter a valid URL (e.g., https://example.com)');
        return;
    }
    
    // Show loading indicator
    showLoading();
    
    try {
        // Send request to backend
        const response = await fetch(API_URL, {
            method: 'POST',
            headers: {
                'Content-Type': 'application/json'
            },
            body: JSON.stringify({ url: normalizedUrl })
        });
        
        if (!response.ok) {
            const errorData = await response.json();
            throw new Error(errorData.error || 'Failed to analyze URL');
        }
        
        const result = await response.json();
        
        // Display results
        displayResult(result);
        
    } catch (error) {
        console.error('Error:', error);
        
        if (error.message.includes('Failed to fetch') || error.message.includes('NetworkError')) {
            showError('Unable to connect to the server. Please make sure the Flask backend is running on http://localhost:5000');
        } else {
            showError(error.message);
        }
    }
}

// Display the analysis result
function displayResult(result) {
    hideLoading();
    
    const { risk_score, status, message, analysis, ml_confidence } = result;
    
    // Update result header
    resultIcon.className = 'result-icon ' + status;
    resultTitle.className = 'result-title ' + status;
    
    // Set result title and message based on status
    const titles = {
        'safe': 'Safe Website',
        'suspicious': 'Suspicious Website',
        'phishing': 'Possible Phishing Website'
    };
    
    resultTitle.textContent = titles[status] || 'Unknown';
    if (typeof ml_confidence === 'number') {
        resultMessage.textContent = `${message} Confidence: ${ml_confidence}%`;
    } else {
        resultMessage.textContent = message;
    }
    
    // Update risk percentage
    riskPercentage.textContent = risk_score + '%';
    
    // Update risk bar
    riskBar.style.width = risk_score + '%';
    riskBar.className = 'risk-bar';
    
    if (risk_score < 25) {
        riskBar.classList.add('low');
    } else if (risk_score < 50) {
        riskBar.classList.add('medium');
    } else {
        riskBar.classList.add('high');
    }
    
    // Display analysis details
    if (analysis) {
        displayAnalysis(analysis);
    }
    
    // Show result container
    resultContainer.classList.remove('hidden');
}

// Display analysis details
function displayAnalysis(analysis) {
    analysisList.innerHTML = '';
    const details = [];
    
    if (analysis.url_length_score > 0) {
        details.push({
            text: `Unusually long URL (+${analysis.url_length_score}%)`,
            level: analysis.url_length_score >= 15 ? 'danger' : 'warning'
        });
    }
    
    if (analysis.ip_address_score > 0) {
        details.push({
            text: `URL contains IP address instead of domain (+${analysis.ip_address_score}%)`,
            level: 'danger'
        });
    }
    
    if (analysis.suspicious_words_score > 0) {
        details.push({
            text: `Contains suspicious words like "login", "verify", "bank" (+${analysis.suspicious_words_score}%)`,
            level: 'warning'
        });
    }
    
    if (analysis.protocol_score > 0) {
        if (analysis.protocol_score === 10) {
            details.push({
                text: 'No protocol specified (http/https)',
                level: 'warning'
            });
        } else {
            details.push({
                text: 'Using insecure HTTP protocol instead of HTTPS',
                level: 'danger'
            });
        }
    }
    
    if (analysis.special_chars_score > 0) {
        details.push({
            text: `Excessive special characters in URL (+${analysis.suspicious_words_score}%)`,
            level: 'warning'
        });
    }
    
    if (analysis.domain_score > 0) {
        details.push({
            text: `Suspicious domain pattern detected (+${analysis.domain_score}%)`,
            level: analysis.domain_score >= 15 ? 'danger' : 'warning'
        });
    }
    
    if (details.length === 0) {
        details.push({
            text: 'No suspicious indicators found',
            level: 'safe'
        });
    }
    
    // Add details to list
    details.forEach(detail => {
        const li = document.createElement('li');
        li.textContent = detail.text;
        if (detail.level === 'danger') {
            li.classList.add('danger');
        } else if (detail.level === 'warning') {
            li.classList.add('warning');
        }
        analysisList.appendChild(li);
    });
    
    analysisDetails.classList.remove('hidden');
}

// UI Helper Functions
function showLoading() {
    loadingIndicator.classList.remove('hidden');
    checkBtn.disabled = true;
    urlInput.disabled = true;
}

function hideLoading() {
    loadingIndicator.classList.add('hidden');
    checkBtn.disabled = false;
    urlInput.disabled = false;
}

function showError(message) {
    hideLoading();
    errorMessage.textContent = message;
    errorMessage.classList.remove('hidden');
}

function hideResults() {
    resultContainer.classList.add('hidden');
    errorMessage.classList.add('hidden');
    analysisDetails.classList.add('hidden');
}

// Add some example URLs for testing on page load
urlInput.addEventListener('focus', () => {
    if (!urlInput.value) {
        urlInput.placeholder = 'e.g., https://www.google.com or http://suspicious-site.tk/login';
    }
});

