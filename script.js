/**
 * Phishing Attack Defender - Frontend JavaScript
 * Multi-feature UI: Email Scanner, URL Scanner, Domain Checker, Takedown
 */

const API_BASE = 'http://localhost:5000';

// Theme toggle and PWA
const themeToggle = document.getElementById('themeToggle');
const rootElement = document.documentElement;

function toggleTheme() {
    const isDark = rootElement.classList.toggle('dark');
  localStorage.setItem('theme', isDark ? 'dark' : 'light');
  themeToggle.setAttribute('aria-label', isDark ? 'Switch to light mode' : 'Switch to dark mode');
}

if (themeToggle) {
  themeToggle.addEventListener('click', toggleTheme);
}

let deferredPrompt;

window.addEventListener('beforeinstallprompt', (e) => {
  e.preventDefault();
  deferredPrompt = e;
});

function showInstallPrompt() {
  if (deferredPrompt) {
    deferredPrompt.prompt();
    deferredPrompt.userChoice.then((choiceResult) => {
      if (choiceResult.outcome === 'accepted') {
        console.log('PWA installed');
      }
      deferredPrompt = null;
    });
  }
}

window.addEventListener('appinstalled', () => {
  console.log('PWA was installed');
});

// Confetti for safe scans
function confettiCelebration() {
  for (let i = 0; i < 50; i++) {
    const confetti = document.createElement('div');
    confetti.style.position = 'fixed';
    confetti.style.left = Math.random() * 100 + 'vw';
    confetti.style.top = '-10px';
    confetti.style.width = '10px';
    confetti.style.height = '10px';
    confetti.style.background = ['#10b981', '#34d399', '#6ee7b7'][Math.floor(Math.random() * 3)];
    confetti.style.borderRadius = '50%';
    confetti.style.pointerEvents = 'none';
    confetti.style.zIndex = '1000';
    confetti.style.animation = `confetti-fall ${Math.random() * 3 + 2}s linear forwards`;
    document.body.appendChild(confetti);

    setTimeout(() => confetti.remove(), 5000);
  }
}

const style = document.createElement('style');
style.textContent = `
  @keyframes confetti-fall {
    to {
      transform: translateY(100vh) rotate(720deg);
      opacity: 0;
    }
  }
`;
document.head.appendChild(style);

// Tab controls
window.addEventListener('load', () => {
  if ('BeforeInstallPromptEvent' in window && deferredPrompt) {
    showInstallPrompt();
  }
});
const featureTabs = document.querySelectorAll('.feature-tab');
const featurePanels = {
    email: document.getElementById('panel-email'),
    url: document.getElementById('panel-url'),
    typosquat: document.getElementById('panel-typosquat'),
    takedown: document.getElementById('panel-takedown'),
};

// URL scanner elements
const urlInput = document.getElementById('urlInput');
const checkBtn = document.getElementById('checkBtn');
const resultContainer = document.getElementById('resultContainer');
const scoreTile = document.getElementById('scoreTile');
const scoreRing = document.getElementById('scoreRing');
const resultTitle = document.getElementById('resultTitle');
const riskPercentage = document.getElementById('riskPercentage');
const summaryCard = document.getElementById('summaryCard');
const summaryTitle = document.getElementById('summaryTitle');
const resultMessage = document.getElementById('resultMessage');
const openUrlBtn = document.getElementById('openUrlBtn');
const analysisDetails = document.getElementById('analysisDetails');
const analysisCards = document.getElementById('analysisCards');
const loadingIndicator = document.getElementById('loadingIndicator');
const errorMessage = document.getElementById('errorMessage');

// Email scanner elements
const emailInput = document.getElementById('emailInput');
const scanEmailBtn = document.getElementById('scanEmailBtn');
const emailResult = document.getElementById('emailResult');

// Domain checker elements
const candidateDomainInput = document.getElementById('candidateDomainInput');
const checkTyposquatBtn = document.getElementById('checkTyposquatBtn');
const typosquatResult = document.getElementById('typosquatResult');

// Takedown elements
const reportedUrlInput = document.getElementById('reportedUrlInput');
const brandInput = document.getElementById('brandInput');
const recipientEmailInput = document.getElementById('recipientEmailInput');
const evidenceInput = document.getElementById('evidenceInput');
const generateTakedownBtn = document.getElementById('generateTakedownBtn');
const takedownResult = document.getElementById('takedownResult');
const takedownActions = document.getElementById('takedownActions');
const downloadTakedownBtn = document.getElementById('downloadTakedownBtn');

let currentTakedownReport = null;

featureTabs.forEach((tab) => {
    tab.addEventListener('click', () => switchTab(tab.dataset.tab));
});

checkBtn.addEventListener('click', checkUrl);
urlInput.addEventListener('keypress', (e) => {
    if (e.key === 'Enter') checkUrl();
});

scanEmailBtn.addEventListener('click', scanEmail);
checkTyposquatBtn.addEventListener('click', checkTyposquat);
generateTakedownBtn.addEventListener('click', generateTakedown);
downloadTakedownBtn.addEventListener('click', downloadTakedownReport);

function switchTab(tabName) {
    featureTabs.forEach((tab) => {
        const isActive = tab.dataset.tab === tabName;
        tab.classList.toggle('active', isActive);
        tab.setAttribute('aria-selected', String(isActive));
    });

    Object.keys(featurePanels).forEach((key) => {
        featurePanels[key].classList.toggle('hidden', key !== tabName);
    });
}

function isValidUrl(value) {
    try {
        const url = new URL(value);
        return url.protocol === 'http:' || url.protocol === 'https:';
    } catch (_) {
        try {
            const url = new URL('http://' + value);
            return url.protocol === 'http:';
        } catch (_) {
            return false;
        }
    }
}

function normalizeUrl(value) {
    if (!value.startsWith('http://') && !value.startsWith('https://')) {
        return 'http://' + value;
    }
    return value;
}

async function checkUrl() {
    const raw = urlInput.value.trim();
    hideUrlResults();

    if (!raw) {
        showUrlError('Please enter a URL to check');
        urlInput.focus();
        return;
    }

    const normalizedUrl = normalizeUrl(raw);
    if (!isValidUrl(normalizedUrl)) {
        showUrlError('Please enter a valid URL (e.g., https://example.com)');
        return;
    }

    showUrlLoading();

    try {
        const response = await fetch(`${API_BASE}/scan-url-detailed`, {
            method: 'POST',
            headers: { 'Content-Type': 'application/json' },
            body: JSON.stringify({ url: normalizedUrl }),
        });

        const data = await response.json();
        if (!response.ok) {
            throw new Error(data.error || 'Failed to analyze URL');
        }

        displayUrlResult(data, normalizedUrl);
    } catch (error) {
        if (String(error.message).includes('Failed to fetch')) {
            showUrlError('Unable to connect to backend on http://localhost:5000');
        } else {
            showUrlError(error.message);
        }
    }
}

function displayUrlResult(result, checkedUrl) {
    hideUrlLoading();

    const { risk_score, status, message, ml_confidence, rule_based } = result;
    if (status === 'safe') {
      confettiCelebration();
    }
    const roundedRisk = Math.max(0, Math.min(100, Math.round(Number(risk_score) || 0)));

    const titles = {
        safe: 'SAFE',
        suspicious: 'SUSPICIOUS',
        phishing: 'DANGEROUS',
    };

    const summaryTitles = {
        safe: 'Low Risk Detected',
        suspicious: 'Exercise Caution',
        phishing: 'High Risk Detected',
    };

    scoreTile.className = 'score-tile ' + status;
    scoreRing.className = 'score-ring ' + status;
    summaryCard.className = 'summary-card ' + status;
    resultTitle.className = 'score-label ' + status;

    resultTitle.textContent = titles[status] || 'Unknown';
    summaryTitle.textContent = summaryTitles[status] || 'Scan Summary';

    resultMessage.textContent = typeof ml_confidence === 'number'
        ? `${message} Confidence: ${ml_confidence}%`
        : message;

    riskPercentage.textContent = String(roundedRisk);
    scoreRing.style.setProperty('--risk-angle', `${Math.round((roundedRisk / 100) * 360)}deg`);

    if (status === 'safe') {
        openUrlBtn.href = checkedUrl;
        openUrlBtn.classList.remove('hidden');
    } else {
        openUrlBtn.href = '#';
        openUrlBtn.classList.add('hidden');
    }

    displayAnalysisCards(checkedUrl, rule_based);

    resultContainer.classList.remove('hidden');
}

function displayAnalysisCards(checkedUrl, ruleBased) {
    analysisCards.innerHTML = '';

    const analysis = ruleBased?.analysis || {};
    const whois = ruleBased?.whois || {};
    const safeBrowsing = ruleBased?.safe_browsing || {};
    const isHttps = checkedUrl.startsWith('https://');

    const cards = [
        {
            title: 'SSL Certificate',
            state: isHttps ? 'good' : 'bad',
            message: isHttps ? 'HTTPS detected for this URL' : 'No HTTPS encryption detected',
            meta: isHttps ? `Protocol: HTTPS` : `Protocol: HTTP`,
        },
        {
            title: 'Domain Age',
            state: whois.age_days >= 90 ? 'good' : 'bad',
            message: typeof whois.age_days === 'number'
                ? `Domain age: ${whois.age_days} days`
                : 'Domain age unavailable',
            meta: whois.creation_date ? `Created: ${whois.creation_date}` : 'WHOIS data unavailable',
        },
        {
            title: 'Blacklist Check',
            state: safeBrowsing.is_safe === false ? 'bad' : 'good',
            message: safeBrowsing.is_safe === false
                ? 'Detected on threat list'
                : 'No blacklist threats detected',
            meta: Array.isArray(safeBrowsing.threats) && safeBrowsing.threats.length
                ? `Threats: ${safeBrowsing.threats.join(', ')}`
                : 'Source: Google Safe Browsing',
        },
        {
            title: 'URL Pattern Risk',
            state: (analysis.domain_score || 0) + (analysis.suspicious_words_score || 0) >= 15 ? 'bad' : 'good',
            message: (analysis.domain_score || 0) + (analysis.suspicious_words_score || 0) >= 15
                ? 'Suspicious URL structure indicators detected'
                : 'No major suspicious pattern found',
            meta: `Domain score: ${analysis.domain_score || 0}, Keyword score: ${analysis.suspicious_words_score || 0}`,
        },
    ];

    cards.forEach((card) => {
        const element = document.createElement('div');
        element.className = `analysis-check-card ${card.state}`;
        element.innerHTML = `
            <div class="check-card-head">
                <h4>${escapeHtml(card.title)}</h4>
                <span class="check-state ${card.state}">${card.state === 'good' ? 'OK' : 'RISK'}</span>
            </div>
            <p class="check-message">${escapeHtml(card.message)}</p>
            <div class="check-meta">${escapeHtml(card.meta)}</div>
        `;
        analysisCards.appendChild(element);
    });

    analysisDetails.classList.remove('hidden');
}

function showUrlLoading() {
    loadingIndicator.classList.remove('hidden');
    checkBtn.disabled = true;
    urlInput.disabled = true;
}

function hideUrlLoading() {
    loadingIndicator.classList.add('hidden');
    checkBtn.disabled = false;
    urlInput.disabled = false;
}

function showUrlError(message) {
    hideUrlLoading();
    errorMessage.textContent = message;
    errorMessage.classList.remove('hidden');
}

function hideUrlResults() {
    resultContainer.classList.add('hidden');
    errorMessage.classList.add('hidden');
    analysisDetails.classList.add('hidden');
    analysisCards.innerHTML = '';
    openUrlBtn.href = '#';
    openUrlBtn.classList.add('hidden');
}

async function scanEmail() {
    const emailText = emailInput.value.trim();
    emailResult.classList.add('hidden');

    if (!emailText) {
        renderModuleError(emailResult, 'Please paste email content.');
        return;
    }

    scanEmailBtn.disabled = true;
    scanEmailBtn.textContent = 'Scanning...';

    try {
        const response = await fetch(`${API_BASE}/scan-email`, {
            method: 'POST',
            headers: { 'Content-Type': 'application/json' },
            body: JSON.stringify({ email_text: emailText }),
        });

        const data = await response.json();
        if (!response.ok) throw new Error(data.error || 'Email scan failed');

        const lines = [
            `<strong>Summary:</strong> ${data.summary.total_urls} URL(s), ` +
            `${data.summary.phishing} phishing, ${data.summary.suspicious} suspicious, ${data.summary.safe} safe`,
        ];

        if (data.results.length) {
            lines.push('<strong>Detected URLs:</strong>');
            lines.push('<ul>');
            data.results.forEach((item) => {
                lines.push(`<li><strong>${item.status.toUpperCase()}</strong> (${item.risk_score}%): ${escapeHtml(item.url)}</li>`);
            });
            lines.push('</ul>');
        } else {
            lines.push('No URLs were found in the email content.');
        }

        emailResult.innerHTML = lines.join('');
        emailResult.classList.remove('hidden');
    } catch (error) {
        renderModuleError(emailResult, error.message);
    } finally {
        scanEmailBtn.disabled = false;
        scanEmailBtn.textContent = 'Scan Email';
    }
}

async function checkTyposquat() {
    const candidateDomain = candidateDomainInput.value.trim();
    typosquatResult.classList.add('hidden');

    if (!candidateDomain) {
        renderModuleError(typosquatResult, 'Please provide a domain to check.');
        return;
    }

    checkTyposquatBtn.disabled = true;
    checkTyposquatBtn.textContent = 'Checking...';

    try {
        const response = await fetch(`${API_BASE}/check-typosquat`, {
            method: 'POST',
            headers: { 'Content-Type': 'application/json' },
            body: JSON.stringify({ domain: candidateDomain }),
        });

        const data = await response.json();
        if (!response.ok) throw new Error(data.error || 'Domain check failed');

        const verdictLabel = data.verdict === 'phishing' ? 'PHISHING' : 'NOT PHISHING';
        const indicators = Array.isArray(data.indicators) && data.indicators.length
            ? `<ul>${data.indicators.map((item) => `<li>${escapeHtml(item)}</li>`).join('')}</ul>`
            : 'No strong phishing indicators found.';

        typosquatResult.innerHTML = [
            `<strong>Verdict:</strong> ${escapeHtml(verdictLabel)}`,
            `<br><strong>Risk Score:</strong> ${data.risk_score}%`,
            `<br><strong>Message:</strong> ${escapeHtml(data.message)}`,
            `<br><strong>Domain:</strong> ${escapeHtml(data.domain)}`,
            `<br><strong>Analysis:</strong> ${indicators}`,
        ].join('');
        typosquatResult.classList.remove('hidden');
    } catch (error) {
        renderModuleError(typosquatResult, error.message);
    } finally {
        checkTyposquatBtn.disabled = false;
        checkTyposquatBtn.textContent = 'Check Domain';
    }
}

async function generateTakedown() {
    const payload = {
        reported_url: reportedUrlInput.value.trim(),
        brand: brandInput.value.trim(),
        recipient_email: recipientEmailInput.value.trim(),
        evidence: evidenceInput.value.trim(),
    };

    takedownResult.classList.add('hidden');
    takedownActions.classList.add('hidden');
    currentTakedownReport = null;

    if (!payload.reported_url) {
        renderModuleError(takedownResult, 'Please provide a reported malicious URL.');
        return;
    }

    generateTakedownBtn.disabled = true;
    generateTakedownBtn.textContent = 'Generating...';

    try {
        const response = await fetch(`${API_BASE}/generate-takedown`, {
            method: 'POST',
            headers: { 'Content-Type': 'application/json' },
            body: JSON.stringify(payload),
        });

        const data = await response.json();
        if (!response.ok) throw new Error(data.error || 'Takedown template generation failed');

        currentTakedownReport = {
            recipientEmail: data.recipient_email,
            subject: data.subject,
            body: data.body,
            brand: payload.brand,
            reportedUrl: payload.reported_url,
        };

        takedownResult.innerHTML = [
            `<strong>Recipient:</strong> ${escapeHtml(data.recipient_email)}`,
            `<br><strong>Subject:</strong> ${escapeHtml(data.subject)}`,
            `<pre class="template-block">${escapeHtml(data.body)}</pre>`,
        ].join('');
        takedownResult.classList.remove('hidden');
        takedownActions.classList.remove('hidden');
    } catch (error) {
        renderModuleError(takedownResult, error.message);
        takedownActions.classList.add('hidden');
    } finally {
        generateTakedownBtn.disabled = false;
        generateTakedownBtn.textContent = 'Generate Takedown Request';
    }
}

function downloadTakedownReport() {
    if (!currentTakedownReport) {
        renderModuleError(takedownResult, 'Generate a takedown report before downloading.');
        return;
    }

    const safeBrand = (currentTakedownReport.brand || 'report')
        .toLowerCase()
        .replace(/[^a-z0-9]+/g, '-')
        .replace(/^-+|-+$/g, '') || 'report';
    const timestamp = new Date().toISOString().slice(0, 10);
    const filename = `takedown-${safeBrand}-${timestamp}.txt`;
    const fileContents = [
        `Recipient: ${currentTakedownReport.recipientEmail}`,
        `Subject: ${currentTakedownReport.subject}`,
        '',
        currentTakedownReport.body,
        '',
        `Reported URL: ${currentTakedownReport.reportedUrl}`,
    ].join('\n');

    const blob = new Blob([fileContents], { type: 'text/plain;charset=utf-8' });
    const downloadUrl = URL.createObjectURL(blob);
    const link = document.createElement('a');
    link.href = downloadUrl;
    link.download = filename;
    document.body.appendChild(link);
    link.click();
    link.remove();
    URL.revokeObjectURL(downloadUrl);
}

function renderModuleError(container, message) {
    container.innerHTML = `<span class="module-error">${escapeHtml(message)}</span>`;
    container.classList.remove('hidden');
}

function escapeHtml(value) {
    return String(value)
        .replaceAll('&', '&amp;')
        .replaceAll('<', '&lt;')
        .replaceAll('>', '&gt;')
        .replaceAll('"', '&quot;')
        .replaceAll("'", '&#39;');
}
