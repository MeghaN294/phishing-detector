document.addEventListener('DOMContentLoaded', function() {
    // ============================================
    // DOM ELEMENTS
    // ============================================
    const urlInput = document.getElementById('urlInput');
    const checkBtn = document.getElementById('checkBtn');
    const loadingDiv = document.getElementById('loading');
    const resultDiv = document.getElementById('result');
    const resultCard = document.getElementById('resultCard');
    const resultHeader = document.getElementById('resultHeader');
    const resultIcon = document.getElementById('resultIcon');
    const resultScore = document.getElementById('resultScore');
    const statusTitle = document.getElementById('statusTitle');
    const analyzedUrl = document.getElementById('analyzedUrl');
    const riskScore = document.getElementById('riskScore');
    const riskList = document.getElementById('riskList');
    const explanation = document.getElementById('explanation');
    const confidenceValue = document.getElementById('confidenceValue');
    const confidenceBar = document.getElementById('confidenceBar');
    const phishingProb = document.getElementById('phishingProb');
    const phishingBar = document.getElementById('phishingBar');
    const legitimateProb = document.getElementById('legitimateProb');
    const legitimateBar = document.getElementById('legitimateBar');
    const urlLength = document.getElementById('urlLength');
    const suspiciousCount = document.getElementById('suspiciousCount');
    const httpsStatus = document.getElementById('httpsStatus');
    const ipStatus = document.getElementById('ipStatus');
    const shortenedStatus = document.getElementById('shortenedStatus');
    const tldStatus = document.getElementById('tldStatus');
    const trustedStatus = document.getElementById('trustedStatus');
    const typoStatus = document.getElementById('typoStatus');
    const domainAge = document.getElementById('domainAge');
    const entropyValue = document.getElementById('entropyValue');
    const riskScoreDisplay = document.getElementById('riskScoreDisplay');
    const detectionMethod = document.getElementById('detectionMethod');

    // ============================================
    // DARK/LIGHT MODE TOGGLE
    // ============================================
    const themeToggle = document.getElementById('themeToggle');
    const themeIcon = document.getElementById('themeIcon');
    const htmlRoot = document.getElementById('html-root') || document.documentElement;

    function setTheme(isLight) {
        if (isLight) {
            htmlRoot.classList.add('light-mode');
            if (themeIcon) {
                themeIcon.textContent = '☀️';
                themeIcon.style.color = '#f6ad55';
            }
            localStorage.setItem('phishguard-theme', 'light');
        } else {
            htmlRoot.classList.remove('light-mode');
            if (themeIcon) {
                themeIcon.textContent = '🌙';
                themeIcon.style.color = '#a0aec0';
            }
            localStorage.setItem('phishguard-theme', 'dark');
        }
    }

    const savedTheme = localStorage.getItem('phishguard-theme');
    setTheme(savedTheme === 'light');

    if (themeToggle) {
        themeToggle.addEventListener('click', function(e) {
            e.preventDefault();
            e.stopPropagation();
            const isLight = htmlRoot.classList.contains('light-mode');
            setTheme(!isLight);
        });
    }

    // ============================================
    // QUICK TEST BUTTONS & EVENTS
    // ============================================
    document.querySelectorAll('.test-btn').forEach(btn => {
        btn.addEventListener('click', function() {
            const url = this.getAttribute('data-url') || this.textContent.trim();
            if (url) {
                urlInput.value = url;
                checkURL();
            }
        });
    });

    if (checkBtn) {
        checkBtn.addEventListener('click', checkURL);
    }

    if (urlInput) {
        urlInput.addEventListener('keypress', (e) => {
            if (e.key === 'Enter') checkURL();
        });
        urlInput.focus();
        urlInput.addEventListener('keydown', (e) => {
            if (e.ctrlKey && e.key === 'Enter') {
                e.preventDefault();
                checkURL();
            }
            if (e.key === 'Escape') {
                urlInput.value = '';
                urlInput.focus();
            }
        });
    }

    // ============================================
    // CHECK URL FUNCTION
    // ============================================
    async function checkURL() {
        const url = urlInput.value.trim();

        if (!url) {
            showError('Please enter a URL to check');
            return;
        }

        if (checkBtn) checkBtn.disabled = true;
        if (loadingDiv) loadingDiv.style.display = 'block';
        if (resultDiv) resultDiv.style.display = 'none';

        animateLoading();

        try {
            const response = await fetch('/predict', {
                method: 'POST',
                headers: {
                    'Content-Type': 'application/json',
                    'Accept': 'application/json'
                },
                body: JSON.stringify({ url: url })
            });

            let data;
            try {
                data = await response.json();
            } catch (e) {
                throw new Error(`Server returned ${response.status}`);
            }

            if (!response.ok && !data) {
                throw new Error(data.error || `Server returned ${response.status}`);
            }

            displayResults(data);

        } catch (error) {
            console.error('❌ Error:', error);
            showError(error.message || 'Network error - check if server is running');
        } finally {
            if (checkBtn) checkBtn.disabled = false;
            if (loadingDiv) loadingDiv.style.display = 'none';
        }
    }

    // ============================================
    // ANIMATE LOADING
    // ============================================
    function animateLoading() {
        const steps = document.querySelectorAll('.step');
        steps.forEach((step, index) => {
            step.className = 'step';
            if (index === 0) step.classList.add('active');
        });

        steps.forEach((step, index) => {
            setTimeout(() => {
                step.classList.remove('active');
                step.classList.add('done');
                if (index + 1 < steps.length) {
                    steps[index + 1].classList.add('active');
                }
            }, (index + 1) * 600);
        });
    }

    // ============================================
    // RESET RESULT CARD STATE
    // ============================================
    function resetResultCardState() {
        if (resultCard) resultCard.classList.remove('invalid');
        if (resultHeader) resultHeader.classList.remove('invalid');
        if (resultIcon) resultIcon.className = 'result-icon';
        if (resultScore) resultScore.classList.remove('invalid');
        if (riskScore) riskScore.className = 'score-value';
        if (statusTitle) statusTitle.style.color = '';
    }

    // ============================================
    // DISPLAY RESULTS
    // ============================================
    function displayResults(data) {
        if (!resultDiv) return;
        resultDiv.style.display = 'block';

        resetResultCardState();

        if (riskList) riskList.innerHTML = '';

        const status = (data.status || '').toLowerCase();
        const isInvalid = data.is_invalid === true || status === 'invalid' || status === 'error';
        const isPhishing = data.is_phishing === true;

        // ============================================
        // STATE 1: INVALID URL
        // ============================================
        if (isInvalid) {
            if (resultCard) resultCard.classList.add('invalid');
            if (resultHeader) resultHeader.classList.add('invalid');
            if (resultIcon) {
                resultIcon.classList.add('invalid');
                resultIcon.innerHTML = '<i class="fas fa-exclamation-circle"></i>';
            }
            if (resultScore) resultScore.classList.add('invalid');
            if (statusTitle) {
                statusTitle.textContent = '⚠️ INVALID URL';
                statusTitle.style.color = '#f6ad55';
            }
            if (riskScore) {
                riskScore.className = 'score-value invalid';
                riskScore.textContent = '—';
            }
            if (analyzedUrl) analyzedUrl.textContent = data.url || data.original_url || 'N/A';

            if (riskList) {
                const tag = document.createElement('span');
                tag.className = 'risk-tag invalid';
                const errMsg = data.error || 'This is not a valid URL';
                tag.innerHTML = `<i class="fas fa-times-circle"></i> ${escapeHtml(errMsg)}`;
                riskList.appendChild(tag);
            }

            if (explanation) {
                const text = data.explanation ||
                    `❌ INVALID URL\n\n${data.error || 'The URL you entered is not valid.'}\n\nPlease enter a valid URL like:\nhttps://www.example.com`;
                explanation.innerHTML = escapeHtml(text).replace(/\n/g, '<br>');
            }

            zeroOutMetrics();
            if (detectionMethod) {
                detectionMethod.textContent = 'Validation';
                detectionMethod.style.color = '#f6ad55';
            }

            scrollToResult();
            return;
        }

        // ============================================
        // STATE 2 & 3: PHISHING / SAFE
        // ============================================
        if (isPhishing) {
            if (resultIcon) {
                resultIcon.classList.add('phishing');
                resultIcon.innerHTML = '<i class="fas fa-exclamation-triangle"></i>';
            }
            if (statusTitle) {
                statusTitle.textContent = '🚨 PHISHING URL DETECTED!';
                statusTitle.style.color = '#fc8181';
            }
            if (riskScore) riskScore.className = 'score-value danger';
        } else {
            if (resultIcon) {
                resultIcon.classList.add('safe');
                resultIcon.innerHTML = '<i class="fas fa-check-circle"></i>';
            }
            if (statusTitle) {
                statusTitle.textContent = '✅ SAFE URL';
                statusTitle.style.color = '#48bb78';
            }
            if (riskScore) riskScore.className = 'score-value success';
        }

        if (analyzedUrl) analyzedUrl.textContent = data.url || data.original_url || 'N/A';

        const score = data.risk_score || 0;
        if (riskScore) riskScore.textContent = score + '%';
        if (riskScoreDisplay) riskScoreDisplay.textContent = score + '%';

        // ============================================
        // DETECTION METHOD
        // ============================================
        if (detectionMethod) {
            const method = data.detection_method || 'Hybrid AI';
            detectionMethod.textContent = method;
            detectionMethod.style.color = method === 'Rule-Based' ? '#f6ad55' : '#667eea';
        }

        // ============================================
        // RISK FACTORS LIST
        // ============================================
        let hasTypoInFeatures = false;

        if (data.risky_features && data.risky_features.length > 0 && riskList) {
            data.risky_features.forEach(feature => {
                const tag = document.createElement('span');
                tag.className = 'risk-tag';
                tag.innerHTML = `<i class="fas fa-exclamation-circle"></i> ${escapeHtml(feature)}`;
                riskList.appendChild(tag);

                // Fail-safe check: look for keywords in the text itself
                const lowerFeature = feature.toLowerCase();
                if (lowerFeature.includes('typosquat') || lowerFeature.includes('mimics')) {
                    hasTypoInFeatures = true;
                }
            });
        } else if (riskList) {
            const tag = document.createElement('span');
            tag.className = 'risk-tag safe';
            tag.innerHTML = `<i class="fas fa-check-circle"></i> No risk factors detected`;
            riskList.appendChild(tag);
        }

        // ============================================
        // EXPLANATION
        // ============================================
        if (explanation) {
            if (data.explanation) {
                explanation.innerHTML = escapeHtml(data.explanation).replace(/\n/g, '<br>');
            } else {
                explanation.textContent = isPhishing ?
                    'This URL shows phishing indicators. Do NOT enter any personal information.' :
                    'This URL appears safe based on our analysis.';
            }
        }

        // ============================================
        // PROBABILITY BARS
        // ============================================
        const confidence = data.confidence || 0;
        if (confidenceValue) confidenceValue.textContent = (confidence * 100).toFixed(1) + '%';
        if (confidenceBar) confidenceBar.style.width = (confidence * 100) + '%';

        const probability = data.probability || { phishing: 0, legitimate: 0 };
        const phishingPct = (probability.phishing || 0) * 100;
        const legitPct = (probability.legitimate || 0) * 100;

        if (phishingProb) phishingProb.textContent = phishingPct.toFixed(1) + '%';
        if (phishingBar) phishingBar.style.width = phishingPct + '%';
        if (legitimateProb) legitimateProb.textContent = legitPct.toFixed(1) + '%';
        if (legitimateBar) legitimateBar.style.width = legitPct + '%';

        // ============================================
        // METRICS
        // ============================================
        const features = data.features || {};
        const getFeature = (key) =>
            features[key] !== undefined ? features[key] : (data[key] !== undefined ? data[key] : 0);

        if (urlLength) urlLength.textContent = getFeature('url_length') || '0';
        if (suspiciousCount) suspiciousCount.textContent = features._suspicious_keyword_count || features.suspicious_keyword_count || '0';

        const https = getFeature('https_flag') || 0;
        if (httpsStatus) {
            httpsStatus.textContent = https ? '✅ Yes' : '❌ No';
            httpsStatus.style.color = https ? '#48bb78' : '#fc8181';
        }

        const hasIp = getFeature('has_ip_address') || 0;
        if (ipStatus) {
            ipStatus.textContent = hasIp ? '⚠️ Yes' : '✅ No';
            ipStatus.style.color = hasIp ? '#fc8181' : '#48bb78';
        }

        const shortened = features._is_shortened || 0;
        if (shortenedStatus) {
            shortenedStatus.textContent = shortened ? '⚠️ Yes' : '✅ No';
            shortenedStatus.style.color = shortened ? '#fc8181' : '#48bb78';
        }

        const suspiciousTld = features._has_suspicious_tld || 0;
        if (tldStatus) {
            tldStatus.textContent = suspiciousTld ? '⚠️ Yes' : '✅ No';
            tldStatus.style.color = suspiciousTld ? '#fc8181' : '#48bb78';
        }

        const reputation = data.reputation || {};
        const trusted = reputation.is_trusted || false;
        if (trustedStatus) {
            trustedStatus.textContent = trusted ? '✅ Yes' : '❌ No';
            trustedStatus.style.color = trusted ? '#48bb78' : '#fc8181';
        }

        // ============================================
        // FAIL-SAFE TYPOSQUATTING UI UPDATE
        // ============================================
        if (typoStatus) {
            // We check BOTH the boolean from backend AND the text from risky_features
            const isTypo = (data.is_typo === true) || hasTypoInFeatures;
            
            if (isTypo) {
                typoStatus.textContent = '❌ Yes';
                typoStatus.style.color = '#fc8181';
            } else {
                typoStatus.textContent = '✅ No';
                typoStatus.style.color = '#48bb78';
            }
        }

        if (domainAge) domainAge.textContent = features.domain_age_days || '0';
        if (entropyValue) {
            const ent = features.url_entropy || 0;
            entropyValue.textContent = typeof ent === 'number' ? ent.toFixed(2) : '0';
        }

        const responseTime = document.getElementById('responseTime');
        const statTime = document.getElementById('statTime');
        if (responseTime) responseTime.textContent = '< 500ms';
        if (statTime) statTime.textContent = '< 500ms';

        scrollToResult();
    }

    // ============================================
    // ZERO-OUT METRICS
    // ============================================
    function zeroOutMetrics() {
        if (confidenceValue) confidenceValue.textContent = '0%';
        if (confidenceBar) confidenceBar.style.width = '0%';
        if (phishingProb) phishingProb.textContent = '0%';
        if (phishingBar) phishingBar.style.width = '0%';
        if (legitimateProb) legitimateProb.textContent = '0%';
        if (legitimateBar) legitimateBar.style.width = '0%';
        if (urlLength) urlLength.textContent = '-';
        if (suspiciousCount) suspiciousCount.textContent = '-';
        if (httpsStatus) { httpsStatus.textContent = '-'; httpsStatus.style.color = ''; }
        if (ipStatus) { ipStatus.textContent = '-'; ipStatus.style.color = ''; }
        if (shortenedStatus) { shortenedStatus.textContent = '-'; shortenedStatus.style.color = ''; }
        if (tldStatus) { tldStatus.textContent = '-'; tldStatus.style.color = ''; }
        if (trustedStatus) { trustedStatus.textContent = '-'; trustedStatus.style.color = ''; }
        if (typoStatus) { typoStatus.textContent = '-'; typoStatus.style.color = ''; }
        if (domainAge) domainAge.textContent = '-';
        if (entropyValue) entropyValue.textContent = '-';
        if (riskScoreDisplay) riskScoreDisplay.textContent = '-';
    }

    // ============================================
    // SCROLL TO RESULT
    // ============================================
    function scrollToResult() {
        setTimeout(() => {
            resultDiv.scrollIntoView({ behavior: 'smooth', block: 'center' });
        }, 300);
    }

    // ============================================
    // ESCAPE HTML
    // ============================================
    function escapeHtml(str) {
        if (str === undefined || str === null) return '';
        return String(str)
            .replace(/&/g, '&amp;')
            .replace(/</g, '&lt;')
            .replace(/>/g, '&gt;')
            .replace(/"/g, '&quot;')
            .replace(/'/g, '&#39;');
    }

    // ============================================
    // SHOW ERROR
    // ============================================
    function showError(message) {
        let toastContainer = document.getElementById('toast-container');
        if (!toastContainer) {
            toastContainer = document.createElement('div');
            toastContainer.id = 'toast-container';
            toastContainer.style.cssText = `
                position: fixed;
                bottom: 30px;
                left: 50%;
                transform: translateX(-50%);
                z-index: 9999;
                max-width: 90%;
                display: flex;
                flex-direction: column;
                align-items: center;
                gap: 10px;
            `;
            document.body.appendChild(toastContainer);
        }

        const toast = document.createElement('div');
        toast.className = 'toast';
        toast.style.cssText = `
            background: rgba(252, 129, 129, 0.95);
            color: white;
            padding: 16px 32px;
            border-radius: 16px;
            font-weight: 500;
            backdrop-filter: blur(10px);
            box-shadow: 0 12px 40px rgba(252, 129, 129, 0.3);
            text-align: center;
            animation: slideUp 0.3s ease;
            font-family: 'Inter', sans-serif;
            width: 100%;
        `;
        toast.innerHTML = `<i class="fas fa-exclamation-circle"></i> ${escapeHtml(message)}`;

        toastContainer.appendChild(toast);

        setTimeout(() => {
            toast.style.opacity = '0';
            toast.style.transition = 'opacity 0.3s ease';
            setTimeout(() => {
                if (toast.parentNode) toast.remove();
            }, 300);
        }, 5000);
    }

    console.log('🚀 PhishGuard Pro initialized successfully!');
});
