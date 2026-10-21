"""
Complete Phishing Detection System with Web of Trust Integration
FIXED VERSION 10:
  - ✅ FIXED: Removed early-exit bug — ML now always runs (except for hard whitelist).
  - ✅ FIXED: Typosquatting detection now runs in predict() directly, not as side-effect.
  - ✅ FIXED: Homoglyph substitution detection (paypa1 -> paypal, g00gle -> google).
  - ✅ FIXED: Hard override forces 99% phishing when typo is detected.
  - ✅ FIXED: JSON Serialization (numpy types -> native Python types).
  - ✅ FIXED: Google's defensive typo domains in whitelist (gogle.com, etc.).
  - ✅ FIXED: ML Model Prob UI text now says "confidence in safety" when low.
"""

import json
import os
import re
import math
import numpy as np
import pandas as pd
from urllib.parse import urlparse
from datetime import datetime
import tldextract
import socket
import ssl
import joblib
import warnings
warnings.filterwarnings('ignore')


# ============================================
# LEVENSHTEIN DISTANCE HELPER
# ============================================
def levenshtein_distance(s1, s2):
    if len(s1) < len(s2):
        return levenshtein_distance(s2, s1)
    if len(s2) == 0:
        return len(s1)
    previous_row = range(len(s2) + 1)
    for i, c1 in enumerate(s1):
        current_row = [i + 1]
        for j, c2 in enumerate(s2):
            insertions = previous_row[j + 1] + 1
            deletions = current_row[j] + 1
            substitutions = previous_row[j] + (c1 != c2)
            current_row.append(min(insertions, deletions, substitutions))
        previous_row = current_row
    return previous_row[-1]


# ============================================
# EXACT FEATURE LIST
# ============================================
TRAINING_FEATURES = [
    'url_length', 'has_ip_address', 'dot_count', 'https_flag', 'url_entropy',
    'token_count', 'subdomain_count', 'query_param_count', 'tld_length',
    'path_length', 'has_hyphen_in_domain', 'number_of_digits', 'tld_popularity',
    'suspicious_file_extension', 'domain_name_length', 'percentage_numeric_chars',
]


FREE_HOSTING_PATTERNS = [
    'godaddysites.com', 'weeblysite.com', 'weebly.com', 'wixsite.com',
    'pages.dev', 'vercel.app', 'netlify.app', 'workers.dev',
    'firebaseapp.com', 'web.app', 'r2.dev', 'gitbook.io',
    'square.site', 'blogspot.com', 'webcindario.com', 'surge.sh',
    'replit.app', 'glitch.me', 'altervista.org', '000webhostapp.com',
    'infinityfreeapp.com', 'byethost', 'epizy.com', 'mybluehost.me',
    'myqcloud.com', 'ipfs.dweb.link', 'fleek.co', 'cos.ap-',
]


class PhishingDetector:
    def __init__(self):
        self.model = None
        self.scaler = None
        self.feature_selector = None
        self.feature_names = []
        self.model_path = 'models/detector_model.pkl'
        self.scaler_path = 'models/scaler.pkl'
        self.selector_path = 'models/selector.pkl'
        self.metadata_path = 'models/metadata.json'

        # WHITELIST
        self.trusted_domains = {
            'google.com', 'www.google.com', 'accounts.google.com', 'mail.google.com',
            'gogle.com', 'www.gogle.com', 'googl.com', 'www.googl.com',
            'googel.com', 'www.googel.com', 'g00gle.com', 'www.g00gle.com',
            'youtube.com', 'www.youtube.com', 'm.youtube.com', 'youtu.be',
            'facebook.com', 'www.facebook.com', 'm.facebook.com', 'fb.com',
            'amazon.com', 'www.amazon.com', 'smile.amazon.com',
            'microsoft.com', 'www.microsoft.com', 'office.com', 'outlook.com',
            'apple.com', 'www.apple.com', 'icloud.com', 'appleid.apple.com',
            'paypal.com', 'www.paypal.com', 'sandbox.paypal.com',
            'netflix.com', 'www.netflix.com',
            'github.com', 'www.github.com', 'gist.github.com',
            'twitter.com', 'www.twitter.com', 'x.com',
            'instagram.com', 'www.instagram.com',
            'linkedin.com', 'www.linkedin.com',
            'reddit.com', 'www.reddit.com',
            'wikipedia.org', 'www.wikipedia.org', 'en.wikipedia.org',
            'stackoverflow.com', 'www.stackoverflow.com',
            'zoom.us', 'www.zoom.us',
            'slack.com', 'www.slack.com',
            'notion.so', 'www.notion.so',
            'dropbox.com', 'www.dropbox.com',
            'spotify.com', 'www.spotify.com',
            'adobe.com', 'www.adobe.com',
            'salesforce.com', 'www.salesforce.com',
            'deepseek.com', 'www.deepseek.com', 'chat.deepseek.com',
            'openai.com', 'www.openai.com', 'chat.openai.com',
            'claude.ai', 'www.claude.ai',
            'perplexity.ai', 'www.perplexity.ai',
            'huggingface.co', 'www.huggingface.co',
            'chase.com', 'www.chase.com',
            'wellsfargo.com', 'www.wellsfargo.com',
            'bankofamerica.com', 'www.bankofamerica.com',
            'capitalone.com', 'www.capitalone.com',
            'citi.com', 'www.citi.com',
            'tiktok.com', 'www.tiktok.com',
            'snapchat.com', 'www.snapchat.com',
            'pinterest.com', 'www.pinterest.com',
            'tumblr.com', 'www.tumblr.com',
            'cnn.com', 'bbc.com', 'nytimes.com', 'wsj.com', 'reuters.com',
            'apnews.com', 'bloomberg.com', 'forbes.com', 'techcrunch.com',
            'ebay.com', 'walmart.com', 'target.com', 'bestbuy.com',
            'etsy.com', 'shopify.com',
        }

        self.trusted_tlds = {
            '.com', '.org', '.net', '.edu', '.gov', '.mil',
            '.io', '.ai', '.co', '.uk', '.de', '.fr', '.jp', '.ca', '.au'
        }

        # BRANDS
        self.brands = [
            'google', 'youtube', 'facebook', 'twitter', 'paypal', 'amazon',
            'microsoft', 'apple', 'netflix', 'github', 'linkedin', 'deepseek',
            'openai', 'perplexity', 'claude', 'uphold', 'coinbase', 'binance',
            'metamask', 'kraken', 'kucoin', 'instagram', 'whatsapp', 'telegram',
            'gemini', 'ledger', 'trezor', 'robinhood', 'dana', 'orange'
        ]

        self.suspicious_keywords = [
            'login', 'signin', 'verify', 'confirm',
            'authenticate', 'validate', 'credential',
            'password', 'suspended', 'unusual',
            'recover', 'reset', 'unlock', 'authorize',
            '2fa', 'two-factor',
            'godaddysites', 'godaddy', 'uphold', 'coinbase', 'binance',
            'wallet', 'crypto', 'blockchain', 'exchange',
        ]

        self.shortening_services = {
            'bit.ly', 'tinyurl', 'goo.gl', 'is.gd', 'buff.ly', 'ow.ly',
            't.co', 'lnkd.in', 'db.tt', 'qr.ae', 'cur.lv', 'shorte.st',
            'tiny.cc', 'shorturl.at', 'rb.gy', 'v.gd', 'cutt.ly', 'rebrand.ly',
            'lihi.cc', 'urlz.fr',
        }

        self.suspicious_tlds = {
            '.tk', '.ml', '.ga', '.cf', '.xyz', '.top', '.club', '.work', '.win',
            '.bid', '.date', '.download', '.review', '.stream', '.trade', '.webcam',
            '.space', '.site', '.men', '.online', '.store', '.tech', '.live',
            '.fun', '.click', '.pro', '.cloud', '.host', '.press', '.rocks', '.gq',
            '.cc', '.icu', '.sbs', '.homes', '.vip', '.shop', '.bond', '.best', '.life',
        }

        self.phishing_patterns = [
            'godaddysites', 'secure-login', 'login-verify', 'verify-account',
            'account-update', 'security-check', 'bank-verify', '-login-',
            'confirm-identity', 'validate-account', 'signin-verify',
            'secure-verify', 'account-verify', 'verify-login',
            'update-account', 'account-secure', 'security-update',
        ]

        self.popular_tlds = {'com', 'org', 'net', 'edu', 'gov', 'io', 'ai', 'co'}

        self.reputation_cache = {}
        self.reputation_cache_file = 'reputation_cache.json'
        self._load_reputation_cache()

        os.makedirs('models', exist_ok=True)
        self.load_model()

    def _load_reputation_cache(self):
        try:
            if os.path.exists(self.reputation_cache_file):
                with open(self.reputation_cache_file, 'r') as f:
                    self.reputation_cache = json.load(f)
        except:
            self.reputation_cache = {}

    def _save_reputation_cache(self):
        try:
            with open(self.reputation_cache_file, 'w') as f:
                json.dump(self.reputation_cache, f)
        except:
            pass

    def load_model(self):
        try:
            if all(os.path.exists(p) for p in [self.model_path, self.scaler_path, self.selector_path]):
                self.model = joblib.load(self.model_path)
                self.scaler = joblib.load(self.scaler_path)
                self.feature_selector = joblib.load(self.selector_path)
                if os.path.exists(self.metadata_path):
                    with open(self.metadata_path, 'r') as f:
                        metadata = json.load(f)
                        self.feature_names = metadata.get('feature_names', [])
                if not self.feature_names:
                    self.feature_names = TRAINING_FEATURES.copy()
                return True
        except Exception as e:
            print(f"⚠️ Could not load model: {e}")
        return False

    def save_model(self):
        joblib.dump(self.model, self.model_path, compress=3)
        joblib.dump(self.scaler, self.scaler_path, compress=3)
        joblib.dump(self.feature_selector, self.selector_path, compress=3)
        metadata = {
            'feature_names': self.feature_names,
            'classes': [int(c) for c in self.model.classes_],
        }
        with open(self.metadata_path, 'w') as f:
            json.dump(metadata, f)

    def check_domain_reputation(self, domain):
        domain_clean = domain.replace('www.', '').split(':')[0]

        if domain_clean in self.reputation_cache:
            cache_time = self.reputation_cache[domain_clean].get('timestamp', 0)
            if datetime.now().timestamp() - cache_time < 7 * 24 * 60 * 60:
                return self.reputation_cache[domain_clean]

        reputation = {
            'score': 0, 'is_trusted': False, 'age_days': 0,
            'has_valid_ssl': False, 'is_popular': False, 'source': 'unknown'
        }

        if domain_clean in self.trusted_domains:
            reputation.update({'score': 100, 'is_trusted': True, 'source': 'whitelist', 'is_popular': True})
            self.reputation_cache[domain_clean] = reputation
            self._save_reputation_cache()
            return reputation

        if re.match(r'^(\d{1,3}\.){3}\d{1,3}$', domain_clean):
            reputation.update({'score': 0, 'is_trusted': False, 'source': 'ip_address'})
            self.reputation_cache[domain_clean] = reputation
            self._save_reputation_cache()
            return reputation

        is_free_host = any(host in domain_clean for host in FREE_HOSTING_PATTERNS)

        try:
            context = ssl.create_default_context()
            with socket.create_connection((domain_clean, 443), timeout=3) as sock:
                with context.wrap_socket(sock, server_hostname=domain_clean) as ssock:
                    cert = ssock.getpeercert()
                    if cert:
                        reputation['has_valid_ssl'] = True
                        reputation['score'] += 5 if is_free_host else 30
                        reputation['source'] = 'ssl_valid'
        except:
            pass

        if domain_clean.endswith(('.edu', '.gov', '.mil')):
            reputation.update({'score': 100, 'is_trusted': True, 'source': 'tld_trusted'})

        if not is_free_host:
            for tld in self.trusted_tlds:
                if domain_clean.endswith(tld):
                    reputation['score'] += 20
                    break

        reputation['score'] = min(100, reputation['score'])
        if reputation['score'] >= 70 and not is_free_host:
            reputation['is_trusted'] = True

        reputation['timestamp'] = datetime.now().timestamp()
        self.reputation_cache[domain_clean] = reputation
        self._save_reputation_cache()
        return reputation

    def extract_all_features(self, url):
        if not url:
            return None
        try:
            parsed = urlparse(url)
            ext = tldextract.extract(url)
            domain = parsed.netloc.lower()
            path = parsed.path.lower()
            query = parsed.query.lower()
            full_url = url.lower()

            if not domain:
                if parsed.path and '.' in parsed.path:
                    domain = parsed.path.split('/')[0].lower()
                else:
                    domain = url.replace('http://', '').replace('https://', '').split('/')[0]

            domain_clean = domain.replace('www.', '')
            domain_no_port = domain_clean.split(':')[0]

            if ext.suffix:
                tld_suffix = ext.suffix
            elif '.' in domain_no_port:
                tld_suffix = domain_no_port.split('.')[-1]
            else:
                tld_suffix = ''

            reputation = self.check_domain_reputation(domain)

            return {
                'url_length': len(url),
                'has_ip_address': 1 if re.match(r'^(\d{1,3}\.){3}\d{1,3}$', domain_no_port) else 0,
                'dot_count': url.count('.'),
                'https_flag': 1 if parsed.scheme == 'https' else 0,
                'url_entropy': self._calculate_entropy(url),
                'token_count': len(url.split('/')),
                'subdomain_count': len(ext.subdomain.split('.')) if ext.subdomain else 0,
                'query_param_count': len(query.split('&')) if query else 0,
                'tld_length': len(tld_suffix),
                'path_length': len(parsed.path),
                'has_hyphen_in_domain': 1 if '-' in domain_no_port else 0,
                'number_of_digits': sum(c.isdigit() for c in url),
                'tld_popularity': 1 if tld_suffix in self.popular_tlds else 0,
                'suspicious_file_extension': 1 if any(
                    path.endswith(e) for e in ['.exe', '.bat', '.cmd', '.js', '.jar', '.apk', '.scr', '.vbs']
                ) else 0,
                'domain_name_length': len(ext.domain) if ext.domain else len(domain_no_port.split('.')[0]),
                'percentage_numeric_chars': (sum(c.isdigit() for c in url) / max(len(url), 1)) * 100,
                '_reputation': reputation,
            }
        except Exception as e:
            print(f"⚠️ Feature extraction error: {e}")
            return None

    def _calculate_entropy(self, text):
        try:
            if not text:
                return 0
            freq = {}
            for c in text[:500]:
                freq[c] = freq.get(c, 0) + 1
            total = sum(freq.values())
            if total == 0:
                return 0
            return -sum((count/total) * math.log2(count/total) for count in freq.values() if count > 0)
        except:
            return 0

    def _detect_typosquatting(self, domain_no_port):
        """
        Aggressive typosquatting check.
        Returns (is_typo: bool, matched_brand: str or None)
        """
        # Strip port if any
        domain = domain_no_port.split(':')[0]

        # Whitelist bypass (Google's defensive typo domains like gogle.com)
        if domain in self.trusted_domains:
            return False, None

        # Strip the TLD to get the root (e.g., "paypa1-login" from "paypa1-login.com")
        domain_root = domain
        for tld in ['.com', '.org', '.net', '.io', '.ai', '.co', '.uk', '.de', '.fr',
                    '.us', '.ca', '.in', '.ru', '.xyz', '.tk', '.ml', '.ga', '.cf',
                    '.site', '.app', '.dev', '.live', '.shop', '.vip', '.top']:
            if domain_root.endswith(tld):
                domain_root = domain_root[:-len(tld)]
                break

        # Split on hyphens and dots to check each token
        parts = re.split(r'[\.\-]', domain_root)

        for part in parts:
            if len(part) < 4:
                continue

            # Exact brand match inside compound domain (e.g. "paypal" in "paypal-login.com")
            # This is suspicious even though "paypal.com" itself is safe (we whitelisted it above)
            if part in self.brands:
                return True, part

            for brand in self.brands:
                # Length must be within 1 of the brand (paypa1 vs paypal = 0 diff in length; paypaal = 1 diff)
                if abs(len(part) - len(brand)) > 1:
                    continue

                # Check 1: Levenshtein distance <= 2
                if levenshtein_distance(part, brand) <= 2:
                    return True, brand

                # Check 2: Single homoglyph substitution (1 -> l, 0 -> o, etc.)
                if len(part) == len(brand):
                    mismatches = sum(1 for a, b in zip(part, brand) if a != b)
                    if mismatches == 1:
                        return True, brand

        return False, None

    def _rule_based_detection(self, url, is_typo, matched_brand):
        url_lower = url.lower()
        risk_score = 0
        risky_features = []

        parsed = urlparse(url)
        domain = parsed.netloc.lower()
        domain_no_port = domain.replace('www.', '').split(':')[0]

        reputation = self.check_domain_reputation(domain)

        # WHITELIST HARD OVERRIDE
        if reputation.get('source') == 'whitelist':
            warning_msg = "✅ Domain is on the trusted whitelist"
            if not url_lower.startswith('https'):
                warning_msg = "✅ Domain is on the trusted whitelist (⚠️ Warning: Uses insecure HTTP connection)"
            return {
                'is_phishing': False,
                'confidence': 0.99,
                'risk_score': 0,
                'probability': {'phishing': 0.01, 'legitimate': 0.99},
                'risky_features': [warning_msg],
                'features': {},
                'url': url,
                'reputation': reputation,
                'detection_method': 'rule-based',
            }

        # TYPOSQUATTING (highest priority)
        if is_typo:
            risk_score += 85
            risky_features.append(f"🚨 Typosquatting detected: '{domain_no_port}' mimics '{matched_brand}'")

        is_free_host = any(host in domain_no_port for host in FREE_HOSTING_PATTERNS)

        if is_free_host:
            risk_score += 20
            risky_features.append(f"Free-hosting platform: {domain_no_port}")

        for pattern in self.phishing_patterns:
            if pattern in url_lower:
                risk_score += 30
                risky_features.append(f"Phishing pattern: '{pattern}'")
                break

        suspicious_count = sum(1 for kw in self.suspicious_keywords if kw in domain_no_port)
        if suspicious_count >= 2:
            risk_score += 30
            risky_features.append(f"Multiple suspicious keywords in domain ({suspicious_count})")
        elif suspicious_count >= 1:
            first_kw = next(kw for kw in self.suspicious_keywords if kw in domain_no_port)
            risk_score += 20
            risky_features.append(f"Suspicious keyword in domain: '{first_kw}'")

        if re.search(r'(\d{1,3}\.){3}\d{1,3}', domain_no_port):
            risk_score += 40
            risky_features.append("Uses IP address instead of domain name")

        if not url_lower.startswith('https'):
            risk_score += 15
            risky_features.append("No HTTPS (insecure connection)")

        if any(service in url_lower for service in self.shortening_services):
            risk_score += 25
            risky_features.append("URL shortened - hides destination")

        hostname_tld = '.' + domain_no_port.split('.')[-1] if '.' in domain_no_port else ''
        if hostname_tld in self.suspicious_tlds:
            risk_score += 25
            risky_features.append(f"Suspicious TLD ({hostname_tld})")

        if '@' in url:
            risk_score += 30
            risky_features.append("Contains '@' symbol - can obscure destination")

        if len(domain_no_port.split('.')) - 1 > 3:
            risk_score += 15
            risky_features.append(f"Excessive subdomains")

        if '-' in domain_no_port:
            risk_score += 8
            risky_features.append("Contains hyphens in domain")

        if len(url) > 100:
            risk_score += 5
            risky_features.append(f"Long URL ({len(url)} characters)")

        # Ensure typo detection forces the score high
        if is_typo:
            risk_score = max(risk_score, 85)

        final_risk_score = min(100, risk_score)

        return {
            'is_phishing': bool(final_risk_score >= 40),
            'confidence': float(final_risk_score / 100),
            'risk_score': int(final_risk_score),
            'probability': {
                'phishing': float(final_risk_score / 100),
                'legitimate': float(1 - (final_risk_score / 100))
            },
            'risky_features': risky_features if risky_features else ["No obvious rule-based risk factors detected."],
            'features': {},
            'url': url,
            'reputation': reputation,
            'detection_method': 'rule-based',
        }

    def predict(self, url):
        parsed = urlparse(url)
        domain = parsed.netloc.lower().replace('www.', '').split(':')[0]

        # Auto-upgrade HTTP to HTTPS for whitelisted domains
        if domain in self.trusted_domains and url.startswith('http://'):
            url = url.replace('http://', 'https://', 1)
            parsed = urlparse(url)

        domain_no_port = domain.split(':')[0]

        # Pre-compute typosquatting ONCE
        is_typo, matched_brand = self._detect_typosquatting(domain_no_port)

        # Run rule-based
        rule_results = self._rule_based_detection(url, is_typo, matched_brand)

        # HARD WHITELIST SHORT-CIRCUIT — only for genuinely whitelisted domains
        if rule_results.get('detection_method') == 'rule-based' and \
           rule_results.get('risk_score') == 0 and \
           rule_results['reputation'].get('source') == 'whitelist':
            return rule_results

        # Extract features
        features = self.extract_all_features(url)
        if not features:
            return rule_results

        # ML PREDICTION (always runs for non-whitelisted URLs)
        ml_phishing_prob = 0.5
        if self.model and self.scaler and self.feature_selector:
            try:
                feature_vector = [features.get(f_name, 0) for f_name in self.feature_names]
                X = np.array([feature_vector])
                X_scaled = self.scaler.transform(X)
                X_selected = self.feature_selector.transform(X_scaled)
                probs = self.model.predict_proba(X_selected)[0]

                classes = list(self.model.classes_)
                class_idx = classes.index(1) if 1 in classes else 1
                ml_phishing_prob = float(probs[class_idx])
            except Exception as e:
                print(f"ML Prediction Error: {e}")
                ml_phishing_prob = 0.5

        # HYBRID FUSION
        rule_score_normalized = rule_results['risk_score'] / 100.0
        final_prob = (0.4 * ml_phishing_prob) + (0.6 * rule_score_normalized)

        # HARD OVERRIDE: Typosquatting = 99% phishing, ML irrelevant
        if is_typo:
            final_prob = max(final_prob, 0.99)

        # HARD OVERRIDE: Whitelist = 5% risk
        rep = features['_reputation']
        if rep.get('is_trusted') or rep.get('source') == 'whitelist':
            final_prob = 0.05

        final_risk_score = int(final_prob * 100)
        is_phishing = bool(final_prob >= 0.35)

        # UI Display Formatting
        all_features = []
        if ml_phishing_prob > 0.50:
            all_features.append(f"ML Model suspicious probability: {ml_phishing_prob*100:.1f}%")
        else:
            all_features.append(f"ML Model confidence in safety: {(1 - ml_phishing_prob)*100:.1f}%")

        if rule_results['risky_features']:
            all_features.extend(rule_results['risky_features'])

        # ENSURE NATIVE PYTHON TYPES FOR JSON SERIALIZATION
        return {
            'is_phishing': bool(is_phishing),
            'confidence': float(final_prob if is_phishing else (1 - final_prob)),
            'risk_score': int(final_risk_score),
            'probability': {
                'phishing': float(final_prob),
                'legitimate': float(1 - final_prob)
            },
            'risky_features': all_features,
            'features': features,
            'url': url,
            'reputation': rep,
            'detection_method': 'hybrid'
        }
