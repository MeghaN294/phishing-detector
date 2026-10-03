"""
Complete Phishing Detection System with Web of Trust Integration
Aligned with training CSV schema (16 pre-extracted features)
FIXED VERSION 3:
  - ✅ CRITICAL: Label inversion fix (dataset uses 1=legitimate, 0=phishing;
       code now normalizes to 1=phishing everywhere)
  - Class index bug fixed
  - utf-8-sig encoding (BOM guard)
  - Free-hosting platform detection
  - IP address with non-standard port detection
  - Malware path pattern detection
  - Weighted hybrid (0.4 ML / 0.6 rules)
  - Raised thresholds (was causing false positives)
  - Suspicious TLD check only on hostname TLD, not full URL
  - Suspicious keywords only counted in domain, not full URL
  - ML override only when rules also saw something suspicious
  - SSL credit only for non-free-host domains
  - Explicit label column detection
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
from sklearn.ensemble import RandomForestClassifier
from sklearn.preprocessing import StandardScaler
from sklearn.model_selection import train_test_split
from sklearn.feature_selection import SelectKBest, mutual_info_classif
from sklearn.metrics import accuracy_score, precision_score, recall_score, f1_score, confusion_matrix
import joblib
import warnings
warnings.filterwarnings('ignore')


# ============================================
# EXACT FEATURE LIST FROM TRAINING CSV
# ============================================
TRAINING_FEATURES = [
    'url_length',
    'has_ip_address',
    'dot_count',
    'https_flag',
    'url_entropy',
    'token_count',
    'subdomain_count',
    'query_param_count',
    'tld_length',
    'path_length',
    'has_hyphen_in_domain',
    'number_of_digits',
    'tld_popularity',
    'suspicious_file_extension',
    'domain_name_length',
    'percentage_numeric_chars',
]


# Free-hosting / abuse-prone platforms
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

        # ============================================
        # WEB OF TRUST - HIGH TRUST DOMAINS
        # ============================================
        self.trusted_domains = {
            'google.com', 'www.google.com', 'accounts.google.com', 'mail.google.com',
            'youtube.com', 'www.youtube.com', 'm.youtube.com',
            'facebook.com', 'www.facebook.com', 'm.facebook.com',
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

        # ============================================
        # EXPANDED BRANDS WITH TYPOS
        # ============================================
        self.brands = {
            'google': ['gooogle', 'goggle', 'googel', 'goolge', 'googlee', 'gogle', 'goole', 'googIe', 'goggl', 'g00gle', 'goog1e', 'g00g1e'],
            'youtube': ['youtub', 'yutube', 'youtbe', 'you-tube', 'youtu.be', 'y0utube', 'youtub3', 'y0utub3'],
            'facebook': ['facebok', 'faceboook', 'facbook', 'fasebook', 'face-book', 'faceb00k', 'f4cebook'],
            'twitter': ['twiter', 'twtter', 'twiiter', 'twittr', 'twitt3r', 'twittter', 'tw1tter'],
            'paypal': ['paypall', 'paypol', 'pay-pal', 'paypai', 'paypa1', 'payp4l', 'paypa1.com'],
            'amazon': ['amaz0n', 'amazn', 'amzon', 'amazzon', 'amazan', 'am4zon'],
            'microsoft': ['micros0ft', 'microsof', 'mcrosoft', 'micr0soft', 'microsft', 'micr0s0ft'],
            'apple': ['appIe', 'app1e', 'appleid', 'app1eid', 'app1e-id'],
            'netflix': ['netflx', 'netfllix', 'netflex', 'net-flix', 'netfilx', 'n3tflix', 'netfl1x'],
            'github': ['githu', 'gihub', 'gthub', 'git-hub', 'git.hub', 'g1thub', 'githubb'],
            'linkedin': ['linkdin', 'linked', 'linkdIn', 'link-edin', 'Iinkedin', '1inkedin', 'linked1n'],
            'deepseek': ['deepseak', 'deepsek', 'deekseek', 'depseek', 'deapseek', 'd3epseek'],
            'openai': ['openal', 'opneai', 'opeani', 'openi', 'openaAI', '0penai', 'open-ai'],
            'perplexity': ['perplexiy', 'perplxity', 'perplexityai', 'perpIexity', 'perpl3xity'],
            'claude': ['claud', 'cloude', 'cIaude', 'cluade', 'c1aude', 'claud3'],
            'uphold': ['uph0ld', 'upholds', 'upholdch', 'uphld', 'uphold-login', 'uphold-verify', 'upphioold', 'uphoild'],
            'coinbase': ['c0inbase', 'coinb4se', 'coinbasee', 'coinbse', 'coinbase-login', 'coinbase-verify', 'koinbase', 'conibase'],
            'binance': ['b1nance', 'bin4nce', 'binancee', 'bnance', 'binance-login', 'binance-verify'],
            'metamask': ['metam4sk', 'metamaskk', 'metmask', 'meta-mask', 'metamsk', 'mittemassk', 'metoiamask', 'mithamask'],
            'kraken': ['kr4ken', 'krakenk', 'krak3n', 'kraken-login', 'kraqken', 'kcrakeen'],
            'kucoin': ['kuco1n', 'kucoin-', 'kucoinx', 'kucoin-login', 'kuoin', 'kuucckioneelos'],
            'instagram': ['1nstagram', 'instagr4m', 'instgram', '1nsta', 'insta-gram'],
            'whatsapp': ['whatsap', 'whats4pp', 'whatsappp', 'whats-app'],
            'telegram': ['telegrm', 't3legram', 'telegran', 'tele-gram', 'telgram', 'telegroom'],
            'gemini': ['gemine', 'gemiin', 'gemunniix', 'gemine-logien', 'geminius', 'gaamineilogius', 'gemeni', 'gemine_logix'],
            'ledger': ['1edger', 'ledgr', 'ledger-', 'ledgerlive', 'ledger-live'],
            'trezor': ['trezo', 'trazor', 'trezorr', 'trezor-', 'triezierewaleiite'],
            'robinhood': ['robinhod', 'robinhoood', 'robihood', 'robinhood-', 'robnhood', 'rounbenlogin'],
            'dana': ['dana-', 'danaid', 'dana-id', 'danaindonesia'],
            'att': ['at&t', 'att-', 'attt', 'aatt'],
            'orange': ['0range', 'or4nge', 'orange-', 'orangepro'],
        }

        # ============================================
        # SUSPICIOUS KEYWORDS
        # Removed overly broad terms (support, account, update, security)
        # ============================================
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

        # Suspicious TLD list — removed legitimate ccTLDs (.be, .cm, .sh, .me, .app, .dev, .info, .biz)
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
                print("📂 Loading ML model...")
                self.model = joblib.load(self.model_path)
                self.scaler = joblib.load(self.scaler_path)
                self.feature_selector = joblib.load(self.selector_path)

                if os.path.exists(self.metadata_path):
                    with open(self.metadata_path, 'r') as f:
                        metadata = json.load(f)
                        self.feature_names = metadata.get('feature_names', [])

                if not self.feature_names:
                    self.feature_names = TRAINING_FEATURES.copy()

                print(f"✅ Model loaded ({os.path.getsize(self.model_path)/1024:.1f} KB)")
                print(f"   Classes: {list(self.model.classes_)}")
                return True
        except Exception as e:
            print(f"⚠️ Could not load model: {e}")
        return False

    def save_model(self):
        print("💾 Saving ML model...")
        joblib.dump(self.model, self.model_path, compress=3)
        joblib.dump(self.scaler, self.scaler_path, compress=3)
        joblib.dump(self.feature_selector, self.selector_path, compress=3)

        metadata = {
            'feature_names': self.feature_names,
            'model_size_kb': os.path.getsize(self.model_path) / 1024,
            'features_count': len(self.feature_names),
            'model_type': 'RandomForestClassifier',
            'classes': [int(c) for c in self.model.classes_],
            'label_convention': '1=phishing, 0=legitimate (normalized at training)',
            'timestamp': str(pd.Timestamp.now())
        }
        with open(self.metadata_path, 'w') as f:
            json.dump(metadata, f)
        print(f"✅ Model saved ({os.path.getsize(self.model_path)/1024:.1f} KB)")

    # ============================================
    # WEB OF TRUST
    # ============================================

    def check_domain_reputation(self, domain):
        domain_clean = domain.replace('www.', '')
        domain_clean = domain_clean.split(':')[0]

        if domain_clean in self.reputation_cache:
            cache_time = self.reputation_cache[domain_clean].get('timestamp', 0)
            if datetime.now().timestamp() - cache_time < 7 * 24 * 60 * 60:
                return self.reputation_cache[domain_clean]

        reputation = {
            'score': 0, 'is_trusted': False, 'age_days': 0,
            'has_valid_ssl': False, 'is_popular': False, 'source': 'unknown'
        }

        if domain_clean in self.trusted_domains:
            reputation['score'] = 100
            reputation['is_trusted'] = True
            reputation['source'] = 'whitelist'
            reputation['is_popular'] = True
            self.reputation_cache[domain_clean] = reputation
            self._save_reputation_cache()
            return reputation

        if re.match(r'^(\d{1,3}\.){3}\d{1,3}$', domain_clean):
            reputation['score'] = 0
            reputation['is_trusted'] = False
            reputation['source'] = 'ip_address'
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
                        if not is_free_host:
                            reputation['score'] += 30
                        else:
                            reputation['score'] += 5
                        reputation['source'] = 'ssl_valid'
        except:
            pass

        if domain_clean.endswith(('.edu', '.gov', '.mil')):
            reputation['score'] = 100
            reputation['is_trusted'] = True
            reputation['source'] = 'tld_trusted'

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

    # ============================================
    # FEATURE EXTRACTION - EXACT CSV MATCH
    # ============================================

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

            features = {
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

                # Extra helpers
                '_domain': domain_clean,
                '_domain_no_port': domain_no_port,
                '_tld': tld_suffix,
                '_typosquatting_score': self._detect_typosquatting(domain),
                '_suspicious_keyword_count': sum(1 for kw in self.suspicious_keywords if kw in full_url),
                '_is_shortened': 1 if any(s in domain_clean for s in self.shortening_services) else 0,
                '_has_suspicious_tld': 1 if (tld_suffix and f'.{tld_suffix}' in self.suspicious_tlds) else 0,
                '_has_at_symbol': 1 if '@' in url else 0,
                '_has_double_slash': 1 if '//' in url and 'https://' not in url and 'http://' not in url else 0,
                '_brand_count': sum(1 for brand in self.brands.keys() if brand in full_url),
                '_reputation_score': reputation.get('score', 0) / 100,
                '_has_valid_ssl': 1 if reputation.get('has_valid_ssl', False) else 0,
                '_reputation': reputation,
            }

            return features

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

    def _detect_typosquatting(self, domain):
        score = 0
        domain_clean = domain.replace('www.', '').lower().split(':')[0]

        domain_without_tld = domain_clean
        for tld in ['.com', '.org', '.net', '.io', '.ai', '.co', '.uk', '.de', '.fr',
                    '.us', '.ca', '.in', '.ru', '.xyz', '.tk', '.ml', '.ga', '.cf',
                    '.site', '.app', '.dev', '.live', '.shop', '.vip', '.top']:
            if domain_without_tld.endswith(tld):
                domain_without_tld = domain_without_tld[:-len(tld)]
                break

        if domain_clean in [td.replace('www.', '') for td in self.trusted_domains]:
            return 0

        for brand, typos in self.brands.items():
            if brand in domain_without_tld:
                if domain_without_tld != brand:
                    if self._is_similar_string(domain_without_tld, brand):
                        score += 10
                        break
                    elif len(domain_without_tld) > len(brand) + 1:
                        if self._is_similar_string(domain_without_tld, brand):
                            score += 8
                            break

            for typo in typos:
                if typo in domain_clean or typo.replace('.com', '') in domain_without_tld:
                    score += 10
                    break
                if self._is_similar_string(domain_without_tld, typo.replace('.com', '')):
                    score += 8
                    break

        if domain_clean.startswith('ww.') or domain_clean.startswith('w.'):
            score += 4

        if '-' in domain_clean:
            score += 3

        leet_substitutions = {'0': 'o', '1': 'i', '3': 'e', '4': 'a', '5': 's', '7': 't'}
        for leet, normal in leet_substitutions.items():
            if leet in domain_clean:
                test_domain = domain_clean.replace(leet, normal)
                for brand in self.brands.keys():
                    if brand in test_domain:
                        score += 5
                        break

        homograph_chars = {'rn': 'm', 'cl': 'd', 'vv': 'w'}
        for homograph, replacement in homograph_chars.items():
            if homograph in domain_clean:
                test_domain = domain_clean.replace(homograph, replacement)
                for brand in self.brands.keys():
                    if brand in test_domain:
                        score += 5
                        break

        return min(score, 10)

    def _is_similar_string(self, str1, str2):
        if abs(len(str1) - len(str2)) > 2:
            return False
        mismatches = 0
        min_len = min(len(str1), len(str2))
        for i in range(min_len):
            if str1[i] != str2[i]:
                mismatches += 1
                if mismatches > 2:
                    return False
        return True

    # ============================================
    # RULE-BASED DETECTION
    # ============================================

    def _rule_based_detection(self, url):
        url_lower = url.lower()
        risk_score = 0
        risky_features = []

        parsed = urlparse(url)
        domain = parsed.netloc.lower()
        domain_no_port = domain.replace('www.', '').split(':')[0]

        reputation = self.check_domain_reputation(domain)

        if reputation.get('source') == 'whitelist':
            return {
                'is_phishing': False,
                'confidence': 0.95,
                'risk_score': 0,
                'probability': {'phishing': 0.05, 'legitimate': 0.95},
                'risky_features': ["✅ Domain is on the trusted whitelist"],
                'features': {},
                'url': url,
                'reputation': reputation,
                'detection_method': 'rule-based',
            }

        is_free_host = any(host in domain_no_port for host in FREE_HOSTING_PATTERNS)

        malware_path_match = re.search(
            r'/(i|bin\.sh|Mozi\.\w*|nc\.exe|nc\.txt|\.scr|\.vbs|\.bin|run\.exe|wall\w*\.exe|del\.exe)$',
            url_lower
        )

        ip_port_match = re.search(r'^\w+://(\d{1,3}\.){3}\d{1,3}:(\d{2,5})/', url)

        # ---- RULE 0: brand on free host = phishing ----
        if is_free_host:
            brand_on_free_host = None
            for brand in self.brands.keys():
                if brand in domain_no_port or brand in url_lower:
                    brand_on_free_host = brand
                    break
            if brand_on_free_host:
                risk_score += 55
                risky_features.append(
                    f"Brand '{brand_on_free_host}' on free-hosting platform '{domain_no_port}'"
                )
            else:
                risk_score += 20
                risky_features.append(f"Free-hosting platform: {domain_no_port}")

        # ---- RULE 1: phishing patterns ----
        for pattern in self.phishing_patterns:
            if pattern in url_lower:
                risk_score += 30
                risky_features.append(f"Phishing pattern: '{pattern}'")
                break

        # ---- RULE 2: typosquatting ----
        typosquatting_detected = False
        matched_brand = None

        domain_without_tld = domain_no_port
        for tld in ['.com', '.org', '.net', '.io', '.ai', '.co', '.uk', '.de', '.fr',
                    '.us', '.site', '.app', '.dev', '.live', '.shop', '.vip', '.top']:
            if domain_without_tld.endswith(tld):
                domain_without_tld = domain_without_tld[:-len(tld)]
                break

        for brand, typos in self.brands.items():
            if brand in domain_without_tld and domain_without_tld != brand:
                risk_score += 45
                risky_features.append(f"Typosquatting: '{domain_no_port}' mimics '{brand}'")
                typosquatting_detected = True
                matched_brand = brand
                break

            for typo in typos:
                if typo in domain_no_port or typo.replace('.com', '') in domain_without_tld:
                    risk_score += 45
                    risky_features.append(f"Typosquatting: '{domain_no_port}' looks like '{brand}'")
                    typosquatting_detected = True
                    matched_brand = brand
                    break

            if self._is_similar_string(domain_without_tld, brand):
                risk_score += 40
                risky_features.append(f"Typosquatting: '{domain_no_port}' is similar to '{brand}'")
                typosquatting_detected = True
                matched_brand = brand
                break

            if typosquatting_detected:
                break

        # ---- RULE 3: suspicious keywords ----
        suspicious_count = 0
        first_kw = None
        for keyword in self.suspicious_keywords:
            if keyword in domain_no_port:
                suspicious_count += 1
                if first_kw is None:
                    first_kw = keyword

        path_keyword_count = sum(1 for kw in self.suspicious_keywords if kw in url_lower)

        if suspicious_count >= 2:
            risk_score += 30
            risky_features.append(f"Multiple suspicious keywords in domain ({suspicious_count})")
        elif suspicious_count >= 1:
            risk_score += 20
            risky_features.append(f"Suspicious keyword in domain: '{first_kw}'")
        elif path_keyword_count >= 3:
            risk_score += 15
            risky_features.append(f"Contains {path_keyword_count} suspicious keywords")

        # ---- RULE 4: IP address ----
        if re.search(r'(\d{1,3}\.){3}\d{1,3}', domain_no_port):
            risk_score += 40
            risky_features.append("Uses IP address instead of domain name")

        # ---- RULE 4b: IP + non-standard port ----
        if ip_port_match:
            port = int(ip_port_match.group(2))
            if port not in (80, 443):
                risk_score += 25
                risky_features.append(f"IP with non-standard port ({port}) — common in malware C2")

        # ---- RULE 4c: malware path ----
        if malware_path_match:
            risk_score += 30
            risky_features.append("Path matches known malware distribution pattern")

        # ---- RULE 5: HTTPS ----
        if not url_lower.startswith('https'):
            risk_score += 15
            risky_features.append("No HTTPS (insecure connection)")

        # ---- RULE 6: URL shortening ----
        if any(service in url_lower for service in self.shortening_services):
            risk_score += 25
            risky_features.append("URL shortened - hides destination")

        # ---- RULE 7: suspicious TLD (hostname only) ----
        hostname_tld = '.' + domain_no_port.split('.')[-1] if '.' in domain_no_port else ''
        if hostname_tld in self.suspicious_tlds:
            risk_score += 25
            risky_features.append(f"Suspicious TLD ({hostname_tld})")

        # ---- RULE 8: @ symbol ----
        if '@' in url:
            risk_score += 30
            risky_features.append("Contains '@' symbol - can obscure destination")

        # ---- RULE 9: double slash ----
        if '//' in url and 'https://' not in url and 'http://' not in url:
            risk_score += 20
            risky_features.append("Double slash redirect technique")

        # ---- RULE 10: subdomain count ----
        subdomain_count = len(domain_no_port.split('.')) - 1
        if subdomain_count > 3:
            risk_score += 15
            risky_features.append(f"Excessive subdomains ({subdomain_count})")

        # ---- RULE 11: hyphens ----
        if '-' in domain_no_port:
            risk_score += 8
            risky_features.append("Contains hyphens in domain (may mimic brand)")

        # ---- RULE 12: long URL ----
        if len(url) > 100:
            risk_score += 5
            risky_features.append(f"Long URL ({len(url)} characters)")

        # ---- RULE 13: GoDaddy Sites ----
        if 'godaddysites.com' in domain_no_port or 'godaddy' in domain_no_port:
            risk_score += 20
            risky_features.append("Hosted on GoDaddy Sites (commonly abused)")

        # ---- RULE 14: multiple brands ----
        brand_count = sum(1 for brand in self.brands.keys() if brand in url_lower)
        if brand_count > 1:
            risk_score += 20
            risky_features.append(f"Multiple brand names detected ({brand_count})")

        # ---- RULE 15: numbers in domain ----
        if re.search(r'\d{3,}', domain_without_tld):
            risk_score += 15
            risky_features.append("Contains many numbers in domain")

        risk_score = min(100, risk_score)

        if typosquatting_detected:
            risk_score = max(risk_score, 50)

        is_phishing = risk_score >= 45
        confidence = risk_score / 100

        return {
            'is_phishing': is_phishing,
            'confidence': confidence,
            'risk_score': risk_score,
            'probability': {'phishing': confidence, 'legitimate': 1 - confidence},
            'risky_features': risky_features[:10],
            'features': {},
            'typosquatting_score': 10 if typosquatting_detected else 0,
            'url': url,
            'reputation': reputation,
            'detection_method': 'rule-based',
        }

    # ============================================
    # TRAINING FROM CSV
    # ============================================

    def train_from_csv(self, csv_path):
        print("🧠 Training ML model with pre-extracted features...")
        print("=" * 50)

        if not os.path.exists(csv_path):
            print(f"⚠️ CSV file not found: {csv_path}")
            return self.train_with_sample_data()

        try:
            df = pd.read_csv(csv_path, encoding='utf-8-sig', on_bad_lines='skip')
            print(f"📈 Loaded {len(df)} records")
            print(f"📊 Columns: {list(df.columns)}")

            df.columns = df.columns.str.strip().str.replace(' ', '_')

            target_col = None
            for candidate in ['ClassLabel', 'classlabel', 'Class', 'Label']:
                if candidate in df.columns:
                    target_col = candidate
                    break
            if target_col is None:
                for col in df.columns:
                    if 'class' in col.lower() or 'label' in col.lower():
                        target_col = col
                        break

            if target_col is None:
                print("⚠️ Could not find target column")
                return self.train_with_sample_data()

            print(f"🎯 Target column: {target_col}")

            df_clean = df.dropna(subset=[target_col])
            print(f"📊 Dropped {len(df) - len(df_clean)} rows with NaN")

            if len(df_clean) == 0:
                return self.train_with_sample_data()

            feature_cols = [col for col in TRAINING_FEATURES if col in df_clean.columns]

            if len(feature_cols) < 16:
                print(f"⚠️ Only {len(feature_cols)}/16 training features found in CSV")
                print(f"Found: {feature_cols}")
                print(f"Missing: {[f for f in TRAINING_FEATURES if f not in df_clean.columns]}")

            print(f"📊 Using {len(feature_cols)} features")

            X = df_clean[feature_cols].fillna(0)
            y_raw = pd.to_numeric(df_clean[target_col], errors='coerce')

            valid_mask = ~y_raw.isna()
            X = X[valid_mask]
            y_raw = y_raw[valid_mask]

            if len(X) == 0:
                return self.train_with_sample_data()

            # ================================================
            # ✅ CRITICAL FIX: Normalize labels to 1=phishing, 0=legitimate
            # ================================================
            # The dataset uses the OPPOSITE convention:
            #   ClassLabel = 1  →  LEGITIMATE
            #   ClassLabel = 0  →  PHISHING
            #
            # We invert so the rest of the code (which assumes
            # 1 = phishing everywhere) is correct.
            # ================================================
            y = 1 - y_raw.astype(int)

            print(f"📊 Samples: {len(X):,}")
            print(f"📊 Original label distribution (from CSV):")
            print(f"     {y_raw.value_counts().to_dict()}")
            print(f"📊 Normalized label distribution (1=phishing, 0=legit):")
            print(f"     {y.value_counts().to_dict()}")

            if len(np.unique(y)) < 2:
                print(f"⚠️ Only one class present after inversion: {np.unique(y)}")
                return self.train_with_sample_data()

            self.feature_names = feature_cols.copy()

            X = np.array(X, dtype=np.float32)
            y = np.array(y, dtype=np.int32)
            X = np.nan_to_num(X, nan=0.0, posinf=0.0, neginf=0.0)

            X_train, X_test, y_train, y_test = train_test_split(
                X, y, test_size=0.2, random_state=42, stratify=y
            )

            print(f"📊 Train: {len(X_train):,}, Test: {len(X_test):,}")

            self.scaler = StandardScaler()
            X_train_scaled = self.scaler.fit_transform(X_train)
            X_test_scaled = self.scaler.transform(X_test)

            k = min(15, len(self.feature_names))
            self.feature_selector = SelectKBest(mutual_info_classif, k=k)
            X_train_selected = self.feature_selector.fit_transform(X_train_scaled, y_train)
            X_test_selected = self.feature_selector.transform(X_test_scaled)

            print("🧠 Training Random Forest...")
            self.model = RandomForestClassifier(
                n_estimators=200,
                max_depth=20,
                min_samples_split=3,
                min_samples_leaf=1,
                random_state=42,
                n_jobs=-1,
                class_weight='balanced'
            )
            self.model.fit(X_train_selected, y_train)

            y_pred = self.model.predict(X_test_selected)

            accuracy = accuracy_score(y_test, y_pred)
            precision = precision_score(y_test, y_pred, average='weighted')
            recall = recall_score(y_test, y_pred, average='weighted')
            f1 = f1_score(y_test, y_pred, average='weighted')
            cm = confusion_matrix(y_test, y_pred)

            print(f"\n{'='*50}")
            print(f"✅ Model Training Complete!")
            print(f"{'='*50}")
            print(f"📊 Accuracy:  {accuracy:.2%}")
            print(f"📊 Precision: {precision:.2%}")
            print(f"📊 Recall:    {recall:.2%}")
            print(f"📊 F1 Score:  {f1:.2%}")
            print(f"📊 Classes:   {list(self.model.classes_)}  (0=legit, 1=phishing)")

            if len(cm) == 2:
                print(f"\n📊 Confusion Matrix:")
                print(f"   True Legitimate:  {cm[0][0]:,}")
                print(f"   False Phishing:   {cm[0][1]:,}")
                print(f"   False Legitimate: {cm[1][0]:,}")
                print(f"   True Phishing:    {cm[1][1]:,}")

            print(f"{'='*50}\n")

            self.save_model()
            return accuracy

        except Exception as e:
            print(f"⚠️ Error training: {e}")
            import traceback
            traceback.print_exc()
            return self.train_with_sample_data()

    def train_with_sample_data(self):
        print("📚 Training with sample data...")

        feature_names = TRAINING_FEATURES.copy()
        np.random.seed(42)

        phishing_urls = [
            "http://secure-login-paypal.com", "http://gogle.com",
            "https://bank-account-verify.com", "http://apple-id-verify.com",
            "https://microsoft-update.com", "http://amazon-account.com/login",
            "https://google-security-verify.com", "http://facebook-login-verify.com",
            "https://netflix-account-update.com", "http://www.gooogle.com",
            "https://www.paypall.com", "http://www.micros0ft.com",
            "https://www.youtub.com", "http://www.netflx.com",
            "http://bit.ly/2XyZ123", "http://bank-login.tk",
            "https://upholdchlogin.godaddysites.com", "https://secure-login.tk",
            "http://verify-account.xyz", "https://coinbase-login.ml",
            "https://metamsk01lgiix.godaddysites.com",
            "http://att-109120.weeblysite.com", "http://telegramwa.com",
            "https://keraekken-loagginnusa.godaddysites.com",
            "http://91.219.171.20:37006/i", "http://59.183.116.177:55504/Mozi.m",
            "http://117.219.42.41:42760/i", "http://115.59.0.2:37388/bin.sh",
        ]

        legitimate_urls = [
            "https://www.google.com", "https://www.youtube.com",
            "https://www.facebook.com", "https://www.wikipedia.org",
            "https://www.amazon.com", "https://www.paypal.com",
            "https://www.microsoft.com", "https://www.apple.com",
            "https://www.github.com", "https://www.stackoverflow.com",
            "https://www.netflix.com", "https://www.twitter.com",
            "https://www.instagram.com", "https://www.linkedin.com",
            "https://www.reddit.com", "https://www.zoom.us",
            "https://slack.com", "https://notion.so",
        ]

        phishing_samples = []
        for url in phishing_urls:
            features = self.extract_all_features(url)
            if features:
                features_list = [features.get(name, 0) for name in feature_names]
                features_list.append(1)  # 1 = phishing
                phishing_samples.append(features_list)

        legitimate_samples = []
        for url in legitimate_urls:
            features = self.extract_all_features(url)
            if features:
                features_list = [features.get(name, 0) for name in feature_names]
                features_list.append(0)  # 0 = legitimate
                legitimate_samples.append(features_list)

        all_samples = phishing_samples + legitimate_samples
        np.random.shuffle(all_samples)

        df = pd.DataFrame(all_samples, columns=feature_names + ['ClassLabel'])
        self.feature_names = feature_names

        X = np.array(df[feature_names])
        y = np.array(df['ClassLabel'])

        X_train, X_test, y_train, y_test = train_test_split(X, y, test_size=0.2, random_state=42)

        self.scaler = StandardScaler()
        X_train_scaled = self.scaler.fit_transform(X_train)
        X_test_scaled = self.scaler.transform(X_test)

        k = min(10, len(self.feature_names))
        self.feature_selector = SelectKBest(mutual_info_classif, k=k)
        X_train_selected = self.feature_selector.fit_transform(X_train_scaled, y_train)
        X_test_selected = self.feature_selector.transform(X_test_scaled)

        self.model = RandomForestClassifier(
            n_estimators=100, max_depth=12,
            random_state=42, class_weight='balanced'
        )
        self.model.fit(X_train_selected, y_train)

        accuracy = self.model.score(X_test_selected, y_test)
        print(f"✅ Sample training complete! Accuracy: {accuracy:.2f}")
        print(f"📊 Classes: {list(self.model.classes_)}  (0=legit, 1=phishing)")

        self.save_model()
        return accuracy

    # ============================================
    # PREDICTION - HYBRID
    # ============================================

    def predict(self, url):
        print(f"🔍 Predicting for URL: {url}")

        if not url or not url.strip():
            return {
                'is_phishing': False, 'confidence': 0, 'risk_score': 0,
                'probability': {'phishing': 0, 'legitimate': 0},
                'risky_features': ["❌ Empty URL provided"],
                'features': {}, 'url': url,
                'reputation': {'score': 0, 'is_trusted': False},
            }

        url = url.strip()

        if 'https://' in url.lower() and url.lower().startswith('http://'):
            url = 'https://' + url[7:]
            print(f"🔒 Fixed HTTPS: {url}")

        if not url.startswith(('http://', 'https://')):
            if '.' in url:
                url = 'http://' + url
            else:
                url = 'http://' + url + '.com'

        try:
            parsed = urlparse(url)
            domain = parsed.netloc.lower()

            if not domain:
                if parsed.path and '.' in parsed.path:
                    domain = parsed.path.split('/')[0].lower()
                    url = 'http://' + domain
                    parsed = urlparse(url)
                else:
                    domain = url.replace('http://', '').replace('https://', '').split('/')[0]
                    if not domain:
                        domain = 'unknown.com'
                    if '.' not in domain:
                        domain = domain + '.com'
                    url = 'http://' + domain

            if domain.startswith('ww.') or domain.startswith('w.'):
                suggestion = (
                    'http://www.' + domain[3:] if domain.startswith('ww.')
                    else 'http://www.' + domain[2:]
                )
                return {
                    'is_phishing': False, 'confidence': 0.5, 'risk_score': 30,
                    'probability': {'phishing': 0.3, 'legitimate': 0.7},
                    'risky_features': [f"⚠️ Malformed domain: Did you mean {suggestion}?"],
                    'features': {}, 'url': url,
                    'reputation': {'score': 30, 'is_trusted': False}
                }
        except Exception as e:
            print(f"⚠️ URL parsing error: {e}")
            domain = url.replace('http://', '').replace('https://', '').split('/')[0]
            if not domain:
                domain = 'unknown.com'
                url = 'http://' + domain

        print(f"🌐 Domain: {domain}")

        # ============================================
        # STEP 1: RULE-BASED DETECTION
        # ============================================
        rule_result = self._rule_based_detection(url)
        rule_risk = rule_result.get('risk_score', 0)
        rule_is_phishing = rule_result.get('is_phishing', False)

        print(f"📊 Rule-based: Risk={rule_risk}%, Phishing={rule_is_phishing}")

        if rule_is_phishing and rule_risk >= 60:
            print("🚨 Rule-based high-confidence phishing")
            return rule_result

        # ============================================
        # STEP 2: ML PREDICTION
        # ============================================
        if self.model is None:
            if not self.load_model():
                return rule_result

        features = self.extract_all_features(url)
        if not features:
            return rule_result

        try:
            feature_values = [features.get(name, 0) for name in self.feature_names]
            X = np.array([feature_values])
            X_scaled = self.scaler.transform(X)
            X_selected = self.feature_selector.transform(X_scaled)

            prob = self.model.predict_proba(X_selected)[0]

            # Since we trained with 1=phishing, class 1 index gives phishing prob
            classes = list(self.model.classes_)
            if 1 in classes:
                ml_phishing_prob = float(prob[classes.index(1)])
            else:
                ml_phishing_prob = 0.0

            print(f"📊 ML probability: {ml_phishing_prob:.2f}")

            # ============================================
            # STEP 3: COMBINE (rules dominate, ML is advisory)
            # ============================================
            rule_clean = rule_risk < 20

            if rule_clean:
                # Rules say clean → trust them, ML cannot flip verdict
                combined_phishing_prob = min(ml_phishing_prob * 0.3, 0.35)
                combined_is_phishing = False
            else:
                combined_phishing_prob = (ml_phishing_prob * 0.3) + (rule_risk / 100 * 0.7)
                combined_is_phishing = combined_phishing_prob > 0.55 or rule_risk >= 55

                # Only allow ML override if rules saw SOMETHING
                if ml_phishing_prob > 0.85 and rule_risk >= 15:
                    combined_is_phishing = True
                    combined_phishing_prob = max(combined_phishing_prob, 0.85)

            risky_features = self._get_risky_features(features)
            all_risky = list(set(rule_result.get('risky_features', []) + risky_features))

            print(f"📊 Combined: {combined_phishing_prob:.2f}, Phishing={combined_is_phishing}")

            return {
                'is_phishing': bool(combined_is_phishing),
                'confidence': combined_phishing_prob,
                'risk_score': int(combined_phishing_prob * 100),
                'probability': {
                    'phishing': combined_phishing_prob,
                    'legitimate': 1 - combined_phishing_prob,
                },
                'ml_probability': {
                    'phishing': ml_phishing_prob,
                    'legitimate': 1 - ml_phishing_prob,
                },
                'risky_features': all_risky[:10],
                'features': features,
                'typosquatting_score': features.get('_typosquatting_score', 0),
                'url': url,
                'reputation': rule_result.get('reputation', {}),
                'detection_method': 'hybrid (ML + Rules)',
            }
        except Exception as e:
            print(f"⚠️ ML prediction error: {e}")
            import traceback
            traceback.print_exc()

        return rule_result

    def _predict_rule_based(self, url):
        return self._rule_based_detection(url)

    def _get_risky_features(self, features):
        risky = []

        if features.get('has_ip_address', 0) == 1:
            risky.append("Uses IP address instead of domain name")
        if features.get('_suspicious_keyword_count', 0) > 0:
            risky.append(f"Contains {features['_suspicious_keyword_count']} suspicious keywords")
        if features.get('_is_shortened', 0) == 1:
            risky.append("URL shortened (hides destination)")
        if features.get('https_flag', 0) == 0:
            risky.append("No HTTPS (insecure connection)")
        if features.get('_has_at_symbol', 0) == 1:
            risky.append("Contains '@' symbol (hides real domain)")
        if features.get('_has_suspicious_tld', 0) == 1:
            risky.append("Suspicious TLD (.tk, .ml, .ga, .cf, .xyz, etc.)")
        if features.get('_typosquatting_score', 0) > 0:
            risky.append(f"Typosquatting score: {features['_typosquatting_score']}/10")
        if features.get('_has_double_slash', 0) == 1:
            risky.append("Double slash redirect technique")
        if features.get('url_length', 0) > 100:
            risky.append(f"Very long URL ({features['url_length']} chars)")
        if features.get('subdomain_count', 0) > 3:
            risky.append(f"Excessive subdomains ({features['subdomain_count']})")
        if features.get('has_hyphen_in_domain', 0) == 1:
            risky.append("Contains hyphens in domain (may mimic brand)")
        if features.get('percentage_numeric_chars', 0) > 20:
            risky.append(f"High numeric percentage ({features['percentage_numeric_chars']:.1f}%)")

        return risky

    def get_model_info(self):
        info = {
            'model_loaded': self.model is not None,
            'feature_count': len(self.feature_names),
            'model_exists': os.path.exists(self.model_path),
            'model_size_kb': os.path.getsize(self.model_path) / 1024 if os.path.exists(self.model_path) else 0,
            'features': self.feature_names,
            'trusted_domains_count': len(self.trusted_domains),
            'brands_count': len(self.brands),
            'reputation_cache_size': len(self.reputation_cache),
            'status': 'Active',
        }
        if self.model is not None:
            info['classes'] = [int(c) for c in self.model.classes_]

        if os.path.exists(self.metadata_path):
            with open(self.metadata_path, 'r') as f:
                info.update(json.load(f))

        return info