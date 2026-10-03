"""
Fast feature extraction for real-time phishing detection
Produces EXACTLY the 16 features from the training CSV
Optimized for speed (< 300ms response time)

UPDATED:
  - Aligned brand list & typos with detector.py
  - Added free-hosting platform detection
  - Expanded suspicious TLD list to match detector.py
  - Added is_free_host() helper
"""

import re
import math
from urllib.parse import urlparse
import tldextract


# ============================================
# EXACT 16 FEATURE NAMES FROM TRAINING CSV
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


# ✅ FIX: same list as detector.py — keep in sync!
FREE_HOSTING_PATTERNS = [
    'godaddysites.com', 'weeblysite.com', 'weebly.com', 'wixsite.com',
    'pages.dev', 'vercel.app', 'netlify.app', 'workers.dev',
    'firebaseapp.com', 'web.app', 'r2.dev', 'gitbook.io',
    'square.site', 'blogspot.com', 'webcindario.com', 'surge.sh',
    'replit.app', 'glitch.me', 'altervista.org', '000webhostapp.com',
    'infinityfreeapp.com', 'byethost', 'epizy.com', 'mybluehost.me',
    'myqcloud.com', 'cos.ap-', 'ipfs.dweb.link', 'fleek.co',
]


class FastFeatureExtractor:
    """
    Extracts 16 features that match the training CSV columns.
    Also provides rule-based helpers for phishing detection.
    """

    def __init__(self):
        self.suspicious_keywords = [
            'login', 'signin', 'secure', 'bank', 'account', 'verify', 'confirm',
            'authenticate', 'validate', 'billing', 'payment', 'credential',
            'password', 'update', 'alert', 'notice', 'suspended', 'unusual',
            'activity', 'security', 'support', 'helpdesk', 'customer',
            'recover', 'reset', 'unlock', 'authorize', 'validat', 'identity',
            'verification', 'authenticator', '2fa', 'two-factor'
        ]

        self.shortening_services = {
            'bit.ly', 'tinyurl', 'goo.gl', 'is.gd', 'buff.ly', 'ow.ly',
            't.co', 'lnkd.in', 'db.tt', 'qr.ae', 'cur.lv', 'shorte.st',
            'tiny.cc', 'shorturl.at', 'rb.gy', 'v.gd', 'cutt.ly', 'rebrand.ly',
            'tinyurl.com', 'bitly.com', 'short.link',
            # ✅ FIX: added common shorteners from your dataset
            'lihi.cc', 'urlz.fr',
        }

        # ✅ FIX: expanded to match detector.py
        self.suspicious_tlds = {
            '.tk', '.ml', '.ga', '.cf', '.xyz', '.top', '.club', '.work', '.win',
            '.bid', '.date', '.download', '.review', '.stream', '.trade', '.webcam',
            '.space', '.site', '.men', '.online', '.store', '.tech', '.live',
            '.fun', '.click', '.pro', '.cloud', '.host', '.press', '.rocks', '.gq',
            '.cc', '.icu', '.info', '.biz', '.name',
            # ✅ FIX: added
            '.app', '.dev', '.sh', '.me', '.sbs', '.my.id', '.homes',
            '.vip', '.shop', '.bond', '.be', '.best', '.life', '.cm',
        }

        # Popular TLDs - matches training CSV's tld_popularity logic
        self.popular_tlds = {'com', 'org', 'net', 'edu', 'gov', 'io', 'ai', 'co'}

        # ✅ FIX: aligned with detector.py's brands dict
        self.brands = {
            'google', 'youtube', 'facebook', 'amazon', 'microsoft', 'apple',
            'paypal', 'netflix', 'github', 'twitter', 'instagram', 'linkedin',
            'reddit', 'wikipedia', 'stackoverflow', 'zoom', 'slack', 'notion',
            'deepseek', 'openai', 'claude', 'perplexity', 'huggingface',
            'uphold', 'coinbase', 'binance', 'metamask', 'kraken',
            # ✅ FIX: added brands present in detector.py
            'kucoin', 'whatsapp', 'telegram', 'gemini', 'ledger', 'trezor',
            'robinhood', 'dana', 'att', 'orange',
        }

        # Common TLDs for domain cleaning
        self.common_tlds = [
            '.com', '.org', '.net', '.io', '.ai', '.co', '.uk', '.de',
            '.fr', '.ca', '.au', '.in', '.br',
            # ✅ FIX: added more
            '.site', '.app', '.dev', '.live', '.shop', '.vip', '.top', '.xyz',
        ]

    # ============================================
    # MAIN FEATURE EXTRACTION - EXACT CSV MATCH
    # ============================================

    def extract_features_fast(self, url):
        """
        Extract exactly the 16 features that match the training CSV.
        Also includes private helper features (prefixed with _).
        """
        if not url:
            return {}

        try:
            url = url.strip()

            if not url.startswith(('http://', 'https://')):
                if '.' in url:
                    url = 'http://' + url
                else:
                    url = 'http://' + url + '.com'

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

            if ext.suffix:
                tld_suffix = ext.suffix
            elif '.' in domain_clean:
                tld_suffix = domain_clean.split('.')[-1]
            else:
                tld_suffix = ''

            # ============================================
            # THE EXACT 16 FEATURES
            # ============================================
            features = {
                'url_length': len(url),
                'has_ip_address': 1 if re.match(r'^(\d{1,3}\.){3}\d{1,3}$', domain_clean) else 0,
                'dot_count': url.count('.'),
                'https_flag': 1 if parsed.scheme == 'https' else 0,
                'url_entropy': self._calculate_entropy(url),
                'token_count': len(url.split('/')),
                'subdomain_count': len(ext.subdomain.split('.')) if ext.subdomain else 0,
                'query_param_count': len(query.split('&')) if query else 0,
                'tld_length': len(tld_suffix),
                'path_length': len(parsed.path),
                'has_hyphen_in_domain': 1 if '-' in domain_clean else 0,
                'number_of_digits': sum(c.isdigit() for c in url),
                'tld_popularity': 1 if tld_suffix in self.popular_tlds else 0,
                'suspicious_file_extension': 1 if any(
                    path.endswith(e) for e in ['.exe', '.bat', '.cmd', '.js', '.jar', '.apk', '.scr', '.vbs']
                ) else 0,
                'domain_name_length': len(ext.domain) if ext.domain else len(domain_clean.split('.')[0]),
                'percentage_numeric_chars': (sum(c.isdigit() for c in url) / max(len(url), 1)) * 100,
            }

            # ============================================
            # EXTRA HELPERS (prefixed with _)
            # ============================================
            features['_domain'] = domain_clean
            features['_url'] = url
            features['_tld'] = tld_suffix
            features['_is_shortened'] = 1 if any(s in domain_clean for s in self.shortening_services) else 0
            features['_has_suspicious_tld'] = 1 if any(full_url.endswith(tld) for tld in self.suspicious_tlds) else 0
            features['_has_at_symbol'] = 1 if '@' in url else 0
            features['_suspicious_keyword_count'] = sum(1 for kw in self.suspicious_keywords if kw in full_url)
            features['_brand_count'] = sum(1 for brand in self.brands if brand in full_url)
            # ✅ FIX: new helper
            features['_is_free_host'] = 1 if any(h in domain_clean for h in FREE_HOSTING_PATTERNS) else 0

            return features

        except Exception as e:
            print(f"⚠️ Feature extraction error for URL '{url}': {e}")
            return {name: 0 for name in TRAINING_FEATURES}

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
            return -sum(
                (count / total) * math.log2(count / total)
                for count in freq.values() if count > 0
            )
        except:
            return 0

    # ============================================
    # CSV EXTRACTION - returns only the 16 features
    # ============================================

    def extract_features_for_csv(self, url):
        features = self.extract_features_fast(url)
        if not features:
            return None
        return {name: features.get(name, 0) for name in TRAINING_FEATURES}

    def get_feature_names(self):
        return TRAINING_FEATURES.copy()

    def batch_extract_features(self, urls):
        results = []
        for url in urls:
            features = self.extract_features_fast(url)
            if features:
                results.append(features)
        return results

    # ============================================
    # RULE-BASED HELPERS
    # ============================================

    def get_domain_from_url(self, url):
        if not url:
            return ''
        try:
            if not url.startswith(('http://', 'https://')):
                if '.' in url:
                    url = 'http://' + url
                else:
                    return url
            parsed = urlparse(url)
            domain = parsed.netloc.lower().replace('www.', '')
            if ':' in domain:
                domain = domain.split(':')[0]
            return domain
        except:
            return url

    def is_typosquatting(self, domain, brand_domains=None):
        """Check if domain is typosquatting a brand. Returns (bool, brand, score)."""
        if not domain:
            return False, None, 0

        domain = domain.lower().replace('www.', '')

        clean_domain = domain
        for tld in self.common_tlds:
            if clean_domain.endswith(tld):
                clean_domain = clean_domain[:-len(tld)]
                break

        for brand in self.brands:
            if brand in clean_domain and clean_domain != brand:
                if self._is_similar_string(clean_domain, brand):
                    return True, brand, 8
                if len(clean_domain) > len(brand) + 1:
                    return True, brand, 6

        return False, None, 0

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

    def is_free_host(self, url):
        """✅ FIX: check if URL is on a known free-hosting platform."""
        if not url:
            return False
        domain = self.get_domain_from_url(url).lower()
        return any(host in domain for host in FREE_HOSTING_PATTERNS)

    def is_suspicious_url(self, url):
        """Quick pre-filter check."""
        features = self.extract_features_fast(url)
        if not features:
            return False

        risk = 0
        if features.get('has_ip_address', 0) == 1:
            risk += 30
        if features.get('_has_suspicious_tld', 0) == 1:
            risk += 25
        if features.get('_is_shortened', 0) == 1:
            risk += 20
        if features.get('_has_at_symbol', 0) == 1:
            risk += 20
        if features.get('https_flag', 0) == 0:
            risk += 15
        if features.get('_suspicious_keyword_count', 0) >= 3:
            risk += 20
        elif features.get('_suspicious_keyword_count', 0) >= 1:
            risk += 10
        # ✅ FIX: free host boosts risk
        if features.get('_is_free_host', 0) == 1:
            risk += 20
        if features.get('_brand_count', 0) > 0 and features.get('_is_free_host', 0) == 1:
            risk += 25  # brand on free host = strong signal

        return risk > 35


# ============================================
# SELF-TEST
# ============================================
if __name__ == '__main__':
    extractor = FastFeatureExtractor()

    test_urls = [
        'https://www.google.com',
        'http://gogle.com',
        'https://upholdchlogin.godaddysites.com',
        'https://www.977theriver.com',
        'http://bit.ly/2XyZ123',
        'http://att-109120.weeblysite.com',
        'http://telegramwa.com',
        'https://metamsk01lgiix.godaddysites.com',
    ]

    print("=" * 70)
    print("FEATURE EXTRACTION TEST")
    print("=" * 70)

    for url in test_urls:
        features = extractor.extract_features_fast(url)
        print(f"\n🌐 URL: {url}")
        print(f"   url_length:                {features['url_length']}")
        print(f"   has_ip_address:            {features['has_ip_address']}")
        print(f"   dot_count:                 {features['dot_count']}")
        print(f"   https_flag:                {features['https_flag']}")
        print(f"   url_entropy:               {features['url_entropy']:.4f}")
        print(f"   token_count:               {features['token_count']}")
        print(f"   subdomain_count:           {features['subdomain_count']}")
        print(f"   query_param_count:         {features['query_param_count']}")
        print(f"   tld_length:                {features['tld_length']}")
        print(f"   path_length:               {features['path_length']}")
        print(f"   has_hyphen_in_domain:      {features['has_hyphen_in_domain']}")
        print(f"   number_of_digits:          {features['number_of_digits']}")
        print(f"   tld_popularity:            {features['tld_popularity']}")
        print(f"   suspicious_file_ext:       {features['suspicious_file_extension']}")
        print(f"   domain_name_length:        {features['domain_name_length']}")
        print(f"   percentage_numeric_chars:  {features['percentage_numeric_chars']:.4f}")
        print(f"   ─── helpers ───")
        print(f"   _is_free_host:             {features['_is_free_host']}")
        print(f"   _is_shortened:             {features['_is_shortened']}")
        print(f"   _has_suspicious_tld:       {features['_has_suspicious_tld']}")
        print(f"   _brand_count:              {features['_brand_count']}")
        print(f"   _suspicious_keyword_count: {features['_suspicious_keyword_count']}")

    print("\n" + "=" * 70)
    print(f"✅ Total features: {len(extractor.get_feature_names())}")
    print(f"📋 Feature names: {extractor.get_feature_names()}")
    print("=" * 70)