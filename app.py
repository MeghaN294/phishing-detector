from flask import Flask, render_template, request, jsonify, send_from_directory
from detector import PhishingDetector
import traceback
import os
import re
from urllib.parse import urlparse

# ============================================
# FLASK APP CONFIG
# ============================================

app = Flask(__name__,
            static_folder='static',
            static_url_path='/static',
            template_folder='templates')

detector = PhishingDetector()


# ============================================
# HELPER: detect IPv4 address (with optional port)
# ============================================

def _is_ipv4(host):
    """Return True if `host` (no port) is a valid IPv4 address."""
    if not re.match(r'^(\d{1,3}\.){3}\d{1,3}$', host):
        return False
    for part in host.split('.'):
        try:
            if int(part) > 255:
                return False
        except ValueError:
            return False
    return True


# ============================================
# URL VALIDATION - STRICT + HTTPS PRESERVATION
# ============================================

def validate_url(url):
    """
    Validates URL and preserves HTTPS if present.
    Allows underscores in domain labels (RFC 2181).
    Accepts IPv4 addresses (with optional non-standard port).
    Returns: (is_valid, error_message, corrected_url, url_type)
    """

    # ============================================
    # EMPTY / LENGTH CHECKS
    # ============================================
    if not url or len(url.strip()) == 0:
        return False, "URL cannot be empty", None, 'invalid'

    url = url.strip()

    if len(url) > 2048:
        return False, "URL is too long (max 2048 characters)", None, 'invalid'

    if ' ' in url:
        return False, "URL contains spaces", None, 'invalid'

    # ============================================
    # TRACK ORIGINAL PROTOCOL
    # ============================================
    original_had_https = url.lower().startswith('https://')

    # ============================================
    # RANDOM TEXT / INVALID PATTERN CHECKS
    # ============================================
    if re.match(r'^[a-zA-Z0-9]+$', url) and '.' not in url:
        return False, f"Invalid URL: '{url}' is not a valid domain or URL", None, 'invalid'

    if url.startswith('.') or url.startswith('..'):
        return False, "URL cannot start with dots", None, 'invalid'

    if re.match(r'^[^a-zA-Z0-9]+$', url):
        return False, "URL must contain letters or numbers", None, 'invalid'

    corrected_url = url

    # ============================================
    # FIX PROTOCOL TYPOS
    # ⚠️ IMPORTANT: Do NOT include ('http:/', 'http://')
    # or ('https:/', 'https://') here — they break
    # valid URLs by adding an extra slash!
    # ============================================
    protocol_fixes = [
        ('http//', 'http://'),
        ('https//', 'https://'),
        ('htp://', 'http://'),
        ('htps://', 'https://'),
        ('htts://', 'https://'),
        ('http:\\', 'http://'),
        ('https:\\', 'https://'),
    ]

    for typo, correct in protocol_fixes:
        if corrected_url.lower().startswith(typo):
            corrected_url = correct + corrected_url[len(typo):]
            if correct.startswith('https'):
                original_had_https = True
            break

    # ============================================
    # REMOVE DUPLICATE PROTOCOLS
    # ============================================
    for _ in range(5):
        if corrected_url.startswith('http://http://'):
            corrected_url = corrected_url.replace('http://http://', 'http://', 1)
        if corrected_url.startswith('http://https://'):
            corrected_url = corrected_url.replace('http://https://', 'https://', 1)
        if corrected_url.startswith('https://http://'):
            corrected_url = corrected_url.replace('https://http://', 'https://', 1)
        if corrected_url.startswith('https://https://'):
            corrected_url = corrected_url.replace('https://https://', 'https://', 1)

    # Collapse 3+ slashes after protocol
    corrected_url = re.sub(r'^(https?):/{3,}', r'\1://', corrected_url)

    if corrected_url.count('://') > 1:
        parts = corrected_url.split('://')
        corrected_url = parts[0] + '://' + parts[-1]

    # ============================================
    # CHECK PROTOCOL EXISTENCE
    # ============================================
    has_protocol = corrected_url.lower().startswith(('http://', 'https://'))

    if has_protocol:
        # ============================================
        # VALIDATE URL WITH PROTOCOL
        # ============================================
        try:
            parsed = urlparse(corrected_url)
            domain = parsed.netloc.lower()

            if '@' in domain:
                domain = domain.split('@')[-1]

            # ✅ FIX: strip port BEFORE any TLD/IP check
            host = domain
            port = None
            if ':' in host and not host.startswith('['):
                host, port = host.rsplit(':', 1)
                # validate port number
                if port and not port.isdigit():
                    return False, f"Invalid port: '{port}'", None, 'invalid'
                if port and not (1 <= int(port) <= 65535):
                    return False, f"Port out of range: '{port}'", None, 'invalid'

            if not host:
                return False, "URL has no domain", None, 'invalid'

            # ✅ FIX: IP address takes precedence over TLD check
            if _is_ipv4(host):
                return True, None, corrected_url, 'valid'

            if '.' not in host and host != 'localhost':
                return False, f"Invalid domain: '{host}' - missing extension (.com, .org, etc.)", None, 'invalid'

            if re.match(r'^[0-9.]+$', host):
                return False, f"Invalid IP address: '{host}'", None, 'invalid'

            # TLD validation (only for non-IP domains)
            if '.' in host:
                tld = host.split('.')[-1]
                if not tld or len(tld) < 2:
                    return False, f"Invalid TLD: '{tld}'", None, 'invalid'
                if not re.match(r'^[a-zA-Z]+$', tld):
                    return False, f"Invalid TLD: '{tld}' must contain letters only", None, 'invalid'

            # Validate each domain label (allow underscores per RFC 2181)
            for label in host.split('.'):
                if label and not re.match(r'^[a-zA-Z0-9_\-]+$', label):
                    return False, f"Invalid character in domain: '{label}'", None, 'invalid'

            return True, None, corrected_url, 'valid'

        except Exception as e:
            return False, f"Invalid URL format: {str(e)}", None, 'invalid'

    else:
        # ============================================
        # VALIDATE URL WITHOUT PROTOCOL
        # ============================================
        if '.' not in corrected_url:
            return False, f"Invalid URL: '{corrected_url}' is not a valid domain (missing extension)", None, 'invalid'

        if not re.search(r'[a-zA-Z0-9]', corrected_url):
            return False, f"Invalid URL: '{corrected_url}' must contain letters or numbers", None, 'invalid'

        domain_part = corrected_url.split('/')[0].split('?')[0]

        if '@' in domain_part:
            domain_part = domain_part.split('@')[-1]

        # ✅ FIX: strip port BEFORE IP / TLD check
        host = domain_part
        port = None
        if ':' in host and not host.startswith('['):
            host, port = host.rsplit(':', 1)
            if port and not port.isdigit():
                return False, f"Invalid port: '{port}'", None, 'invalid'
            if port and not (1 <= int(port) <= 65535):
                return False, f"Port out of range: '{port}'", None, 'invalid'

        if not host:
            return False, f"Invalid domain: '{host}'", None, 'invalid'

        # ✅ FIX: allow IPv4 addresses without TLD
        if _is_ipv4(host):
            if original_had_https:
                corrected_url = 'https://' + corrected_url
            else:
                corrected_url = 'http://' + corrected_url
            return True, None, corrected_url, 'valid'

        if '.' not in host:
            return False, f"Invalid domain: '{host}'", None, 'invalid'

        tld = host.split('.')[-1]
        if len(tld) < 2:
            return False, f"Invalid TLD: '{tld}' - must be at least 2 characters", None, 'invalid'

        if not re.match(r'^[a-zA-Z]+$', tld):
            return False, f"Invalid TLD: '{tld}' must contain letters only", None, 'invalid'

        # Allow underscores in domain labels
        for label in host.split('.'):
            if not label:
                return False, "Domain contains empty label (double dot)", None, 'invalid'
            if not re.match(r'^[a-zA-Z0-9_\-]+$', label):
                return False, f"Invalid character in domain: '{label}'", None, 'invalid'
            if label.startswith('-') or label.endswith('-'):
                return False, f"Domain label cannot start/end with hyphen: '{label}'", None, 'invalid'

        # Preserve HTTPS or default to HTTP
        if original_had_https:
            corrected_url = 'https://' + corrected_url
        else:
            corrected_url = 'http://' + corrected_url

        return True, None, corrected_url, 'valid'


# ============================================
# STATIC FILE ROUTE
# ============================================

@app.route('/static/<path:filename>')
def serve_static(filename):
    response = send_from_directory('static', filename)
    response.headers['Cache-Control'] = 'no-store, no-cache, must-revalidate, max-age=0'
    return response


# ============================================
# TRAINING
# ============================================

print("🔍 Checking for existing model...")
if not detector.load_model():
    print("📚 No model found. Training...")
    if os.path.exists('data/legitphish.csv'):
        accuracy = detector.train_from_csv('data/legitphish.csv')
        print(f"✅ Model trained with accuracy: {accuracy:.2%}")
    else:
        accuracy = detector.train_with_sample_data()
        print(f"✅ Sample model trained with accuracy: {accuracy:.2%}")
else:
    print("✅ Model loaded successfully")


# ============================================
# ROUTES
# ============================================

@app.route('/')
def index():
    return render_template('index.html')


@app.route('/predict', methods=['POST'])
def predict():
    try:
        data = request.get_json()
        if not data:
            return jsonify({
                'error': 'No JSON data received',
                'is_phishing': False,
                'is_invalid': True,
                'status': 'error'
            }), 400

        original_url = data.get('url', '').strip()
        print(f"🔍 Received URL: {original_url}")

        if not original_url:
            return jsonify({
                'is_phishing': False,
                'is_invalid': True,
                'status': 'error',
                'error': 'URL is empty',
                'explanation': "❌ Please enter a URL to check"
            }), 400

        # ============================================
        # VALIDATE URL
        # ============================================
        is_valid, error_msg, corrected_url, url_type = validate_url(original_url)

        if not is_valid:
            print(f"❌ Invalid URL: {error_msg}")
            return jsonify({
                'is_phishing': False,
                'is_invalid': True,
                'status': 'invalid',
                'error': error_msg,
                'url': original_url,
                'corrected_url': None,
                'risk_score': 0,
                'confidence': 0,
                'probability': {'phishing': 0, 'legitimate': 0},
                'risky_features': [f"❌ {error_msg}"],
                'features': {},
                'reputation': {'score': 0, 'is_trusted': False},
                'explanation': (
                    f"❌ INVALID URL\n\n{error_msg}\n\n"
                    "Please enter a valid URL like:\nhttps://www.example.com"
                )
            }), 200

        url_to_check = corrected_url
        print(f"🌐 Checking URL: {url_to_check}")

        # ============================================
        # PREDICT
        # ============================================
        result = detector.predict(url_to_check)

        if not isinstance(result, dict):
            result = {
                'is_phishing': False,
                'is_invalid': False,
                'confidence': 0,
                'risk_score': 0,
                'probability': {'phishing': 0, 'legitimate': 0},
                'risky_features': [],
                'features': {},
                'reputation': {'score': 0, 'is_trusted': False}
            }

        result.setdefault('is_phishing', False)
        result.setdefault('is_invalid', False)
        result.setdefault('confidence', 0)
        result.setdefault('risk_score', 0)
        result.setdefault('probability', {'phishing': 0, 'legitimate': 0})
        result.setdefault('risky_features', [])
        result.setdefault('features', {})
        result.setdefault('reputation', {'score': 0, 'is_trusted': False})
        result.setdefault('url', url_to_check)

        result['original_url'] = original_url
        result['status'] = 'valid'
        result['is_invalid'] = False
        result['explanation'] = generate_explanation(result)

        print(
            f"📊 Result: "
            f"{'PHISHING' if result.get('is_phishing', False) else 'SAFE'} "
            f"(Risk: {result.get('risk_score', 0)}%)"
        )

        return jsonify(result)

    except Exception as e:
        print("❌ Error in predict route:")
        print(traceback.format_exc())
        return jsonify({
            'error': str(e),
            'is_phishing': False,
            'is_invalid': True,
            'status': 'error',
            'explanation': f"❌ Server Error\n\n{str(e)}"
        }), 500


@app.route('/stats', methods=['GET'])
def stats():
    try:
        return jsonify(detector.get_model_info())
    except Exception as e:
        return jsonify({'error': str(e)}), 500


@app.route('/test', methods=['GET'])
def test():
    return jsonify({
        'status': 'ok',
        'message': 'PhishGuard API is running',
        'model_loaded': detector.model is not None
    })


# ============================================
# EXPLANATION GENERATION
# ============================================

def generate_explanation(result):
    lines = []

    is_phishing = result.get('is_phishing', False)
    is_invalid = result.get('is_invalid', False)
    risk_score = result.get('risk_score', 0)
    confidence = result.get('confidence', 0)

    if is_invalid:
        lines.append("❌ INVALID URL")
        lines.append("=" * 40)
        lines.append("")
        lines.append("This is not a valid URL. Common reasons:")
        lines.append("  • Missing domain extension (e.g., .com)")
        lines.append("  • Contains spaces")
        lines.append("  • Invalid characters")
        lines.append("  • Random text, not a web address")
        lines.append("")
        lines.append("Please enter a valid URL like:")
        lines.append("  • https://www.google.com")
        lines.append("  • https://example.com")
        return "\n".join(lines)

    if is_phishing:
        lines.append("🔴 PHISHING URL DETECTED!")
        lines.append("=" * 40)
        lines.append("")
        lines.append("🚨 Risk Factors Found:")
        risky_features = result.get('risky_features', [])
        if risky_features:
            for feature in risky_features[:8]:
                lines.append(f"  ⚠️ {feature}")
        else:
            lines.append("  ⚠️ Multiple suspicious patterns detected")

        lines.append("")
        lines.append("⚠️ DO NOT enter any personal information!")
        lines.append("⚠️ DO NOT click on any links on this page!")
        lines.append("⚠️ DO NOT download anything from this page!")
    else:
        lines.append("🟢 SAFE URL")
        lines.append("=" * 40)
        lines.append("")
        lines.append("✅ No major risk factors detected.")
        risky_features = result.get('risky_features', [])
        if risky_features:
            lines.append("")
            lines.append("ℹ️ Minor Observations:")
            for feature in risky_features[:3]:
                lines.append(f"  • {feature}")

    lines.append("")
    lines.append("📊 Analysis Results:")
    lines.append(f"  • Risk Score: {risk_score}%")
    lines.append(f"  • Confidence: {confidence*100:.1f}%")

    probability = result.get('probability', {})
    if probability:
        lines.append(f"  • Phishing Probability: {probability.get('phishing', 0)*100:.1f}%")
        lines.append(f"  • Legitimate Probability: {probability.get('legitimate', 0)*100:.1f}%")

    reputation = result.get('reputation', {})
    if reputation:
        lines.append(f"  • Domain Reputation: {reputation.get('score', 0)}/100")
        if reputation.get('is_trusted', False):
            lines.append("  • ✅ Domain is trusted")
        else:
            lines.append("  • ⚠️ Domain not in trust list")

    return "\n".join(lines)


# ============================================
# MAIN
# ============================================

if __name__ == '__main__':
    port = int(os.environ.get('PORT', 5000))
    print(f"🚀 Starting PhishGuard Pro on port {port}")
    print(f"🌐 Open http://localhost:{port} in your browser")
    print(f"📁 Static: {app.static_folder}")
    print(f"📁 Templates: {app.template_folder}")
    app.run(host='0.0.0.0', port=port, debug=True)