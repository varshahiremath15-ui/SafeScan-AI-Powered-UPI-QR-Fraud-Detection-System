"""
Feature Extraction Module for SafeScan
Extracts structural, lexical, behavioral, and domain-specific security features
from UPI URIs, payment links, and web URLs.
"""

import re
from urllib.parse import urlparse, parse_qs, unquote

# Well-known legitimate UPI bank handles issued by NPCI in India
LEGITIMATE_UPI_HANDLES = {
    'okhdfcbank', 'okaxis', 'oksbi', 'okicici', 'paytm', 'ybl', 'ibl',
    'axl', 'barodampay', 'upi', 'apl', 'ptaxis', 'ptyes', 'ptsbi',
    'pthdfc', 'icici', 'sbi', 'federal', 'aubank', 'pnb', 'kotak',
    'indus', 'citi', 'idbi', 'hsbc', 'postbank', 'rbl', 'yesbank',
    'cnrb', 'unionbank', 'allbank', 'syndicate', 'vijayabank'
}

# Suspicious keywords commonly found in fraudulent UPI/payment lures
SUSPICIOUS_KEYWORDS = [
    'refund', 'cashback', 'reward', 'prize', 'lottery', 'kyc', 'urgent',
    'blocked', 'verify', 'claim', 'bonus', 'free', 'winner', 'gift',
    'support-helpdesk', 'apk', 'update-account', 'telegram', 'airdrop',
    'helpline', 'customer-care', 'bill-overdue', 'lottery-winner', 'lucky-draw',
    'pan-update', 'aadhaar-link', 'electricity-bill', 'offer-valid', 'scratch-card'
]

# Common URL shortening services frequently used in phishing attacks
KNOWN_SHORTENERS = [
    'bit.ly', 'tinyurl.com', 'is.gd', 't.co', 'cutt.ly', 'rb.gy',
    'shorturl.at', 'rotf.lol', 'v.gd', 'ow.ly', 'buff.ly', 'adf.ly'
]

FEATURE_COLUMNS = [
    'url_length',
    'num_dots',
    'num_hyphens',
    'num_special_chars',
    'has_at_symbol',
    'is_ip_address',
    'is_https',
    'num_parameters',
    'suspicious_keyword_count',
    'is_upi_scheme',
    'has_valid_vpa_format',
    'vpa_length',
    'has_amount_param',
    'amount_value',
    'has_unusual_characters',
    'num_subdomains',
    'is_shortened_url',
    'has_payee_name',
    'is_high_risk_keyword_present'
]

def extract_features(raw_input: str) -> dict:
    """
    Extract comprehensive numerical and boolean features for ML model,
    as well as structural payment details and human-readable risk indicators.
    """
    cleaned_input = (raw_input or '').strip()
    unquoted = unquote(cleaned_input)

    # 1. Basic lexical lengths & counts
    url_length = len(cleaned_input)
    num_dots = cleaned_input.count('.')
    num_hyphens = cleaned_input.count('-')
    
    # Special characters outside standard alphanumeric, dot, hyphen, slash, colon, question, ampersand, equals, underscore
    special_char_pattern = re.compile(r'[^a-zA-Z0-9.\-/:?&=_@%]')
    num_special_chars = len(special_char_pattern.findall(cleaned_input))
    
    # 2. Key symbols
    has_at_symbol = 1 if '@' in cleaned_input else 0

    # 3. IP address detection
    ip_pattern = re.compile(r'(?:https?://)?(?:\d{1,3}\.){3}\d{1,3}(?::\d+)?')
    is_ip_address = 1 if ip_pattern.search(cleaned_input) else 0

    # 4. Protocol & Scheme
    is_https = 1 if cleaned_input.lower().startswith('https://') else 0
    is_http = 1 if cleaned_input.lower().startswith('http://') else 0
    is_upi_scheme = 1 if cleaned_input.lower().startswith('upi://') or 'upi://pay' in cleaned_input.lower() else 0

    # 5. Parsing parameters
    num_parameters = 0
    parsed_vpa = ''
    payee_name = ''
    amount_val = 0.0
    has_amount_param = 0
    has_payee_name = 0

    # Try parsing as URL or UPI query string
    try:
        if '?' in cleaned_input:
            query_part = cleaned_input.split('?', 1)[1]
            params = parse_qs(query_part)
            num_parameters = len(params)
            
            # Extract UPI specific standard params
            # pa: payee address / VPA
            if 'pa' in params:
                parsed_vpa = params['pa'][0].strip()
            # pn: payee name
            if 'pn' in params:
                payee_name = params['pn'][0].strip()
                has_payee_name = 1
            # am: transaction amount
            if 'am' in params:
                has_amount_param = 1
                try:
                    amount_val = float(params['am'][0].strip())
                except ValueError:
                    amount_val = 0.0
        elif '@' in cleaned_input and not cleaned_input.startswith(('http://', 'https://')):
            # Direct VPA entered, e.g., merchant@okaxis
            parsed_vpa = cleaned_input
    except Exception:
        num_parameters = 0

    # 6. VPA structure validation
    has_valid_vpa_format = 0
    vpa_length = len(parsed_vpa)
    vpa_handle = ''
    if parsed_vpa and '@' in parsed_vpa:
        parts = parsed_vpa.split('@')
        if len(parts) == 2:
            vpa_user, vpa_handle = parts[0].strip(), parts[1].lower().strip()
            # Legitimate handles from NPCI or general alphabetic handle
            if len(vpa_user) >= 2 and vpa_handle in LEGITIMATE_UPI_HANDLES:
                has_valid_vpa_format = 1
            elif len(vpa_user) >= 2 and re.match(r'^[a-zA-Z]{3,15}$', vpa_handle):
                has_valid_vpa_format = 1

    # 7. Suspicious keywords check
    lower_input = cleaned_input.lower()
    keyword_matches = [kw for kw in SUSPICIOUS_KEYWORDS if kw in lower_input]
    suspicious_keyword_count = len(keyword_matches)
    is_high_risk_keyword_present = 1 if suspicious_keyword_count > 0 else 0

    # 8. Unusual characters / excessive encoding / hidden script tags
    unusual_chars_found = re.findall(r'(%[0-9a-fA-F]{2}|[<>{}\[\]\\^`~])', cleaned_input)
    has_unusual_characters = 1 if len(unusual_chars_found) > 2 else 0

    # 9. Domain and subdomain analysis
    num_subdomains = 0
    is_shortened_url = 0
    try:
        parsed_url = urlparse(cleaned_input)
        netloc = parsed_url.netloc.lower()
        if netloc:
            # check shorteners
            for shortener in KNOWN_SHORTENERS:
                if shortener in netloc:
                    is_shortened_url = 1
                    break
            # count dots in hostname
            host_parts = netloc.split('.')
            if len(host_parts) > 2:
                num_subdomains = len(host_parts) - 2
    except Exception:
        pass

    # Feature vector dictionary for ML model
    features_dict = {
        'url_length': url_length,
        'num_dots': num_dots,
        'num_hyphens': num_hyphens,
        'num_special_chars': num_special_chars,
        'has_at_symbol': has_at_symbol,
        'is_ip_address': is_ip_address,
        'is_https': is_https,
        'num_parameters': num_parameters,
        'suspicious_keyword_count': suspicious_keyword_count,
        'is_upi_scheme': is_upi_scheme,
        'has_valid_vpa_format': has_valid_vpa_format,
        'vpa_length': vpa_length,
        'has_amount_param': has_amount_param,
        'amount_value': amount_val,
        'has_unusual_characters': has_unusual_characters,
        'num_subdomains': num_subdomains,
        'is_shortened_url': is_shortened_url,
        'has_payee_name': has_payee_name,
        'is_high_risk_keyword_present': is_high_risk_keyword_present
    }

    # Generate human-readable reasons and explanations based on detected features
    reasons = []
    if is_ip_address:
        reasons.append("Raw IP address used instead of legitimate verified domain name.")
    if is_http:
        reasons.append("Insecure plain HTTP connection detected (lacks SSL/TLS encryption).")
    if is_shortened_url:
        reasons.append("URL shortener used to conceal the genuine destination payment endpoint.")
    if keyword_matches:
        reasons.append(f"Deceptive lures/keywords detected: {', '.join(keyword_matches[:3])}.")
    if has_unusual_characters:
        reasons.append("Obfuscated or excessive encoded special characters found in payment string.")
    if is_upi_scheme and not has_valid_vpa_format and parsed_vpa:
        reasons.append(f"Unverified or unrecognized UPI handle '{parsed_vpa}' (not from a verified banking PSP).")
    if has_amount_param and amount_val >= 2000.0:
        reasons.append(f"Fixed pre-filled debit amount of ₹{amount_val:,.2f} embedded into payment request.")
    if num_subdomains >= 3:
        reasons.append("Abnormal number of nested subdomains indicating possible phishing redirect chain.")
    if url_length > 150:
        reasons.append("Abnormally long payment URL containing extraneous tracking or redirect tokens.")

    # Contextual recommendation based on findings
    if is_ip_address or (keyword_matches and is_shortened_url) or (is_http and keyword_matches):
        recommendation = "DO NOT PAY. This payment link exhibits multiple high-confidence fraudulent patterns and is likely designed to steal funds or credentials."
    elif len(reasons) >= 2 or keyword_matches:
        recommendation = "Caution advised: Verify the recipient's phone number and genuine identity directly before authorizing any transaction in your UPI app."
    else:
        recommendation = "Verified structure: The payment link conforms to standard UPI and secure URL standards. Proceed normally while verifying the recipient name on your payment screen."

    return {
        'features': features_dict,
        'feature_vector': [features_dict[col] for col in FEATURE_COLUMNS],
        'parsed_vpa': parsed_vpa,
        'payee_name': payee_name,
        'amount': amount_val,
        'reasons': reasons,
        'recommendation': recommendation,
        'raw_input': cleaned_input,
        'matched_keywords': keyword_matches
    }
