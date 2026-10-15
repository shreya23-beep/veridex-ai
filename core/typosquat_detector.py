"""
VeriDex AI - Core Typosquatting & Homoglyph Engine
Detects brand impersonation, character substitution, Punycode/IDN attacks,
and deceptive subdomain nesting entirely on-device with zero cloud calls.
"""

import re
import idna
from urllib.parse import urlparse

HIGH_VALUE_TARGETS = [
    "paypal", "google", "microsoft", "apple", "amazon", "netflix",
    "facebook", "instagram", "twitter", "chase", "bankofamerica",
    "wellsfargo", "citibank", "binance", "coinbase", "metamask",
    "ledger", "steam", "dhl", "fedex", "ups", "linkedin", "dropbox",
    "adobe", "whatsapp", "telegram", "spotify", "yahoo", "outlook",
    "icloud", "walmart", "target", "ebay", "aliexpress", "roblox",
    "discord", "github", "gitlab", "stripe", "usps", "irs"
]

HOMOGLYPH_MAP = {
    '0': 'o',
    '1': 'l',
    '!': 'i',
    '@': 'a',
    '3': 'e',
    '4': 'a',
    '5': 's',
    '8': 'b',
    '9': 'g',
    'vv': 'w',
    'rn': 'm',
    'cl': 'd',
}

SUSPICIOUS_KEYWORDS = [
    "login", "verify", "secure", "account", "update", "banking",
    "confirm", "wallet", "support", "billing", "auth", "signin",
    "security", "recovery", "password", "suspended", "unlock"
]

def levenshtein_distance(s1: str, s2: str) -> int:
    """Calculates minimal edit distance between two strings."""
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

def normalize_homoglyphs(text: str) -> str:
    """Replaces common leetspeak and visual substitutions with standard letters."""
    normalized = text.lower()
    for sub, repl in HOMOGLYPH_MAP.items():
        normalized = normalized.replace(sub, repl)
    return normalized

def extract_domain_parts(url: str):
    """Parses URL into scheme, full domain, registered domain, and subdomains."""
    if not url.startswith(("http://", "https://")):
        url = "http://" + url
    parsed = urlparse(url)
    hostname = parsed.hostname or parsed.netloc or ""
    
    # Handle Punycode (IDN homograph attack)
    is_punycode = hostname.startswith("xn--") or ".xn--" in hostname
    unicode_domain = hostname
    if is_punycode:
        try:
            unicode_domain = idna.decode(hostname)
        except Exception:
            pass

    parts = hostname.split('.')
    if len(parts) >= 2:
        tld = parts[-1]
        domain_name = parts[-2]
        subdomains = parts[:-2]
    else:
        tld = ""
        domain_name = hostname
        subdomains = []

    return {
        "hostname": hostname,
        "unicode_domain": unicode_domain,
        "is_punycode": is_punycode,
        "domain_name": domain_name,
        "tld": tld,
        "subdomains": subdomains,
        "path": parsed.path,
        "query": parsed.query
    }

def analyze_typosquatting(url: str) -> dict:
    """
    Performs on-device heuristics to detect if the URL impersonates a known brand.
    Returns details on spoofed brand, similarity, and risk severity.
    """
    parts = extract_domain_parts(url)
    domain = parts["domain_name"].lower()
    hostname = parts["hostname"].lower()
    subdomains = parts["subdomains"]
    normalized_domain = normalize_homoglyphs(domain)

    result = {
        "is_typosquat": False,
        "spoofed_brand": None,
        "reason": "Clean domain",
        "severity": "LOW",
        "confidence": 0.0,
        "is_punycode": parts["is_punycode"],
        "suspicious_subdomains": False
    }

    # 1. IDN / Punycode flag
    if parts["is_punycode"]:
        result["is_typosquat"] = True
        result["severity"] = "HIGH"
        result["reason"] = f"Punycode homograph attack detected ({parts['hostname']} -> {parts['unicode_domain']})"
        result["confidence"] = 0.95

    # 2. Check if a high-value brand is trapped in a subdomain
    # e.g. "paypal.com.attacker-controlled.xyz"
    for sub in subdomains:
        sub_norm = normalize_homoglyphs(sub)
        for brand in HIGH_VALUE_TARGETS:
            if brand == sub_norm or brand in sub_norm.split('-'):
                # legitimate domain check (e.g. login.paypal.com is fine, but paypal.com.evil.xyz is NOT)
                if brand != domain:
                    result["is_typosquat"] = True
                    result["spoofed_brand"] = brand
                    result["severity"] = "CRITICAL"
                    result["suspicious_subdomains"] = True
                    result["reason"] = f"Brand '{brand}' disguised inside subdomain while actual domain is '{domain}.{parts['tld']}'"
                    result["confidence"] = 0.99
                    return result

    # 3. Check for brand embedded or compound tokens (e.g. "paypa1-security-verification" or "secure-apple-login")
    domain_tokens = re.split(r"[-_]", domain)
    norm_tokens = re.split(r"[-_]", normalized_domain)

    for brand in HIGH_VALUE_TARGETS:
        # Check normalized full domain containment
        if (brand in domain or brand in normalized_domain) and domain != brand:
            for kw in SUSPICIOUS_KEYWORDS:
                if kw in domain or kw in hostname or kw in normalized_domain:
                    result["is_typosquat"] = True
                    result["spoofed_brand"] = brand
                    result["severity"] = "HIGH"
                    result["reason"] = f"Target brand '{brand}' paired with deceptive keywords in '{domain}'"
                    result["confidence"] = 0.94
                    return result

        # Check token-level typosquatting in compound domains
        for t_raw, t_norm in zip(domain_tokens, norm_tokens):
            if t_norm == brand and t_raw != brand:
                result["is_typosquat"] = True
                result["spoofed_brand"] = brand
                result["severity"] = "CRITICAL"
                result["reason"] = f"Homoglyph character substitution of '{brand}' in token '{t_raw}'"
                result["confidence"] = 0.98
                return result

            # Distance against token
            dist_token = min(levenshtein_distance(t_raw, brand), levenshtein_distance(t_norm, brand))
            if len(brand) >= 5 and dist_token == 1 and t_raw != brand:
                result["is_typosquat"] = True
                result["spoofed_brand"] = brand
                result["severity"] = "HIGH"
                result["reason"] = f"Typosquatting permutation of '{brand}' in domain token '{t_raw}'"
                result["confidence"] = 0.92
                return result

    # 4. Levenshtein edit distance & character substitution on whole domain
    # e.g. "paypa1", "pypal", "micros0ft", "g00gle"
    for brand in HIGH_VALUE_TARGETS:
        # Distance against raw domain
        dist_raw = levenshtein_distance(domain, brand)
        # Distance against normalized homoglyph domain
        dist_norm = levenshtein_distance(normalized_domain, brand)

        if dist_norm == 0 and domain != brand:
            result["is_typosquat"] = True
            result["spoofed_brand"] = brand
            result["severity"] = "CRITICAL"
            result["reason"] = f"Homoglyph character substitution of '{brand}' (detected '{domain}')"
            result["confidence"] = 0.98
            return result

        # Small edit distance for brands of length >= 5
        min_dist = min(dist_raw, dist_norm)
        if len(brand) >= 5 and min_dist == 1 and domain != brand:
            result["is_typosquat"] = True
            result["spoofed_brand"] = brand
            result["severity"] = "HIGH"
            result["reason"] = f"Typosquatting permutation of '{brand}' (distance=1, '{domain}')"
            result["confidence"] = 0.90
            return result
        elif len(brand) >= 7 and min_dist == 2 and domain != brand:
            result["is_typosquat"] = True
            result["spoofed_brand"] = brand
            result["severity"] = "MEDIUM"
            result["reason"] = f"Probable typosquatting permutation of '{brand}' (distance=2, '{domain}')"
            result["confidence"] = 0.75
            return result

    return result
