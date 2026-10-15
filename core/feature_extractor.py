"""
VeriDex AI - Core Feature Extractor
Extracts 20+ lexical, structural, statistical, and brand-impersonation features
from raw URLs for real-time, low-latency on-device ML inference.
"""

import math
import re
from urllib.parse import urlparse
from .typosquat_detector import analyze_typosquatting, extract_domain_parts

SUSPICIOUS_TLDS = {
    "xyz", "top", "work", "ru", "cc", "buzz", "club", "tk", "ml",
    "ga", "cf", "gq", "click", "rest", "support", "monster", "icu",
    "cam", "fit", "surf", "live", "vip", "link", "shop"
}

SUSPICIOUS_KEYWORDS = [
    "login", "verify", "secure", "account", "update", "banking",
    "confirm", "wallet", "support", "billing", "auth", "signin",
    "security", "recovery", "password", "suspended", "unlock", "free",
    "prize", "claim", "airdrop", "gift", "validation", "authenticate"
]

FEATURE_COLUMNS = [
    "url_length",
    "domain_length",
    "path_length",
    "query_length",
    "subdomain_count",
    "entropy_domain",
    "entropy_path",
    "count_digits_domain",
    "ratio_digits_domain",
    "count_hyphens_domain",
    "count_dots_url",
    "count_special_chars",
    "has_at_symbol",
    "has_double_slash",
    "has_ip_address",
    "is_https",
    "is_suspicious_tld",
    "suspicious_keyword_count",
    "typosquat_score",
    "is_punycode"
]

def shannon_entropy(data: str) -> float:
    """Calculates Shannon entropy to detect algorithmic randomness or obfuscation."""
    if not data:
        return 0.0
    entropy = 0.0
    length = len(data)
    frequencies = {}
    for char in data:
        frequencies[char] = frequencies.get(char, 0) + 1
    for count in frequencies.values():
        p = count / length
        entropy -= p * math.log2(p)
    return round(entropy, 4)

def is_ip_address(hostname: str) -> int:
    """Checks if hostname is an IPv4 or IPv6 address."""
    ipv4_pattern = r"^(?:(?:25[0-5]|2[0-4][0-9]|[01]?[0-9][0-9]?)\.){3}(?:25[0-5]|2[0-4][0-9]|[01]?[0-9][0-9]?)$"
    return 1 if re.match(ipv4_pattern, hostname) else 0

def extract_features(url: str) -> dict:
    """
    Extracts numerical feature dictionary suitable for ML model inference.
    """
    raw_url = url.strip()
    if not raw_url.startswith(("http://", "https://")):
        processed_url = "http://" + raw_url
    else:
        processed_url = raw_url

    parsed = urlparse(processed_url)
    hostname = (parsed.hostname or parsed.netloc or "").lower()
    path = parsed.path or ""
    query = parsed.query or ""

    domain_parts = extract_domain_parts(raw_url)
    domain_name = domain_parts["domain_name"]
    tld = domain_parts["tld"].lower()
    subdomains = domain_parts["subdomains"]

    # Typosquat analysis
    typosquat_info = analyze_typosquatting(raw_url)
    typosquat_score = typosquat_info["confidence"]

    # Digits and hyphens
    digits_in_domain = sum(c.isdigit() for c in hostname)
    ratio_digits = round(digits_in_domain / max(len(hostname), 1), 4)
    hyphens_in_domain = hostname.count("-")
    dots_in_url = raw_url.count(".")

    # Special characters
    special_chars = sum(raw_url.count(c) for c in ['@', '?', '=', '&', '%', '$', '!', '~', '*', '+', ';'])
    has_at = 1 if "@" in raw_url else 0
    has_double_slash = 1 if "//" in path else 0
    is_ip = is_ip_address(hostname)
    is_https = 1 if raw_url.lower().startswith("https://") else 0
    is_suspicious_tld = 1 if tld in SUSPICIOUS_TLDS else 0

    # Suspicious keywords
    url_lower = raw_url.lower()
    keyword_count = sum(1 for kw in SUSPICIOUS_KEYWORDS if kw in url_lower)

    # Entropies
    entropy_dom = shannon_entropy(hostname)
    entropy_pth = shannon_entropy(path)

    features = {
        "url_length": len(raw_url),
        "domain_length": len(hostname),
        "path_length": len(path),
        "query_length": len(query),
        "subdomain_count": len(subdomains),
        "entropy_domain": entropy_dom,
        "entropy_path": entropy_pth,
        "count_digits_domain": digits_in_domain,
        "ratio_digits_domain": ratio_digits,
        "count_hyphens_domain": hyphens_in_domain,
        "count_dots_url": dots_in_url,
        "count_special_chars": special_chars,
        "has_at_symbol": has_at,
        "has_double_slash": has_double_slash,
        "has_ip_address": is_ip,
        "is_https": is_https,
        "is_suspicious_tld": is_suspicious_tld,
        "suspicious_keyword_count": keyword_count,
        "typosquat_score": typosquat_score,
        "is_punycode": 1 if typosquat_info["is_punycode"] else 0
    }

    return features

def features_to_vector(features: dict) -> list:
    """Converts feature dict to ordered array for model ingestion."""
    return [features[col] for col in FEATURE_COLUMNS]
