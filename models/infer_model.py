
import os
import sys
import re
import joblib
import numpy as np
from difflib import SequenceMatcher

# --------------------------------------------------
# 1. Project path
# --------------------------------------------------
PROJECT_ROOT = os.path.dirname(
    os.path.dirname(os.path.abspath(__file__))
)
sys.path.insert(0, PROJECT_ROOT)

from core.feature_extractor import (
    extract_features,
    features_to_vector,
    FEATURE_COLUMNS
)

# --------------------------------------------------
# 2. Load trained model
# --------------------------------------------------
MODEL_PATH = os.path.join(
    os.path.dirname(os.path.abspath(__file__)),
    "veridex_model.joblib"
)

if not os.path.isfile(MODEL_PATH):
    raise FileNotFoundError(f"Model not found: {MODEL_PATH}")

model = joblib.load(MODEL_PATH)

print("VeriDex AI model loaded successfully!")
print(f"Expected features: {model.n_features_in_}")

# --------------------------------------------------
# 3. Brand impersonation detection
# Add more brands as required by your project.
# --------------------------------------------------
BRANDS = {
    "amazon": ["amazon.com", "amazon.in"],
    "google": ["google.com"],
    "microsoft": ["microsoft.com"],
    "apple": ["apple.com"],
    "paypal": ["paypal.com"],
    "facebook": ["facebook.com"],
    "instagram": ["instagram.com"],
    "netflix": ["netflix.com"],
    "whatsapp": ["whatsapp.com"],
    "flipkart": ["flipkart.com"],
    "github": ["github.com"],
    "linkedin": ["linkedin.com"],
    "outlook": ["outlook.com"],
    "sbi": ["sbi.co.in"],
}

# Common Unicode lookalikes used in deceptive domains
CONFUSABLES = str.maketrans({
    "а": "a", "ɑ": "a",
    "е": "e", "ё": "e",
    "і": "i", "ı": "i", "ӏ": "l",
    "о": "o", "ο": "o",
    "р": "p", "ρ": "p",
    "с": "c", "ϲ": "c",
    "х": "x", "χ": "x",
    "у": "y", "ј": "j",
    "ѕ": "s", "ԁ": "d",
})


def normalize_domain(host):
    """Normalize Unicode and common deceptive characters."""
    host = host.lower().strip(".")
    host = host.translate(CONFUSABLES)

    try:
        # Convert internationalized domain labels to ASCII
        host = host.encode("idna").decode("ascii")
    except UnicodeError:
        pass

    return host


def get_host(url):
    """Extract hostname safely from a URL."""
    from urllib.parse import urlsplit

    candidate = url.strip()

    if not re.match(r"^[a-zA-Z][a-zA-Z0-9+.-]*://", candidate):
        candidate = "//" + candidate

    try:
        return urlsplit(candidate).hostname
    except ValueError:
        return None


def check_brand_impersonation(url):
    """
    Return a warning if a hostname resembles a protected brand
    but is not one of its explicitly listed domains.
    """
    host = get_host(url)

    if not host:
        return "INVALID", "Could not parse the URL hostname."

    original_host = host.lower().rstrip(".")
    normalized_host = normalize_domain(original_host)

    # IP addresses should be handled by other security checks.
    if re.fullmatch(r"\d{1,3}(?:\.\d{1,3}){3}", normalized_host):
        return None, None

    labels = normalized_host.split(".")

    # Compare each domain label, not just the full hostname.
    # This can catch login-amazon.example or amazin.com.
    for brand, official_domains in BRANDS.items():

        # Exact official domains and their subdomains are exempt
        # from this particular brand-similarity check.
        normalized_official = [
            normalize_domain(domain) for domain in official_domains
        ]

        if any(
            normalized_host == domain
            or normalized_host.endswith("." + domain)
            for domain in normalized_official
        ):
            continue

        for label in labels:
            # Ignore tiny labels and exact brand names
            if len(label) < 4 or label == brand:
                continue

            similarity = SequenceMatcher(
                None, label, brand
            ).ratio()

            # Strong spelling similarity or a one/two-character edit
            if (
                similarity >= 0.78
                or (
                    abs(len(label) - len(brand)) <= 2
                    and similarity >= 0.70
                )
            ):
                return (
                    "SUSPICIOUS",
                    f"Hostname resembles the brand '{brand}'. "
                    f"Actual hostname: {original_host}"
                )

    # Detect Unicode hostnames for additional review.
    try:
        original_host.encode("ascii")
    except UnicodeEncodeError:
        return (
            "REVIEW",
            f"Unicode hostname detected: {original_host}"
        )

    return None, None


# --------------------------------------------------
# 4. URL inference
# --------------------------------------------------
def predict_url(url):
    url = url.strip()

    if not url:
        raise ValueError("Enter a URL.")

    # Check the domain before trusting the ML prediction
    warning, reason = check_brand_impersonation(url)

    if warning == "INVALID":
        result = "INVALID URL"
        scam_probability = None

    elif warning == "SUSPICIOUS":
        result = "POTENTIAL PHISHING / BRAND IMPERSONATION"
        scam_probability = None

    else:
        # Extract the same 26 features used for training
        features = extract_features(url)
        vector = features_to_vector(features)

        X = np.asarray(
            vector, dtype=np.float32
        ).reshape(1, -1)

        if X.shape[1] != model.n_features_in_:
            raise ValueError(
                f"Expected {model.n_features_in_} features, "
                f"received {X.shape[1]}."
            )

        prediction = int(model.predict(X)[0])
        probabilities = model.predict_proba(X)[0]
        classes = list(model.classes_)

        scam_probability = (
            float(probabilities[classes.index(1)]) * 100
            if 1 in classes else 0.0
        )

        if prediction == 1:
            result = "POTENTIAL SCAM / PHISHING"
        elif warning == "REVIEW":
            result = "SUSPICIOUS - MANUAL REVIEW REQUIRED"
        else:
            result = "MODEL PREDICTS BENIGN - NOT VERIFIED SAFE"

    print("\n" + "=" * 52)
    print("               VERIDEX AI")
    print("=" * 52)
    print("URL:", url)
    print("Result:", result)

    if scam_probability is not None:
        print(f"Model scam probability: {scam_probability:.2f}%")

    if reason:
        print("Reason:", reason)

    print("=" * 52)

    return {
        "url": url,
        "result": result,
        "scam_probability": (
            round(scam_probability, 2)
            if scam_probability is not None else None
        ),
        "reason": reason
    }


# --------------------------------------------------
# 5. Terminal interface
# --------------------------------------------------
if __name__ == "__main__":
    while True:
        url = input(
            "\nEnter URL (or 'exit' to quit): "
        ).strip()

        if url.lower() == "exit":
            print("Exiting VeriDex AI.")
            break

        try:
            predict_url(url)
        except Exception as error:
            print("Inference error:", error)
