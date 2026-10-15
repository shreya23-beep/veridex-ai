"""
VeriDex AI - Model Training & ONNX Exporter Pipeline
Builds and trains a high-precision on-device Random Forest classifier on URL features,
evaluates performance metrics, and compiles the model into an optimized ONNX runtime artifact.
"""

import os
import json
import numpy as np
from sklearn.ensemble import RandomForestClassifier
from sklearn.model_selection import train_test_split
from sklearn.metrics import accuracy_score, precision_score, recall_score, f1_score, roc_auc_score
import joblib
from skl2onnx import convert_sklearn
from skl2onnx.common.data_types import FloatTensorType

from .feature_extractor import extract_features, features_to_vector, FEATURE_COLUMNS

# Curated dataset of legitimate and sophisticated phishing/typosquatted URLs
LEGITIMATE_SAMPLES = [
    "https://www.google.com/search?q=cybersecurity+defense",
    "https://github.com/torvalds/linux/commit/8f2c",
    "https://en.wikipedia.org/wiki/Phishing",
    "https://apple.com/iphone-16-pro/specs",
    "https://microsoft.com/en-us/windows/get-windows-11",
    "https://amazon.com/dp/B08N5WRWNW",
    "https://paypal.com/signin",
    "https://chase.com/personal/banking",
    "https://bankofamerica.com/online-banking",
    "https://wellsfargo.com/help",
    "https://binance.com/en/trade/BTC_USDT",
    "https://coinbase.com/dashboard",
    "https://netflix.com/browse/genre/83",
    "https://spotify.com/us/premium",
    "https://linkedin.com/feed",
    "https://twitter.com/home",
    "https://reddit.com/r/MachineLearning",
    "https://stackoverflow.com/questions/52110",
    "https://python.org/downloads/release/python-3120",
    "https://docs.python.org/3/library/unittest.html",
    "https://cloudflare.com/learning/security/what-is-zero-trust",
    "https://nist.gov/cyberframework",
    "https://whitehouse.gov/briefing-room",
    "https://cisa.gov/shields-up",
    "https://mit.edu/research",
    "https://stanford.edu/academics",
    "https://harvard.edu/programs",
    "https://nytimes.com/section/technology",
    "https://bbc.com/news/world",
    "https://reuters.com/business/finance",
    "https://dropbox.com/home",
    "https://adobe.com/creativecloud.html",
    "https://slack.com/workspace-signin",
    "https://zoom.us/join",
    "https://walmart.com/ip/electronics",
    "https://target.com/c/grocery",
    "https://ebay.com/itm/12489",
    "https://gitlab.com/gitlab-org/gitlab",
    "https://digitalocean.com/products/droplets",
    "https://aws.amazon.com/s3/pricing",
    "https://cloud.google.com/kubernetes-engine",
    "https://azure.microsoft.com/en-us/solutions",
    "https://stripe.com/docs/api",
    "https://shopify.com/pricing",
    "https://medium.com/@infosec/modern-threats",
    "https://archive.org/web",
    "https://craigslist.org/about/best",
    "https://duckduckgo.com/?q=privacy",
    "https://mozilla.org/en-US/firefox/new",
    "https://ubuntu.com/download/desktop"
]

PHISHING_SAMPLES = [
    "http://paypa1-security-verification.com/login.php?user=alert",
    "http://192.168.1.105/bankofamerica/secure-auth.html",
    "http://appleid-verify-locked-account.support.xyz/auth",
    "http://chase-bank-customer-support-update.top/account/verify",
    "http://secure-wellsfargo-banking-restore.click/login",
    "http://binance-airdrop-free-tokens.buzz/claim?wallet=crypto",
    "http://metamask-security-recovery-phrase.tk/connect",
    "http://coinbase-fraud-prevention-alert.work/2fa",
    "http://micros0ft-office365-verify.ru/session/login",
    "http://g00gle-drive-shared-document.ml/auth/download",
    "http://netflix-billing-card-declined.cf/update-payment",
    "http://amazon-prime-giftcard-winner.gq/claim-now",
    "http://steam-trade-community-gift.rest/promo/free",
    "http://dhl-express-package-reschedule-fee.cam/tracking",
    "http://fedex-customs-duty-unpaid.monster/pay-now",
    "http://paypal.com.account-verification-service.xyz/signin",
    "http://facebook.com.profile-security-check.icu/confirm",
    "http://instagram-blue-badge-apply.top/verify-profile",
    "http://whatsapp-web-free-gift.surf/download-update",
    "http://irs-tax-refund-immediate-action.live/claim",
    "http://citibank-card-freeze-unlock.fit/client/login",
    "http://dropbox-urgent-document-share.vip/file?id=8392",
    "http://ledger-hardware-wallet-firmware.link/recovery",
    "http://roblox-free-robux-generator.shop/auth",
    "http://discord-nitro-steam-promo.top/free-gift",
    "http://usps-tracking-package-address-confirm.icu/redelivery",
    "http://adobe-account-payment-suspended.club/billing",
    "http://twitter-blue-verification-free.top/claim",
    "http://ebay-buyer-protection-refund.buzz/dispute",
    "http://target-free-coupon-survey.cam/card-claim",
    "http://walmart-shopper-rewards-sweepstakes.live/prize",
    "http://github-security-token-revoke.xyz/repo/login",
    "http://linkedin-job-interview-contact.work/resume/download",
    "http://spotify-family-billing-update.top/card/verify",
    "http://zoom-meeting-invitation-client-update.xyz/join",
    "http://slack-workspace-migration-admin.cam/login",
    "http://xn--pypal-4ve.com/account/security-restore",
    "http://xn--appl-wqa.com/appleid/verify",
    "http://104.244.42.1/chase/signon.php",
    "http://203.0.113.195/secure/login/bank.html",
    "http://verify-bank-account-urgent-suspension.xyz/action",
    "http://update-credit-card-billing-portal.top/step1",
    "http://claim-crypto-usdt-airdrop-2026.club/connect",
    "http://auth-security-center-notification.monster/login",
    "http://wallet-seed-phrase-validator.ru/restore",
    "http://recover-frozen-funds-support.rest/claim",
    "http://customer-identity-proofing-alert.click/id",
    "http://confirm-unauthorized-transaction-now.work/reversal",
    "http://urgent-notice-security-patch.xyz/download.exe",
    "http://win-giftcard-today-survey.buzz/survey.php"
]

def train_and_export_model(output_dir: str = "models"):
    """
    Extracts features, trains the Random Forest model, calculates performance metrics,
    and converts the model to ONNX format.
    """
    os.makedirs(output_dir, exist_ok=True)
    print("[TRAINER] Extracting feature vectors from curated dataset...")

    X = []
    y = []

    for url in LEGITIMATE_SAMPLES:
        feats = extract_features(url)
        X.append(features_to_vector(feats))
        y.append(0)  # 0 = Benign/Safe

    for url in PHISHING_SAMPLES:
        feats = extract_features(url)
        X.append(features_to_vector(feats))
        y.append(1)  # 1 = Phishing/Scam

    X = np.array(X, dtype=np.float32)
    y = np.array(y, dtype=np.int64)

    X_train, X_test, y_train, y_test = train_test_split(
        X, y, test_size=0.25, random_state=42, stratify=y
    )

    print(f"[TRAINER] Training set: {len(X_train)} samples, Test set: {len(X_test)} samples")
    
    # Train robust ensemble classifier
    rf = RandomForestClassifier(
        n_estimators=100,
        max_depth=10,
        random_state=42,
        class_weight="balanced"
    )
    rf.fit(X_train, y_train)

    # Evaluation
    y_pred = rf.predict(X_test)
    y_proba = rf.predict_proba(X_test)[:, 1]

    acc = accuracy_score(y_test, y_pred)
    prec = precision_score(y_test, y_pred)
    rec = recall_score(y_test, y_pred)
    f1 = f1_score(y_test, y_pred)
    roc_auc = roc_auc_score(y_test, y_proba)

    metrics = {
        "accuracy": round(float(acc) * 100, 2),
        "precision": round(float(prec) * 100, 2),
        "recall": round(float(rec) * 100, 2),
        "f1_score": round(float(f1) * 100, 2),
        "roc_auc": round(float(roc_auc) * 100, 2),
        "total_training_samples": len(X),
        "features_count": len(FEATURE_COLUMNS),
        "model_architecture": "RandomForest-100 (Exported to ONNX)",
        "quantization_format": "FP32 Optimized for CPU On-Device"
    }

    print("\n[TRAINER] Model Evaluation Results:")
    for k, v in metrics.items():
        print(f"  - {k}: {v}")

    # 1. Save Metrics and Feature Schema
    metrics_path = os.path.join(output_dir, "model_metrics.json")
    with open(metrics_path, "w") as f:
        json.dump(metrics, f, indent=2)

    features_path = os.path.join(output_dir, "feature_names.json")
    with open(features_path, "w") as f:
        json.dump(FEATURE_COLUMNS, f, indent=2)

    # 2. Save scikit-learn backup model
    joblib_path = os.path.join(output_dir, "veridex_model.joblib")
    joblib.dump(rf, joblib_path)
    print(f"[TRAINER] Saved joblib model to {joblib_path}")

    # 3. Export to ONNX
    print("[TRAINER] Exporting model to ONNX runtime format...")
    initial_type = [("float_input", FloatTensorType([None, len(FEATURE_COLUMNS)]))]
    onnx_model = convert_sklearn(
        rf,
        initial_types=initial_type,
        target_opset=12,
        options={type(rf): {"zipmap": False}}
    )

    onnx_path = os.path.join(output_dir, "veridex_model.onnx")
    with open(onnx_path, "wb") as f:
        f.write(onnx_model.SerializeToString())
    
    print(f"[TRAINER] ONNX Model successfully exported to: {onnx_path}")
    print(f"[TRAINER] ONNX Model file size: {os.path.getsize(onnx_path) / 1024:.2f} KB")

    return metrics

if __name__ == "__main__":
    train_and_export_model()
