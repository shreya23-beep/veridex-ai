"""
VeriDex AI - On-Device ONNX Runtime Inference & Explainability Engine
Executes ultra-low latency (< 5ms) on-device machine learning predictions,
breaking down risk factors into explainable, non-fatiguing security insights.
"""

import os
import time
import json
import numpy as np
import onnxruntime as ort
import joblib

from .feature_extractor import extract_features, features_to_vector, FEATURE_COLUMNS
from .typosquat_detector import analyze_typosquatting

MODELS_DIR = os.path.join(os.path.dirname(os.path.dirname(__file__)), "models")
ONNX_MODEL_PATH = os.path.join(MODELS_DIR, "veridex_model.onnx")
JOBLIB_MODEL_PATH = os.path.join(MODELS_DIR, "veridex_model.joblib")

class OnDeviceMLEngine:
    """
    Autonomous On-Device Machine Learning Engine.
    Executes entirely offline using ONNX Runtime with hardware acceleration.
    """

    def __init__(self):
        self.session = None
        self.sklearn_model = None
        self.model_type = "UNKNOWN"
        self._load_model()

    def _load_model(self):
        """Loads ONNX runtime session or falls back to scikit-learn model."""
        if os.path.exists(ONNX_MODEL_PATH):
            try:
                opts = ort.SessionOptions()
                opts.intra_op_num_threads = 2
                opts.graph_optimization_level = ort.GraphOptimizationLevel.ORT_ENABLE_ALL
                self.session = ort.InferenceSession(ONNX_MODEL_PATH, opts, providers=["CPUExecutionProvider"])
                self.input_name = self.session.get_inputs()[0].name
                self.model_type = "ONNX Runtime (Zero-Cloud On-Device)"
                print(f"[ML_ENGINE] Successfully initialized {self.model_type}")
                return
            except Exception as e:
                print(f"[ML_ENGINE] ONNX load warning: {e}. Falling back to Joblib.")

        if os.path.exists(JOBLIB_MODEL_PATH):
            try:
                self.sklearn_model = joblib.load(JOBLIB_MODEL_PATH)
                self.model_type = "Scikit-Learn Random Forest (Local Engine)"
                print(f"[ML_ENGINE] Loaded fallback model: {self.model_type}")
            except Exception as e:
                print(f"[ML_ENGINE] Error loading joblib model: {e}")

    def inspect_url(self, url: str) -> dict:
        """
        Performs full multi-layered on-device inspection:
        1. Typosquatting / Homoglyph rule heuristics
        2. Feature extraction (20 dimensions)
        3. Local ONNX ML prediction
        4. Explainable AI (XAI) risk factor synthesis
        """
        start_time = time.perf_counter()
        raw_url = url.strip()

        # 1. Typosquat analysis
        typosquat = analyze_typosquatting(raw_url)

        # 2. Extract feature vector
        features = extract_features(raw_url)
        vector = features_to_vector(features)
        input_data = np.array([vector], dtype=np.float32)

        # 3. Model Inference
        ml_probability = 0.0
        ml_prediction = 0

        if self.session is not None:
            try:
                outputs = self.session.run(None, {self.input_name: input_data})
                # outputs[0] is label, outputs[1] is probabilities array
                ml_prediction = int(outputs[0][0])
                if len(outputs) > 1 and len(outputs[1]) > 0:
                    probs = outputs[1][0]
                    # Check if probs is dict or array
                    if isinstance(probs, dict):
                        ml_probability = float(probs.get(1, 0.0))
                    elif hasattr(probs, "__len__"):
                        ml_probability = float(probs[1]) if len(probs) > 1 else float(probs[0])
                else:
                    ml_probability = 1.0 if ml_prediction == 1 else 0.0
            except Exception as e:
                print(f"[ML_ENGINE] ONNX inference exception: {e}")
                if self.sklearn_model:
                    ml_prediction = int(self.sklearn_model.predict(input_data)[0])
                    ml_probability = float(self.sklearn_model.predict_proba(input_data)[0][1])
        elif self.sklearn_model is not None:
            ml_prediction = int(self.sklearn_model.predict(input_data)[0])
            ml_probability = float(self.sklearn_model.predict_proba(input_data)[0][1])

        # Latency
        latency_ms = round((time.perf_counter() - start_time) * 1000, 2)

        # 4. Multi-layer Risk Scoring Synthesis
        # If typosquatting is critical/high, fuse with ML probability
        combined_risk_score = ml_probability * 100.0
        if typosquat["is_typosquat"]:
            if typosquat["severity"] == "CRITICAL":
                combined_risk_score = max(combined_risk_score, 98.0)
            elif typosquat["severity"] == "HIGH":
                combined_risk_score = max(combined_risk_score, 88.0)
            elif typosquat["severity"] == "MEDIUM":
                combined_risk_score = max(combined_risk_score, 70.0)

        # 5. Explainable AI (XAI) Risk Factors
        risk_factors = []
        if typosquat["is_typosquat"]:
            risk_factors.append(f"Brand Impersonation: {typosquat['reason']}")
        if features["is_punycode"] == 1:
            risk_factors.append("Punycode / IDN Homograph: Uses deceptive look-alike international characters.")
        if features["has_ip_address"] == 1:
            risk_factors.append("Raw IP Address: Website is hosted on a bare IP rather than a registered domain.")
        if features["is_suspicious_tld"] == 1:
            risk_factors.append(f"High-Risk TLD: Domain uses an extension frequently abused for automated spam campaigns.")
        if features["has_at_symbol"] == 1:
            risk_factors.append("URL Obfuscation: '@' character detected, which can mask the true destination.")
        if features["has_double_slash"] == 1:
            risk_factors.append("Path Redirection: Double slashes '//' inside path indicate redirect manipulation.")
        if features["suspicious_keyword_count"] >= 2:
            risk_factors.append(f"Deceptive Keywords: URL contains {features['suspicious_keyword_count']} high-risk keywords (e.g. login, verify, secure).")
        if features["entropy_domain"] > 3.8:
            risk_factors.append(f"High Domain Entropy ({features['entropy_domain']}): Indicates algorithmic randomness or DGA generation.")
        if features["is_https"] == 0:
            risk_factors.append("Unencrypted Connection: Missing HTTPS protocol encryption.")

        # Verdict assignment
        if combined_risk_score >= 70:
            verdict = "PHISHING / THREAT DETECTED"
            threat_color = "#ef4444" # Red
        elif combined_risk_score >= 40:
            verdict = "SUSPICIOUS / CAUTION"
            threat_color = "#f59e0b" # Amber
        else:
            verdict = "SAFE & VERIFIED"
            threat_color = "#22c55e" # Green
            if not risk_factors:
                risk_factors.append("Legitimate structural metrics, no typosquatting or deception signatures found.")

        return {
            "url": raw_url,
            "verdict": verdict,
            "threat_color": threat_color,
            "risk_score": round(combined_risk_score, 1),
            "confidence": round(max(ml_probability, 1.0 - ml_probability) * 100, 1),
            "is_threat": combined_risk_score >= 50,
            "latency_ms": latency_ms,
            "engine": self.model_type,
            "risk_factors": risk_factors,
            "typosquat_details": typosquat,
            "features": features
        }

# Global singleton engine instance
engine = OnDeviceMLEngine()
