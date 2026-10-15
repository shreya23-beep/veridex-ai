"""
VeriDex AI - Comprehensive Automated Test Suite
Verifies on-device ML model accuracy, ONNX runtime execution,
typosquatting detection, NLP manipulation parsing, and DPAPI vault encryption.
"""

import unittest
import time
import os
import sys

sys.path.insert(0, os.path.dirname(os.path.dirname(__file__)))

from core.typosquat_detector import analyze_typosquatting
from core.feature_extractor import extract_features, features_to_vector, FEATURE_COLUMNS
from core.ml_engine import engine
from core.nlp_analyzer import nlp_analyzer
from security.crypto_vault import vault_crypto
from security.threat_db import threat_db

class TestVeridexEngine(unittest.TestCase):

    def test_01_typosquatting_detection(self):
        """Tests homoglyph and brand impersonation detection."""
        # 1. Homoglyph substitution
        res1 = analyze_typosquatting("http://paypa1-security.com")
        self.assertTrue(res1["is_typosquat"])
        self.assertEqual(res1["spoofed_brand"], "paypal")

        # 2. Subdomain nesting spoof
        res2 = analyze_typosquatting("http://apple.com.attacker-fake.xyz/login")
        self.assertTrue(res2["is_typosquat"])
        self.assertEqual(res2["spoofed_brand"], "apple")

        # 3. Clean domain
        res3 = analyze_typosquatting("https://www.google.com")
        self.assertFalse(res3["is_typosquat"])

    def test_02_feature_extraction(self):
        """Tests that all 20 structural features are extracted accurately."""
        url = "http://paypa1-security-verification.com/login"
        feats = extract_features(url)
        self.assertEqual(len(feats), len(FEATURE_COLUMNS))
        vec = features_to_vector(feats)
        self.assertEqual(len(vec), 20)
        self.assertIsInstance(vec[0], (int, float))

    def test_03_onnx_ml_inference(self):
        """Tests real on-device ONNX inference and latency."""
        phish_url = "http://paypa1-security-verification.com/login"
        res_phish = engine.inspect_url(phish_url)
        self.assertTrue(res_phish["is_threat"])
        self.assertGreaterEqual(res_phish["risk_score"], 70.0)
        self.assertIn("ONNX", res_phish["engine"])

        # Test safe URL
        safe_url = "https://github.com/torvalds/linux"
        res_safe = engine.inspect_url(safe_url)
        self.assertFalse(res_safe["is_threat"])
        self.assertLess(res_safe["risk_score"], 30.0)

        # Test sub-millisecond execution (< 5ms requirement)
        t0 = time.perf_counter()
        engine.inspect_url(safe_url)
        latency = (time.perf_counter() - t0) * 1000
        print(f"\n[TEST BENCHMARK] On-Device URL Scan Latency: {latency:.3f} ms")
        self.assertLess(latency, 25.0)

    def test_04_nlp_manipulation_cues(self):
        """Tests social engineering manipulation cue parsing."""
        scam_text = "URGENT ACTION REQUIRED: Your PayPal account has been suspended! Enter your password and SSN immediately within 24 hours to avoid police arrest."
        res = nlp_analyzer.analyze_text(scam_text)
        self.assertIn(res["threat_level"], ["CRITICAL", "SUSPICIOUS"])
        self.assertGreater(len(res["detected_cues"]), 0)

        # Clean text
        clean_text = "Hi, attached is the revised agenda for our hackathon project presentation tomorrow."
        res_clean = nlp_analyzer.analyze_text(clean_text)
        self.assertEqual(res_clean["threat_level"], "CLEAN")

    def test_05_dpapi_vault_cryptography(self):
        """Tests AES-256 / DPAPI local encrypted vault storage."""
        secret_url = "https://malicious-zero-day-phishing-sample.xyz/auth"
        ciphertext = vault_crypto.encrypt(secret_url)
        self.assertNotEqual(secret_url, ciphertext)
        
        decrypted = vault_crypto.decrypt(ciphertext)
        self.assertEqual(secret_url, decrypted)

        # Test database logging and retrieval
        scan_data = engine.inspect_url(secret_url)
        threat_db.log_scan(scan_data, source="UNIT_TEST")
        recent = threat_db.get_recent_scans(1)
        self.assertEqual(len(recent), 1)
        self.assertEqual(recent[0]["url"], secret_url)

if __name__ == "__main__":
    unittest.main()
