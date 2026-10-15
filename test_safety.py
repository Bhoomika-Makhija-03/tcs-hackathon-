"""
Unit tests for safety.py in ThreatLens AI.

Tests contextual safety recommendations for students across all phishing categories,
graceful error handling, and robustness against unexpected inputs.
"""

from __future__ import annotations

import unittest

from safety import get_safe_action


class TestSafetyAction(unittest.TestCase):
    """Test suite for get_safe_action recommendation logic."""

    def test_payment_related_phishing_recommendation(self):
        """Case 1: Payment-related phishing should recommend not paying and independent verification."""
        flags = [
            {
                "category": "Payment Request",
                "evidence": "pay Rs. 5000",
                "explanation": "Directs student to pay pending examination fee immediately."
            }
        ]
        action = get_safe_action(flags)
        self.assertIsInstance(action, str)
        self.assertGreater(len(action), 15)

        action_lower = action.lower()
        # Must recommend not paying
        self.assertTrue(
            "not make any payment" in action_lower or "do not pay" in action_lower or "never transfer" in action_lower,
            f"Expected non-payment warning, got: {action}"
        )
        # Must recommend independent verification
        self.assertTrue(
            "verify" in action_lower or "accounts" in action_lower or "official" in action_lower,
            f"Expected verification guidance, got: {action}"
        )

    def test_credential_and_otp_theft_recommendation(self):
        """Case 2: OTP/password theft should recommend not sharing credentials."""
        flags = [
            {
                "category": "Sensitive Information",
                "evidence": "enter your student portal password and OTP",
                "explanation": "Solicits confidential login credentials and one-time password."
            }
        ]
        action = get_safe_action(flags)
        self.assertIsInstance(action, str)

        action_lower = action.lower()
        # Must recommend not sharing credentials/passwords/OTPs
        self.assertTrue(
            "not submit" in action_lower or "do not share" in action_lower or "never share" in action_lower,
            f"Expected credential protection warning, got: {action}"
        )
        self.assertTrue(
            "password" in action_lower or "otp" in action_lower or "credential" in action_lower,
            f"Expected mention of credentials or passwords, got: {action}"
        )

    def test_suspicious_url_recommendation(self):
        """Case 3: Suspicious URLs should recommend avoiding the link and using verified official website."""
        flags = [
            {
                "category": "Suspicious Link",
                "evidence": "http://192.168.1.100/login",
                "explanation": "URL uses raw IP host evading domain reputation filters."
            }
        ]
        action = get_safe_action(flags)
        self.assertIsInstance(action, str)

        action_lower = action.lower()
        # Must recommend avoiding/not clicking the link
        self.assertTrue(
            "not click" in action_lower or "avoid" in action_lower,
            f"Expected link avoidance warning, got: {action}"
        )
        # Must recommend using independently verified official website / browser
        self.assertTrue(
            "official" in action_lower or "verified" in action_lower or "browser" in action_lower or "website" in action_lower,
            f"Expected guidance to use verified official site, got: {action}"
        )

    def test_impersonation_recommendation(self):
        """Case 4: Impersonation should recommend contacting the institution using official contact details."""
        flags = [
            {
                "category": "College Impersonation",
                "evidence": "vesit-portal.com",
                "explanation": "Domain mimics official college portal on unverified third-party host."
            }
        ]
        action = get_safe_action(flags)
        self.assertIsInstance(action, str)

        action_lower = action.lower()
        # Must recommend contacting official department or institution
        self.assertTrue(
            "hod" in action_lower or "office" in action_lower or "administrative" in action_lower or "counselor" in action_lower or "official" in action_lower,
            f"Expected guidance to contact official institutional authorities, got: {action}"
        )

    def test_empty_flags_general_guidance(self):
        """Case 5: Empty flags should return sensible general guidance."""
        action = get_safe_action([])
        self.assertIsInstance(action, str)
        self.assertGreater(len(action), 20)

        action_lower = action.lower()
        self.assertTrue(
            "no immediate" in action_lower or "safe" in action_lower or "verify" in action_lower,
            f"Expected sensible general guidance, got: {action}"
        )

    def test_unknown_flag_categories_no_crash(self):
        """Case 6: Unknown or custom flag categories should not crash and return fallback guidance."""
        unknown_flags = [
            {
                "category": "Exotic Threat Vector",
                "evidence": "quantum_token_123",
                "explanation": "Unrecognized category from future plugin."
            }
        ]
        action = get_safe_action(unknown_flags)
        self.assertIsInstance(action, str)
        self.assertGreater(len(action), 10)
        self.assertTrue("verify" in action.lower() or "college" in action.lower())

    def test_scholarship_internship_recommendation(self):
        """Bonus: Scholarship / internship fraud should recommend checking with T&P cell."""
        flags = [
            {
                "category": "Scholarship/Internship Fraud",
                "evidence": "stipend of Rs. 40,000",
                "explanation": "Unrealistic stipend requiring registration payment."
            }
        ]
        action = get_safe_action(flags)
        self.assertIsInstance(action, str)
        self.assertTrue(
            "t&p" in action.lower() or "placement" in action.lower() or "training" in action.lower() or "scholarship" in action.lower()
        )

    def test_robustness_against_malformed_inputs(self):
        """Robustness: Non-list, None, or dirty flag items should not crash."""
        # None input
        self.assertIsInstance(get_safe_action(None), str)

        # Non-list input
        self.assertIsInstance(get_safe_action("not a list"), str)

        # List with non-dict elements
        self.assertIsInstance(get_safe_action(["string", 123, None]), str)

        # Dict with missing keys
        self.assertIsInstance(get_safe_action([{"only_one_key": "val"}]), str)


if __name__ == "__main__":
    unittest.main()
