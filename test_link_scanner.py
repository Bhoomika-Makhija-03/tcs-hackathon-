"""
Unit tests for link_scanner.py in ThreatLens AI.

Tests 10 synthetic phishing detection cases, interface contracts,
offline security invariants, and scoring behavior.
"""

from __future__ import annotations

import unittest
from unittest.mock import patch

from link_scanner import analyze_links


class TestLinkScanner(unittest.TestCase):
    """Test suite for URL extraction and heuristic risk scoring."""

    def _assert_contract(self, message: str, result: dict) -> None:
        """Verify the strict interface schema, score bounds, and evidence substring invariants."""
        self.assertIsInstance(result, dict, "Result must be a dictionary")
        self.assertIn("score", result, "Result dictionary must have 'score'")
        self.assertIn("flags", result, "Result dictionary must have 'flags'")

        self.assertIsInstance(result["score"], int, "Score must be an integer")
        self.assertGreaterEqual(result["score"], 0, "Score cannot be less than 0")
        self.assertLessEqual(result["score"], 100, "Score cannot be greater than 100")

        self.assertIsInstance(result["flags"], list, "Flags must be a list")

        # Verify no duplicate flags
        seen = set()
        for flag in result["flags"]:
            self.assertIsInstance(flag, dict, "Each flag must be a dict")
            self.assertIn("category", flag)
            self.assertIn("evidence", flag)
            self.assertIn("explanation", flag)
            self.assertIsInstance(flag["category"], str)
            self.assertIsInstance(flag["evidence"], str)
            self.assertIsInstance(flag["explanation"], str)

            # Substring invariant: Evidence MUST be an exact substring of original message
            self.assertIn(
                flag["evidence"],
                message,
                f"Flag evidence '{flag['evidence']}' is NOT an exact substring of message '{message}'"
            )

            # Deduplication check
            sig = (flag["category"], flag["evidence"], flag["explanation"])
            self.assertNotIn(sig, seen, f"Duplicate flag found: {sig}")
            seen.add(sig)

    def test_case_01_normal_https_college_url(self):
        """Case 1: Normal HTTPS college URL should have score 0 and no flags."""
        message = "Please check the official semester timetable at https://ves.ac.in/notices/exam-schedule.pdf."
        result = analyze_links(message)
        self._assert_contract(message, result)

        self.assertEqual(result["score"], 0)
        self.assertEqual(result["flags"], [])

    def test_case_02_http_link_requesting_payment(self):
        """Case 2: HTTP link requesting payment should flag insecure HTTP / fee risks."""
        message = "Urgent: Pay your pending semester fees at http://college-fees.net/pay immediately!"
        result = analyze_links(message)
        self._assert_contract(message, result)

        self.assertGreater(result["score"], 30)
        categories = [f["category"] for f in result["flags"]]
        self.assertTrue(
            "Suspicious Link" in categories or "College Impersonation" in categories
        )
        self.assertTrue(
            any("http" in f["explanation"].lower() or "fee" in f["explanation"].lower() for f in result["flags"])
        )

    def test_case_03_ip_address_based_url(self):
        """Case 3: IP-address-based URL should flag raw IP usage."""
        message = "Access your internal grades portal here: http://192.168.1.100/login"
        result = analyze_links(message)
        self._assert_contract(message, result)

        self.assertGreaterEqual(result["score"], 35)
        self.assertTrue(
            any("raw ip address" in f["explanation"].lower() for f in result["flags"])
        )

    def test_case_04_url_shortener(self):
        """Case 4: URL shortener like bit.ly should flag shortener without being definitively marked malicious."""
        message = "Check the sports day schedule: bit.ly/vesit-newsletter"
        result = analyze_links(message)
        self._assert_contract(message, result)

        # Should produce a warning flag for obscured link
        self.assertTrue(
            any("shortener" in f["explanation"].lower() for f in result["flags"])
        )
        # Must avoid marking all shortened links as definitively malicious (High Risk >= 60)
        self.assertLess(result["score"], 60, "Isolated shortened link should not be marked as definitively high risk")
        self.assertGreaterEqual(result["score"], 20)

    def test_case_05_fake_college_lookalike_domain(self):
        """Case 5: Fake college website using a lookalike domain."""
        message = "Admissions 2026 are now open! Register at http://vesit-portal.com/apply."
        result = analyze_links(message)
        self._assert_contract(message, result)

        self.assertGreaterEqual(result["score"], 40)
        self.assertTrue(
            any(f["category"] == "College Impersonation" for f in result["flags"])
        )

    def test_case_06_misleading_subdomain(self):
        """Case 6: Misleading subdomain such as college.example.com.attacker.test."""
        message = "Download your hall ticket at http://college.example.com.attacker.test/hallticket"
        result = analyze_links(message)
        self._assert_contract(message, result)

        self.assertGreaterEqual(result["score"], 35)
        self.assertTrue(
            any("subdomain" in f["explanation"].lower() for f in result["flags"])
        )

    def test_case_07_course_registration_links(self):
        """Case 7: Compare legitimate-looking fake course reg link vs real college course reg link."""
        # Deceptive course registration on unverified external domain
        deceptive_msg = "Mandatory course registration open at http://vesit-courses.org/course-registration"
        res_deceptive = analyze_links(deceptive_msg)
        self._assert_contract(deceptive_msg, res_deceptive)
        self.assertGreaterEqual(res_deceptive["score"], 40)

        # Legitimate course registration on official verified domain
        official_msg = "Official course registration portal: https://ves.ac.in/course-registration"
        res_official = analyze_links(official_msg)
        self._assert_contract(official_msg, res_official)
        self.assertEqual(res_official["score"], 0)
        self.assertEqual(res_official["flags"], [])

        # Suspicious links must score higher than legitimate HTTPS links
        self.assertGreater(res_deceptive["score"], res_official["score"])

    def test_case_08_message_with_no_links(self):
        """Case 8: Message with no links should cleanly return score 0 and empty flags."""
        message = "The college library will remain closed tomorrow for annual maintenance."
        result = analyze_links(message)
        self._assert_contract(message, result)

        self.assertEqual(result["score"], 0)
        self.assertEqual(result["flags"], [])

    def test_case_09_multiple_urls_in_one_message(self):
        """Case 9: Multiple URLs in one message should be parsed and aggregated without duplicate flags."""
        message = (
            "Refer to circular https://ves.ac.in/notices/fee-deadline.pdf. "
            "Pay now at http://192.168.1.50/pay or visit bit.ly/ves-pay-help."
        )
        result = analyze_links(message)
        self._assert_contract(message, result)

        # Must detect multiple distinct issues across the multiple URLs
        self.assertGreaterEqual(result["score"], 50)
        evidences = {f["evidence"] for f in result["flags"]}
        self.assertIn("http://192.168.1.50/pay", evidences)
        self.assertIn("bit.ly/ves-pay-help", evidences)

    def test_case_10_malformed_url_and_unusual_port(self):
        """Case 10: Malformed URL and unusual port should be handled gracefully without crashing."""
        # Unusual port
        unusual_port_msg = "Internal faculty portal accessible at http://college-portal.net:8888/exam"
        res_port = analyze_links(unusual_port_msg)
        self._assert_contract(unusual_port_msg, res_port)
        self.assertTrue(
            any(":8888" in f["explanation"] or "port" in f["explanation"].lower() for f in res_port["flags"])
        )

        # Malformed port syntax (e.g. string port)
        malformed_msg = "Check this portal: http://example.com:notaport/test"
        res_malformed = analyze_links(malformed_msg)
        self._assert_contract(malformed_msg, res_malformed)
        self.assertTrue(
            any("port" in f["explanation"].lower() or "malformed" in f["explanation"].lower() for f in res_malformed["flags"])
        )

        # Invalid IPv6 brackets
        malformed_ipv6_msg = "Check link http://[invalid-ipv6/test"
        res_ipv6 = analyze_links(malformed_ipv6_msg)
        self._assert_contract(malformed_ipv6_msg, res_ipv6)

    def test_domain_check_uses_parsed_hostname_not_simple_substring(self):
        """Domain checks must use the parsed hostname, not a simple substring of message or path."""
        # Message mentions 'college' and 'vesit' in text, but URL domain is legitimate (github.com)
        msg1 = "VESIT students can access the college project repository at https://github.com/vesit/anti-phishing."
        res1 = analyze_links(msg1)
        self._assert_contract(msg1, res1)
        # github.com is NOT a college lookalike domain, so no College Impersonation flag should fire
        self.assertFalse(
            any(f["category"] == "College Impersonation" for f in res1["flags"]),
            "Should not flag College Impersonation when 'vesit' is only in path or message text"
        )

        # URL has 'vesit' in path on benign host
        msg2 = "See project docs at https://readthedocs.io/vesit-security-guide"
        res2 = analyze_links(msg2)
        self._assert_contract(msg2, res2)
        self.assertFalse(
            any(f["category"] == "College Impersonation" for f in res2["flags"])
        )

    def test_strict_offline_security_no_network_calls(self):
        """Security Invariant: Scanner must NEVER open, fetch, or visit any URLs."""
        with patch("urllib.request.urlopen", side_effect=RuntimeError("NETWORK CALL FORBIDDEN")):
            with patch("socket.socket.connect", side_effect=RuntimeError("SOCKET CALL FORBIDDEN")):
                result = analyze_links("Pay immediately at http://vesit-portal.xyz/fees")
                self.assertIsInstance(result, dict)
                self.assertGreater(result["score"], 0)

    def test_punycode_homograph_detection(self):
        """Punycode / IDN homograph domains should trigger high-risk spoofing flags."""
        msg = "View student notices at http://xn--vsi-tma8e.com/notices"
        result = analyze_links(msg)
        self._assert_contract(msg, result)
        self.assertTrue(
            any("punycode" in f["explanation"].lower() for f in result["flags"])
        )
        self.assertGreaterEqual(result["score"], 40)

    def test_userinfo_at_trick_detection(self):
        """Deceptive '@' userinfo trick in URLs should be flagged."""
        msg = "Authenticate your account at http://vesit.edu@evil-portal.com/login"
        result = analyze_links(msg)
        self._assert_contract(msg, result)
        self.assertTrue(
            any("@" in f["explanation"] for f in result["flags"])
        )


if __name__ == "__main__":
    unittest.main()
