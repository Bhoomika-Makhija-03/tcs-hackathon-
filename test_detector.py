"""
test_detector.py - Automated QA Test Suite for ThreatLens AI detector.py
"""

import unittest
from detector import analyze_text


class TestThreatLensDetector(unittest.TestCase):

    def _verify_result_structure(self, sender: str, message: str, result: dict):
        """Validates contract, types, bounds, and exact evidence substring integrity."""
        self.assertIsInstance(result, dict, "Result must be a dict")
        self.assertIn("score", result, "Result must contain 'score'")
        self.assertIn("flags", result, "Result must contain 'flags'")
        
        score = result["score"]
        self.assertIsInstance(score, int, "Score must be an integer")
        self.assertTrue(0 <= score <= 100, f"Score {score} must be between 0 and 100")
        
        flags = result["flags"]
        self.assertIsInstance(flags, list, "Flags must be a list")
        
        for idx, flag in enumerate(flags):
            self.assertIsInstance(flag, dict, f"Flag {idx} must be a dict")
            self.assertEqual(
                set(flag.keys()),
                {"category", "evidence", "explanation"},
                f"Flag {idx} must have exactly 'category', 'evidence', 'explanation'"
            )
            self.assertTrue(isinstance(flag["category"], str) and flag["category"].strip())
            self.assertTrue(isinstance(flag["evidence"], str) and flag["evidence"].strip())
            self.assertTrue(isinstance(flag["explanation"], str) and flag["explanation"].strip())
            
            # CRITICAL CHECK: Evidence must be an exact substring of sender OR message
            evidence = flag["evidence"]
            is_in_sender = evidence in sender
            is_in_message = evidence in message
            self.assertTrue(
                is_in_sender or is_in_message,
                f"Flag evidence '{evidence}' is NOT an exact substring of sender or message!"
            )

    # 1. Normal College Messages (Must be Safe: Score 0-29)
    def test_normal_college_messages(self):
        cases = [
            (
                "exam_cell@vesit.ac.in",
                "Dear Students, the revised timetable for End Semester Examinations has been uploaded on the college website. Please review your slots."
            ),
            (
                "library@vesit.ac.in",
                "Reminder: Return your issued reference books before Friday 4 PM to avoid standard library fine of Rs. 10."
            ),
            (
                "sports_committee@vesit.ac.in",
                "Annual Sports Day registrations are now open for football, cricket, and badminton. Meet the sports coordinator at the gymkhana."
            )
        ]
        for sender, msg in cases:
            res = analyze_text(sender, msg)
            self._verify_result_structure(sender, msg, res)
            self.assertLess(
                res["score"], 30,
                f"Normal message incorrectly scored >= 30: {res['score']}. Flags: {res['flags']}"
            )

    # 2. Scholarship Phishing (High Risk / Suspicious: Score >= 30)
    def test_scholarship_phishing(self):
        cases = [
            (
                "scholarship_desk@gmail.com",
                "URGENT: Your scholarship approved claim now! Free laptop scheme allotment is pending. Pay processing fee of Rs 1200 within 24 hours to claim."
            ),
            (
                "merit_rewards@yahoo.com",
                "Congratulations! You won the national student scholarship. Deposit registration fee to UPI ID student.reward@upi today."
            )
        ]
        for sender, msg in cases:
            res = analyze_text(sender, msg)
            self._verify_result_structure(sender, msg, res)
            self.assertGreaterEqual(
                res["score"], 60,
                f"Scholarship phishing score too low: {res['score']}"
            )
            categories = [f["category"] for f in res["flags"]]
            self.assertTrue(
                any("Scholarship" in c or "Payment" in c for c in categories),
                f"Expected scholarship or payment flag in {categories}"
            )

    # 3. Fake Internship Offers (High Risk: Score >= 60)
    def test_fake_internship_offers(self):
        cases = [
            (
                "tcs_campus_drive@yahoo.com",
                "Exclusive TCS selection! You are offered guaranteed internship with stipend of Rs. 65000. Direct selection without interview. Pay registration fee of Rs 1500 to confirm."
            ),
            (
                "hr_recruiter@gmail.com",
                "Direct placement offer at top tech company with 100% placement assurance. Transfer money to UPI for background check immediately."
            )
        ]
        for sender, msg in cases:
            res = analyze_text(sender, msg)
            self._verify_result_structure(sender, msg, res)
            self.assertGreaterEqual(
                res["score"], 60,
                f"Fake internship score too low: {res['score']}"
            )

    # 4. OTP and Credential Theft (High Risk: Score >= 60)
    def test_otp_requests(self):
        cases = [
            (
                "vesit_admin@gmail.com",
                "Your student portal account has been flagged for suspicious activity. Share your OTP immediately within 15 minutes or your account will be suspended."
            ),
            (
                "support@verify-portal.net",
                "Please send your password and OTP to verify your semester hall ticket. Failure to comply will lead to cancelled admission."
            )
        ]
        for sender, msg in cases:
            res = analyze_text(sender, msg)
            self._verify_result_structure(sender, msg, res)
            self.assertGreaterEqual(res["score"], 60)
            categories = [f["category"] for f in res["flags"]]
            self.assertIn("Sensitive Information Request", categories)

    # 5. Hindi & Hinglish Scams (High Risk: Score >= 60)
    def test_hindi_hinglish_scams(self):
        cases = [
            (
                "offers@promo-alerts.net",
                "Bhai lottery lag gayi! Aapko free laptop scheme ke antargat inaam mila hai. Turant contact karo, aaj aakhri tareekh hai!"
            ),
            (
                "placement_alert@gmail.com",
                "Bina interview ke placement offer letter taiyar hai. Jaldi karo, paise transfer karo is account me turant."
            ),
            (
                "helpdesk@unknown.com",
                "Khatra hai! Aapka account band ho jayega. Apna OTP share karein turant verification ke liye."
            )
        ]
        for sender, msg in cases:
            res = analyze_text(sender, msg)
            self._verify_result_structure(sender, msg, res)
            self.assertGreaterEqual(
                res["score"], 50,
                f"Hinglish scam score too low: {res['score']}"
            )

    # 6. Harmless Messages Containing Suspicious-Sounding Keywords (Must be Safe: Score 0-29)
    def test_harmless_messages_with_suspicious_keywords(self):
        cases = [
            (
                "cyber_cell@vesit.ac.in",
                "Security Advisory: Never share your OTP, password, or login credentials with anyone pretending to be from college IT."
            ),
            (
                "prof_sharma@vesit.ac.in",
                "Network Security Lecture: Tomorrow we will cover one-time password generation and cryptographic password hashing."
            ),
            (
                "tcs_coordinator@vesit.ac.in",
                "Announcement: No registration fee is required for any student participating in TCS Tech Day hackathon."
            ),
            (
                "dean_office@vesit.ac.in",
                "Please pay attention to the circular regarding academic integrity during laboratory examinations."
            ),
            (
                "scholarship_office@vesit.ac.in",
                "The government scholarship committee will verify student eligibility documents in room 105 tomorrow."
            )
        ]
        for sender, msg in cases:
            res = analyze_text(sender, msg)
            self._verify_result_structure(sender, msg, res)
            self.assertLess(
                res["score"], 30,
                f"Harmless message false positive! Score: {res['score']} for message: '{msg}'. Flags: {res['flags']}"
            )


if __name__ == "__main__":
    unittest.main(verbosity=2)
