"""
ThreatLens AI - safety.py
Module for generating contextual, actionable safety guidance for students.

Translates detected phishing risk flags into one concise, practical,
and empowering next step tailored to college student scenarios.

Product Principles:
- Recommend one practical safe next action.
- Action-oriented: tells students what NOT to do and WHERE to safely verify.
- Robust and fault-tolerant against varying flag structures.
"""

from __future__ import annotations


def get_safe_action(flags: list) -> str:
    """
    Returns a short, practical safety recommendation based on detected risk flags.
    
    Args:
        flags: A list of flag dictionaries, each expected to have:
               - "category": str
               - "evidence": str
               - "explanation": str
               
    Returns:
        str: A concise, actionable recommendation for the student.
    """
    if not flags or not isinstance(flags, list):
        return (
            "No immediate phishing indicators detected. Always verify unfamiliar or "
            "unsolicited requests through official college channels before taking action."
        )

    categories = {
        str(f.get("category", "")).strip().lower()
        for f in flags
        if isinstance(f, dict)
    }

    # Extract all explanation text for contextual fallback
    explanation_text = " ".join(
        str(f.get("explanation", ""))
        for f in flags
        if isinstance(f, dict)
    ).lower()

    # 1. Payment Requests / Financial Demands
    payment_cats = {"payment request", "payment", "fee request", "fee demand"}
    if categories & payment_cats or any(
        w in explanation_text
        for w in ["fee payment", "pending fee", "transfer money", "upi payment", "challan payment"]
    ):
        return (
            "Do not make any payment or transfer money. Verify all fee notices directly "
            "with the official VESIT accounts department or official student portal."
        )

    # 2. Sensitive Information / Credential / OTP Theft
    credential_cats = {
        "sensitive information",
        "sensitive-information request",
        "credential harvesting",
        "credential theft",
    }
    if categories & credential_cats or any(
        w in explanation_text
        for w in ["solicits confidential login", "enter password", "submit credentials", "one-time password"]
    ):
        return (
            "Do not submit passwords, OTPs, or student credentials. Official college "
            "administration will never ask for login details via unverified links or messages."
        )

    # 3. Scholarship / Internship / Placement / Reward Fraud
    scholarship_cats = {
        "scholarship/internship fraud",
        "scholarship fraud",
        "internship fraud",
        "unrealistic rewards",
        "placement fraud",
    }
    if categories & scholarship_cats or any(
        w in explanation_text
        for w in ["scholarship offer", "stipend", "internship offer", "placement offer"]
    ):
        return (
            "Do not pay registration fees or share personal documents. Cross-verify scholarship "
            "and internship offers directly with the VESIT Training & Placement (T&P) Cell."
        )

    # 4. College Impersonation / Fake Authority
    impersonation_cats = {
        "college impersonation",
        "fake authority",
        "authority impersonation",
        "domain impersonation",
    }
    if categories & impersonation_cats or any(
        w in explanation_text
        for w in ["impersonates an official", "fake authority", "mimics official college"]
    ):
        return (
            "Do not comply with unverified instructions. Confirm authenticity directly with "
            "your department HOD, class counselor, or the VESIT administrative office."
        )

    # 5. Suspicious Links / URL Obfuscation / Raw IP Hosts / Shorteners
    link_cats = {
        "suspicious link",
        "suspicious links",
        "deceptive link",
        "deceptive subdomain",
        "obfuscated link",
    }
    if categories & link_cats or any(
        w in explanation_text
        for w in ["raw ip address", "link shortener", "deceptive subdomain", "punycode", "unencrypted http"]
    ):
        return (
            "Do not click or open the link. Navigate to the verified college website "
            "(ves.ac.in or vesit.edu) by typing the address directly in your browser."
        )

    # 6. Urgency / Pressure Tactics
    urgency_cats = {"urgency", "pressure tactics", "artificial urgency"}
    if categories & urgency_cats or any(
        w in explanation_text
        for w in ["pressure to act", "artificial deadline", "account suspension"]
    ):
        return (
            "Do not rush to act under artificial deadlines. Take time to pause and "
            "cross-check the claim on the official college notice board before responding."
        )

    # Default fallback when flags are present but unclassified
    return (
        "Verify this communication directly with college staff or your department office "
        "before taking any action or clicking any links."
    )
