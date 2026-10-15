"""
detector.py - ThreatLens AI Text Classification and Scoring Module
Role: Detection Engine

Analyzes sender info and message content for student-targeted phishing signals:
- Multilingual cues (English, Hindi, Marathi, Hinglish, mixed scripts)
- Polished contextual fraud (Scholarship fee traps, fake internships, credential theft)
- False-positive prevention for legitimate college fee notices, academic deadlines,
  Unstop competition circulars, and security advisories.
- Psychological tactic categorization.

Standard library only (zero external dependencies).
"""

import re
from typing import Dict, List, Any, Tuple


# =====================================================================
# Rule Specifications: (Category, Pattern, Weight, Explanation)
# All patterns capture exact substrings for transparent evidence quoting.
# =====================================================================
TEXT_RULES: List[Tuple[str, str, int, str]] = [
    # -----------------------------------------------------------------
    # 1. Credential & Sensitive Info Theft (Actionable solicitation)
    # -----------------------------------------------------------------
    (
        "Sensitive Information Request",
        r"\b(?:share|send|enter|submit|provide|verify|confirm|tell|forward|input)\s+(?:your\s+)?(?:otp|one[- ]time[- ]password|password|passcode|mpin|cvv|login credentials|atm pin)\b",
        35,
        "Actively solicits confidential credentials, passwords, or OTPs, which legitimate college authorities never request."
    ),
    (
        "Sensitive Information Request",
        r"\b(?:and\s+)?(?:otp|one[- ]time[- ]password|password|passcode|mpin|cvv)\s+(?:share (?:karein|karo)|bhejo|batayein|enter karein|send karein|verify karein)\b",
        35,
        "Uses conversational Hinglish prompts to elicit OTPs or credentials under false pretenses."
    ),
    # Hindi / Marathi Devanagari credential prompts
    (
        "Sensitive Information Request",
        r"(?:अपना\s+OTP\s+(?:साझा\s+करें|भेजें|बताएं)|तुमचा\s+OTP\s+(?:शेअर\s+करा|पाठवा|सांगा)|OTP\s+(?:साझा\s+करें|शेअर\s+करा))",
        35,
        "Directly solicits one-time passwords in Hindi or Marathi."
    ),
    (
        "Sensitive Information Request",
        r"\b(?:provide|ask for|disclose)\s+(?:your\s+)?(?:bank details|debit card pin|atm pin|aadhaar card details)\b",
        30,
        "Requests sensitive banking or identity credentials."
    ),

    # -----------------------------------------------------------------
    # 2. Payment & Advance-Fee Requests (Excluding benign tuition fees)
    # -----------------------------------------------------------------
    (
        "Payment Request",
        r"\b(?:pay (?:rs\.?|inr|\$|₹)\s*\d+|transfer (?:money|funds?|amount)|send money to upi|upi id|gpay|phonepe|paytm karo|paise (?:bhejo|transfer|jama))\b",
        25,
        "Prompts direct personal payment or transfer to unofficial accounts or UPI handles."
    ),
    (
        "Payment Request",
        r"\b(?:registration fee|processing fee|security deposit|clearance charge|refundable deposit|application charges?)\b",
        25,
        "Demands an upfront fee or deposit, a frequent indicator of recruitment and scholarship advance-fee scams."
    ),
    # Hindi / Marathi Devanagari payment demands
    (
        "Payment Request",
        r"(?:तुरंत\s*(?:₹|रु\.?|rs\.?)?\s*\d+\s*(?:जमा\s+करें|भेजें|पे\s+करें)|ताबडतोब\s*(?:₹|रु\.?|rs\.?)?\s*\d+\s*(?:भरा|पाठवा|जमा\s+करा)|नोंदणी\s+शुल्क|प्रक्रिया\s+शुल्क|रजिस्ट्रेशन\s+फीस|प्रोसेसिंग\s+फीस)",
        25,
        "Demands immediate monetary payment or processing fees in Hindi or Marathi."
    ),

    # -----------------------------------------------------------------
    # 3. Urgency & Coercive Threats
    # -----------------------------------------------------------------
    (
        "Urgency & Threat",
        r"\b(?:immediate(?:ly)?|within (?:24|12|6|2|1)\s*hours?|within (?:30|15|10)\s*minutes?|act now|last date today|expires today|final warning|strictly prohibited|failure to comply)\b",
        15,
        "Manufactures artificial urgency or administrative pressure to force hasty decisions before verification."
    ),
    (
        "Urgency & Threat",
        r"\b(?:admission (?:will be )?cancell?ed|cancell?ed admission|account (?:will be )?(?:suspended|blocked|deactivated)|hall ticket (?:withheld|blocked)|debarred from placement|legal action|khatra|account band ho jayega)\b",
        25,
        "Threatens severe academic or disciplinary consequences to provoke immediate panic."
    ),
    # Hindi / Marathi Devanagari urgency & threats
    (
        "Urgency & Threat",
        r"(?:खाता\s+(?:निलंबित|बंद)\s+(?:हो\s+जाएगा|केला\s+जाईल)|अकाउंट\s+बंद\s+हो\s+जाएगा|प्रवेश\s+रद्द\s+होईल|प्रवेश\s+रद्द\s+होगा|ताबडतोब|त्वरित)",
        20,
        "Leverages severe administrative threats in Hindi or Marathi to incite panic."
    ),
    (
        "Urgency & Threat",
        r"\b(?:jaldi (?:karein|karo)|turant (?:karein|karo|sampark)|aaj hi|der mat karo|aakhri mauka)\b",
        15,
        "Leverages informal Hinglish/Hindi urgency cues to bypass rational skepticism."
    ),

    # -----------------------------------------------------------------
    # 4. Scholarship & Internship Fraud / Unrealistic Rewards
    # -----------------------------------------------------------------
    (
        "Scholarship/Internship Fraud",
        r"\b(?:guaranteed (?:internship|placement|job offer)|100% (?:placement|selection)|direct selection without interview|bina interview (?:ke )?(?:job|placement|selection))\b",
        25,
        "Promises guaranteed placement or selection without evaluation, typical of fake hiring rings targeting college students."
    ),
    (
        "Scholarship/Internship Fraud",
        r"\b(?:free laptop (?:scheme|distribution|allotment)|stipend of (?:rs\.?|inr|\$|₹)\s*[5-9]\d{4,}|scholarship approved claim now|claim (?:your )?reward|lottery lag gayi|inaam mila hai)\b",
        25,
        "Dangles extravagant student incentives, fake government schemes, or unearned lottery rewards."
    ),
    # Hindi / Marathi Devanagari scholarship & job promises
    (
        "Scholarship/Internship Fraud",
        r"(?:छात्रवृत्ति\s+मंजूर|शिष्यवृत्ती\s+मंजूर|मुफ्त\s+लैपटॉप|मोफत\s+लॅपटॉप|लॅपटॉप\s+योजना|लैपटॉप\s+योजना|मुलाखतीशिवाय\s+(?:थेट\s+निवड|नोकरी)|बिना\s+इंटरव्यू\s+(?:के\s+)?(?:नौकरी|प्लेसमेंट))",
        25,
        "Offers unearned scholarships, free laptops, or interview-free jobs in Hindi or Marathi."
    ),
    (
        "Scholarship/Internship Fraud",
        r"\bcongratulations[!,\s]+(?:you (?:have )?won|you are selected|aapko mila hai|claim your)\b",
        20,
        "Uses unsolicited congratulatory language commonly found in prize, lottery, and scholarship scams."
    ),
    (
        "Scholarship/Internship Fraud",
        r"\b(?:national student scholarship|exclusive tcs selection|direct placement offer)\b",
        20,
        "Uses enticing brand or national scholarship hooks to fabricate legitimacy."
    ),
    # Fake Unstop / Competition prize scam hooks
    (
        "Scholarship/Internship Fraud",
        r"\b(?:unstop\s+(?:winner|cash\s+prize|winner\s+alert)|disburse (?:the )?(?:cash )?prize)\b",
        20,
        "Impersonates student competition platforms like Unstop to demand processing fees for fake prizes."
    ),

    # -----------------------------------------------------------------
    # 5. Fake Authority & Institutional Impersonation
    # -----------------------------------------------------------------
    (
        "Fake Authority",
        r"\b(?:from:?\s*(?:tcs\s+hr|campus\s+recruitment\s+team|vesit\s+placement\s+cell|exam\s+cell|dean\s+office|scholarship\s+department))\b",
        15,
        "Claims official organizational authority in the message body to manipulate student trust."
    ),
]


def _check_sender_impersonation(sender: str) -> List[Dict[str, str]]:
    """
    Checks if an official-sounding entity (e.g. Dean, Placement, TCS, VESIT)
    is being sent from a public/free email provider (e.g. @gmail.com, @yahoo.com).
    """
    flags: List[Dict[str, str]] = []
    sender_clean = sender.strip()
    if not sender_clean:
        return flags

    # Check for free public webmail domains
    free_domains_regex = r"@(gmail|yahoo|hotmail|outlook|rediffmail|live|protonmail)\.[a-z.]+"
    has_free_domain = re.search(free_domains_regex, sender_clean, re.IGNORECASE)

    # Keywords suggesting institutional authority or corporate identity
    authority_regex = r"(?:^|[\b._\-])(vesit|dean|placement|exam[-_ ]?cell|scholarship|registrar|director|tcs|tata consultancy|admin|principal)(?:$|[\b._\-])"
    authority_match = re.search(authority_regex, sender_clean, re.IGNORECASE)

    if has_free_domain and authority_match:
        matched_keyword = authority_match.group(1)
        flags.append({
            "category": "Sender Impersonation",
            "evidence": sender_clean,
            "explanation": f"Sender claims official authority ('{matched_keyword}') but uses a free/personal email service ('{has_free_domain.group(0)}') rather than an official institutional or corporate domain."
        })

    return flags


def _is_negated_or_advisory(text: str, start_pos: int, end_pos: int, category: str) -> bool:
    """
    Checks if a detected match is part of a benign security advisory, negated context,
    or routine academic notice.
    """
    window_start = max(0, start_pos - 80)
    preceding = text[window_start:start_pos].lower()
    following_window = text[end_pos:min(len(text), end_pos + 40)].lower()

    # 1. Benign Security Advisories (e.g. "Never share your OTP or password")
    if category == "Sensitive Information Request":
        if re.search(r"\b(?:never|do not|don't|will never|should not|must not|advisory|warning|kisi ko na|कधीही\s+शेअर\s+करू\s+नका|नाही)\s+(?:\w+\s+){0,3}$", preceding):
            return True
        if any(term in preceding for term in ["never share", "do not share", "security advisory", "never disclose", "कधीही शेअर करू नका"]):
            return True

    # 2. Negated fee terms (e.g. "No registration fee is required")
    if category == "Payment Request":
        if re.search(r"\b(?:no|zero|without (?:any)?|waived|free of|कोणतेही\s+नाही|नाही)\s+(?:\w+\s+){0,2}$", preceding):
            return True
        if "no registration fee" in preceding or "zero registration fee" in preceding:
            return True

    # 3. Legitimate college fee / exam notices through standard portals
    # e.g., "pay your semester tuition fees before Friday via student portal"
    # Should not trigger unless accompanied by personal UPI/unsolicited fee demand
    if category == "Payment Request":
        benign_fee_context = any(term in text.lower() for term in [
            "tuition fee", "semester tuition", "exam form fee", "college accounts office",
            "accounts counter", "bank challan", "moodle", "college erp"
        ])
        suspicious_destination = any(term in text.lower() for term in [
            "upi id", "gpay", "phonepe", "paytm karo", "@upi", "crypto", "gift card"
        ])
        if benign_fee_context and not suspicious_destination:
            # Check if this specific match is just "tuition fee" or standard schedule
            if "registration fee" not in text[start_pos:end_pos].lower():
                return True

    # 4. Standard academic deadlines (e.g., "Assignment 3 deadline is Friday 5 PM")
    if category == "Urgency & Threat":
        if any(term in preceding or term in following_window for term in [
            "assignment", "lab submission", "moodle submission", "homework", "practical record"
        ]):
            if not any(threat in text.lower() for threat in ["admission cancelled", "account blocked", "legal action", "suspended"]):
                return True

    return False


def get_psychology_tactics(flags: List[Dict[str, str]]) -> List[str]:
    """
    Extracts psychological manipulation tactics directly supported by detected evidence.

    Returns list from:
    - Urgency / FOMO
    - Financial Pressure
    - Financial Incentive
    - Authority Impersonation
    - Credential Theft
    """
    tactics = set()
    for f in flags:
        cat = f.get("category", "")
        ev = f.get("evidence", "").lower()
        exp = f.get("explanation", "").lower()

        if "urgency" in cat.lower() or "threat" in cat.lower():
            tactics.add("Urgency / FOMO")
        elif "sensitive" in cat.lower() or any(k in ev for k in ["otp", "password", "credential", "pin"]):
            tactics.add("Credential Theft")
        elif "impersonation" in cat.lower() or "authority" in cat.lower():
            tactics.add("Authority Impersonation")
        elif "payment" in cat.lower():
            tactics.add("Financial Pressure")
        elif "scholarship" in cat.lower() or "fraud" in cat.lower() or any(k in ev for k in ["won", "reward", "laptop", "stipend", "lottery", "inaam", "मंजूर", "योजना"]):
            tactics.add("Financial Incentive")

    order = [
        "Urgency / FOMO",
        "Financial Pressure",
        "Financial Incentive",
        "Authority Impersonation",
        "Credential Theft"
    ]
    return [t for t in order if t in tactics]


def analyze_text(sender: str, message: str) -> Dict[str, Any]:
    """
    Analyzes sender info and message content for phishing cues.

    Parameters:
        sender (str): Email address, handle, or display name of sender.
        message (str): Body of the suspicious message/email/SMS/WhatsApp.

    Returns:
        dict: {"score": int (0-100), "flags": list of dicts with category, evidence, explanation}
    """
    score = 0
    flags: List[Dict[str, str]] = []
    seen_evidence_lower = set()

    # 1. Analyze Sender for Impersonation
    sender_flags = _check_sender_impersonation(sender)
    for flag in sender_flags:
        key = (flag["category"], flag["evidence"].lower())
        if key not in seen_evidence_lower:
            seen_evidence_lower.add(key)
            flags.append(flag)
            score += 30

    # 2. Treat message strictly as raw untrusted data (prompt-injection immune)
    full_text = message or ""

    for category, pattern, weight, explanation in TEXT_RULES:
        for match in re.finditer(pattern, full_text, re.IGNORECASE):
            start_pos, end_pos = match.span()

            # Skip matches that are negated, advisories, or benign academic notices
            if _is_negated_or_advisory(full_text, start_pos, end_pos, category):
                continue

            # Extract exact substring from original text
            exact_evidence = match.group(0)
            key = (category, exact_evidence.lower())

            if key not in seen_evidence_lower:
                seen_evidence_lower.add(key)
                flags.append({
                    "category": category,
                    "evidence": exact_evidence,
                    "explanation": explanation
                })
                score += weight

    # 3. Deterministic normalization & cap at 100
    final_score = max(0, min(100, int(score)))

    return {
        "score": final_score,
        "flags": flags
    }
