"""
detector.py - ThreatLens AI Text Classification and Scoring Module
Owner: Person 2

Analyzes sender and message text for student-targeted phishing signals,
including urgency, payment demands, fake authority/impersonation,
credential/OTP theft, internship/scholarship scams, and Hinglish/Hindi
deceptive patterns.

Standard library only (no external dependencies).
"""

import re
from typing import Dict, List, Any, Tuple


# Rule specifications: (Category, Regex Pattern, Weight, Explanation Template)
TEXT_RULES: List[Tuple[str, str, int, str]] = [
    # 1. Credential & Sensitive Info Theft (Actionable solicitation, avoiding false positives on advisories/lectures)
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
    (
        "Sensitive Information Request",
        r"\b(?:provide|ask for|disclose)\s+(?:your\s+)?(?:bank details|debit card pin|atm pin|aadhaar card details)\b",
        30,
        "Requests sensitive banking or identity credentials."
    ),

    # 2. Payment & Fee Requests (Excluding negated forms like 'no registration fee')
    (
        "Payment Request",
        r"\b(?:pay (?:rs\.?|inr|\$)\s*\d+|transfer (?:money|funds?|amount)|send money to upi|upi id|gpay|phonepe|paytm karo|paise (?:bhejo|transfer|jama))\b",
        25,
        "Prompts direct personal payment or transfer to unofficial accounts or UPI handles."
    ),
    (
        "Payment Request",
        r"\b(?:registration fee|processing fee|security deposit|clearance charge|refundable deposit|application charges?)\b",
        25,
        "Demands an upfront fee or deposit, a frequent indicator of recruitment and scholarship advance-fee scams."
    ),

    # 3. Urgency & Coercive Pressure
    (
        "Urgency & Threat",
        r"\b(?:immediate(?:ly)?|within (?:24|12|6|2|1)\s*hours?|within (?:30|15|10)\s*minutes?|act now|last date today|expires today|final warning|strictly prohibited|failure to comply)\b",
        15,
        "Manufactures artificial urgency or administrative pressure to force hasty decisions before verification."
    ),
    (
        "Urgency & Threat",
        r"\b(?:admission (?:will be )?cancell?ed|cancell?ed admission|account (?:will be )?(?:suspended|blocked)|hall ticket (?:withheld|blocked)|debarred from placement|legal action|khatra|account band ho jayega)\b",
        25,
        "Threatens severe academic or disciplinary consequences to provoke immediate panic."
    ),
    (
        "Urgency & Threat",
        r"\b(?:jaldi (?:karein|karo)|turant (?:karein|karo|sampark)|aaj hi|der mat karo|aakhri mauka)\b",
        15,
        "Leverages informal Hinglish/Hindi urgency cues to bypass rational skepticism."
    ),

    # 4. Scholarship & Internship Fraud / Unrealistic Rewards
    (
        "Scholarship/Internship Fraud",
        r"\b(?:guaranteed (?:internship|placement|job offer)|100% (?:placement|selection)|direct selection without interview|bina interview (?:ke )?(?:job|placement|selection))\b",
        25,
        "Promises guaranteed placement or selection without evaluation, typical of fake hiring rings targeting college students."
    ),
    (
        "Scholarship/Internship Fraud",
        r"\b(?:free laptop (?:scheme|distribution|allotment)|stipend of (?:rs\.?|inr|\$)\s*[5-9]\d{4,}|scholarship approved claim now|claim (?:your )?reward|lottery lag gayi|inaam mila hai)\b",
        25,
        "Dangles extravagant student incentives, fake government schemes, or unearned lottery rewards."
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

    # 5. Fake Authority & Institutional Impersonation in Message Body
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
    Checks if a detected match is part of a benign security advisory or negated context.
    E.g., 'Never share your OTP' or 'No registration fee is required'.
    """
    window_start = max(0, start_pos - 60)
    preceding = text[window_start:start_pos].lower()

    if category == "Sensitive Information Request":
        if re.search(r"\b(?:never|do not|don't|will never|should not|must not|advisory|warning|kisi ko na)\s+(?:\w+\s+){0,3}$", preceding):
            return True
        if "never share" in preceding or "do not share" in preceding or "security advisory" in preceding:
            return True

    if category == "Payment Request":
        if re.search(r"\b(?:no|zero|without (?:any)?|waived|free of)\s+(?:\w+\s+){0,2}$", preceding):
            return True

    return False


def analyze_text(sender: str, message: str) -> Dict[str, Any]:
    """
    Analyzes sender info and message content for phishing cues.

    Parameters:
        sender (str): Email address or display name of the sender.
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
            score += 30  # Substantial weight for impersonation from free email

    # 2. Analyze Message Content with Regex Rules
    full_text = message or ""

    for category, pattern, weight, explanation in TEXT_RULES:
        for match in re.finditer(pattern, full_text, re.IGNORECASE):
            start_pos, end_pos = match.span()

            # Skip matches that are negated or legitimate security advisories
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
