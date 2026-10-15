"""
ThreatLens AI - link_scanner.py
Module for offline scanning and risk analysis of URLs in student communications.

Detects suspicious link patterns using standard library parsing:
- Raw IP address hosts (evading domain reputation filters)
- Punycode / IDN homograph spoofing (xn-- lookalikes)
- Misleading university and college domain impersonation (e.g., VESIT spoofing)
- Deceptive subdomains (mimicking official portals on third-party domains)
- URL shortening services (obscuring destination addresses)
- Unusual HTTP usage (unencrypted HTTP or non-standard ports for sensitive actions)
- High-risk disposable top-level domains (.xyz, .top, .buzz, etc.)
- Embedded credentials (@ symbol obfuscation)
- Deceptive academic lures (course registration, fee claims, hall tickets)
- Malformed URLs and invalid port specifications

Security Principles:
- Strictly offline parsing using Python standard library (urllib.parse, re, ipaddress).
- NEVER fetches, visits, or opens URLs over the network.
- Domain checks strictly use parsed hostnames, never raw message substrings.
- Evidence strictly quotes an exact substring of the original message.
- Indicators are heuristic risk signals, not guarantees.
"""

from __future__ import annotations

import ipaddress
import re
from urllib.parse import urlsplit


# Legitimate academic, institutional, and examination authority domains
LEGITIMATE_ACADEMIC_DOMAINS = {
    "ves.ac.in",
    "vesit.edu",
    "vesit.ac.in",
    "ves.edu",
    "mu.ac.in",
    "mumbai.ac.in",
    "aicte-india.org",
    "ugc.gov.in",
    "scholarships.gov.in",
    "mahaeschol.maharashtra.gov.in",
    "nptel.ac.in",
    "swayam.gov.in",
    "tcs.com",
    "tcsion.com",
}

# Known URL shorteners commonly used to conceal destination links
KNOWN_SHORTENERS = {
    "bit.ly",
    "tinyurl.com",
    "t.co",
    "cutt.ly",
    "is.gd",
    "rb.gy",
    "ow.ly",
    "rebrand.ly",
    "shorturl.at",
    "tiny.cc",
    "bc.vc",
    "goo.gl",
    "v.gd",
    "bl.ink",
    "s.id",
    "soo.gd",
    "tny.im",
}

# High-risk / disposable TLDs frequently abused in ephemeral phishing attacks
HIGH_RISK_TLDS = {
    "xyz",
    "top",
    "buzz",
    "icu",
    "club",
    "work",
    "fit",
    "rest",
    "click",
    "link",
    "zip",
    "mov",
    "surfer",
    "kim",
    "gdn",
    "tk",
    "ml",
    "ga",
    "cf",
    "gq",
    "cc",
    "online",
    "site",
    "vip",
}

# Keywords indicating institutional branding or administrative services
COLLEGE_KEYWORDS = [
    "vesit",
    "ves-",
    "ves_",
    "v-esit",
    "ves1t",
    "vescollege",
    "college-",
    "-college",
    "college.",
    "university-",
    "-university",
    "university.",
    "examcell",
    "exam-cell",
    "placementcell",
    "placement-cell",
    "studentportal",
    "student-portal",
    "campusportal",
    "campus-portal",
    "mumbaiuniv",
]

# Academic lures targeted at students in paths or query strings
ACADEMIC_LURE_KEYWORDS = [
    "course-reg",
    "coursereg",
    "course-registration",
    "exam-form",
    "hall-ticket",
    "hallticket",
    "stipend-claim",
    "free-laptop",
    "scholarship-award",
    "semester-fee",
    "fee-waiver",
    "fee-payment",
    "re-exam",
    "admit-card",
    "provisional-degree",
]

# Sensitive operations keywords for checking insecure HTTP protocols
SENSITIVE_KEYWORDS = [
    "login",
    "signin",
    "fee",
    "fees",
    "pay",
    "payment",
    "bank",
    "account",
    "password",
    "otp",
    "register",
    "admission",
    "scholarship",
    "result",
    "exam",
    "verify",
    "credential",
]

# Regex pattern matching URLs with schemes, scheme-less domains, shorteners, or IP addresses
URL_REGEX = re.compile(
    r'(?i)\b('
    r'https?://[^\s<>"\'`()\[\]{}]+'
    r'|'
    r'www\.[a-z0-9-]+(?:\.[a-z0-9-]+)+(?::\d+)?(?:/[^\s<>"\'`()\[\]{}]*)?'
    r'|'
    r'(?:bit\.ly|tinyurl\.com|t\.co|cutt\.ly|is\.gd|rb\.gy|ow\.ly|shorturl\.at|bl\.ink|s\.id)/[^\s<>"\'`()\[\]{}]+'
    r'|'
    r'[a-z0-9-]+(?:\.[a-z0-9-]+)*\.(?:com|org|net|edu|ac\.in|edu\.in|gov|gov\.in|xyz|top|site|online|tech|live|club|tk|ml|ga|cf|gq|cc|in|info|biz|me|app|link|buzz|icu|io|zip|mov|test)(?::\d+)?(?:/[^\s<>"\'`()\[\]{}]*)?'
    r'|'
    r'(?:(?:25[0-5]|2[0-4]\d|[01]?\d\d?)\.){3}(?:25[0-5]|2[0-4]\d|[01]?\d\d?)(?::\d+)?(?:/[^\s<>"\'`()\[\]{}]*)?'
    r')'
)

# Trailing punctuation to strip from sentence-embedded URLs
TRAILING_PUNCTUATION = ".,;:!?)>]}'`\""


def _extract_urls(message: str) -> list[str]:
    """
    Extract unique URLs from message text while guaranteeing every returned
    string is an exact substring of message.
    """
    if not isinstance(message, str) or not message.strip():
        return []

    extracted: list[str] = []
    seen: set[str] = set()

    for match in URL_REGEX.finditer(message):
        start = match.start()
        # Avoid capturing email domain parts (e.g. user@ves.ac.in)
        if start > 0 and message[start - 1] == "@":
            continue

        raw = match.group(0)
        clean = raw
        while clean and clean[-1] in TRAILING_PUNCTUATION:
            clean = clean[:-1]

        if clean and clean not in seen and clean in message:
            seen.add(clean)
            extracted.append(clean)

    return extracted


def _is_ip_address(host: str) -> bool:
    """Check if the given host string is a raw IPv4 or IPv6 address."""
    try:
        ipaddress.ip_address(host)
        return True
    except ValueError:
        return False


def _is_legitimate_domain(host: str) -> bool:
    """Check if the parsed hostname belongs to verified educational or institutional domains."""
    if not host:
        return False

    for legit in LEGITIMATE_ACADEMIC_DOMAINS:
        if host == legit or host.endswith("." + legit):
            return True

    # Real accredited institutional top-level domains
    if (
        host.endswith(".ac.in")
        or host.endswith(".edu.in")
        or host.endswith(".gov.in")
        or host.endswith(".edu")
    ):
        return True

    return False


def _check_deceptive_subdomain(host: str) -> tuple[bool, str]:
    """
    Detects deceptive subdomains designed to mimic institutional, educational,
    or official portals on third-party domains (e.g. college.example.com.attacker.test).
    """
    labels = host.split(".")
    if len(labels) < 3 or _is_legitimate_domain(host):
        return False, ""

    # Determine root domain and subdomain prefix
    if (
        len(labels) >= 4
        and labels[-2] in {"ac", "edu", "co", "gov", "org", "net"}
        and len(labels[-1]) == 2
    ):
        subdomain_labels = labels[:-3]
        root_domain = ".".join(labels[-3:])
    else:
        subdomain_labels = labels[:-2]
        root_domain = ".".join(labels[-2:])

    subdomain_prefix = ".".join(subdomain_labels)

    # 1. Embedded pseudo-TLD in subdomain
    embedded_tlds = {"com", "edu", "org", "net", "ac", "gov", "in", "io", "test"}
    for lbl in subdomain_labels:
        if lbl in embedded_tlds:
            return (
                True,
                f"Domain embeds a pseudo-TLD (.{lbl}) in its subdomain ('{subdomain_prefix}') "
                f"to disguise the true destination domain ('{root_domain}').",
            )

    # 2. Institutional/college terms in subdomain while root domain is unverified
    institutional_terms = {
        "college",
        "university",
        "vesit",
        "ves",
        "campus",
        "student",
        "studentportal",
        "examcell",
        "placement",
        "admissions",
        "admin",
        "academic",
        "noticeboard",
        "portal",
    }
    for term in institutional_terms:
        if any(term == lbl or term in lbl for lbl in subdomain_labels):
            return (
                True,
                f"Domain uses deceptive subdomain ('{subdomain_prefix}') mimicking "
                f"an academic institution on an unverified destination domain ('{root_domain}').",
            )

    # 3. Excessive subdomain nesting (5 or more labels)
    if len(labels) >= 5:
        return (
            True,
            f"Domain contains excessive nested subdomains ({len(labels)} levels) "
            f"commonly used in phishing to conceal the root domain ('{root_domain}').",
        )

    return False, ""


def analyze_links(message: str) -> dict:
    """
    Analyzes URLs found in a student communication for phishing and deception indicators.
    
    Args:
        message: The raw text of the incoming message.
        
    Returns:
        dict: {
            "score": int (0 to 100),
            "flags": [
                {
                    "category": str,
                    "evidence": str (exact substring of message),
                    "explanation": str
                },
                ...
            ]
        }
    """
    if not isinstance(message, str) or not message.strip():
        return {"score": 0, "flags": []}

    urls = _extract_urls(message)
    if not urls:
        return {"score": 0, "flags": []}

    flags: list[dict] = []
    seen_flag_keys: set = set()
    total_score = 0

    def add_flag(category: str, evidence: str, explanation: str, score_delta: int) -> None:
        nonlocal total_score
        sig = (category, evidence, explanation)
        if sig not in seen_flag_keys:
            seen_flag_keys.add(sig)
            flags.append({
                "category": category,
                "evidence": evidence,
                "explanation": explanation,
            })
            total_score += score_delta

    for raw_url in urls:
        evidence = raw_url
        url_to_parse = raw_url
        if not (url_to_parse.startswith("http://") or url_to_parse.startswith("https://")):
            url_to_parse = "http://" + url_to_parse

        malformed = False
        malformed_detail = ""
        port = None
        host = ""
        scheme = ""
        path = ""
        query = ""
        netloc = ""

        try:
            parsed = urlsplit(url_to_parse)
            host = (parsed.hostname or "").lower()
            scheme = (parsed.scheme or "").lower()
            path = (parsed.path or "").lower()
            query = (parsed.query or "").lower()
            netloc = (parsed.netloc or "").lower()
            try:
                port = parsed.port
            except ValueError as ve:
                malformed = True
                malformed_detail = f"invalid port specification ({ve})"
        except Exception as e:
            malformed = True
            malformed_detail = f"malformed URL structure ({e})"

        # Handle malformed URL / port safely without crashing
        if malformed:
            add_flag(
                category="Suspicious Link",
                evidence=evidence,
                explanation=(
                    f"URL contains an {malformed_detail}, a potential indicator of "
                    "malformed or obfuscated phishing payload."
                ),
                score_delta=20,
            )
            continue

        # Verified educational portals over HTTPS with standard ports are safe
        if (
            _is_legitimate_domain(host)
            and scheme == "https"
            and "@" not in netloc
            and (port is None or port in (80, 443))
        ):
            continue

        # 1. Embedded Credentials / '@' Obfuscation Trick
        if "@" in netloc:
            add_flag(
                category="Suspicious Link",
                evidence=evidence,
                explanation=(
                    f"URL contains an '@' character ('{netloc}'), a deceptive technique "
                    "used to mislead users about the true destination."
                ),
                score_delta=35,
            )

        # 2. Raw IP Host Detection
        is_ip = _is_ip_address(host)
        if is_ip:
            add_flag(
                category="Suspicious Link",
                evidence=evidence,
                explanation=(
                    f"URL uses a raw IP address ('{host}') instead of a verified domain name, "
                    "frequently used to evade domain reputation filters."
                ),
                score_delta=35,
            )

        # 3. Punycode / IDN Homograph Spoofing
        elif "xn--" in host:
            add_flag(
                category="Suspicious Link",
                evidence=evidence,
                explanation=(
                    f"Domain contains Punycode ('{host}'), an indicator of homograph spoofing "
                    "targeting institutional names."
                ),
                score_delta=40,
            )

        # 4. URL Shortener Detection (moderately scored to avoid marking all shorteners definitively malicious)
        elif host in KNOWN_SHORTENERS or any(host.endswith("." + s) for s in KNOWN_SHORTENERS):
            add_flag(
                category="Suspicious Link",
                evidence=evidence,
                explanation=(
                    f"URL uses a link shortener ('{host}') that obscures the destination web address, "
                    "commonly seen in student phishing."
                ),
                score_delta=25,
            )

        # 5. Misleading Subdomain Spoofing
        is_subdomain_spoof, sub_explanation = _check_deceptive_subdomain(host)
        if is_subdomain_spoof:
            add_flag(
                category="Suspicious Link",
                evidence=evidence,
                explanation=sub_explanation,
                score_delta=35,
            )

        # 6. Misleading College Domain Impersonation & Lookalikes (checked on parsed hostname)
        is_impersonating = False
        if host and not _is_legitimate_domain(host) and not is_ip and not is_subdomain_spoof:
            for kw in COLLEGE_KEYWORDS:
                if kw in host:
                    add_flag(
                        category="College Impersonation",
                        evidence=evidence,
                        explanation=(
                            f"Domain '{host}' impersonates an official college or university portal "
                            "on an unverified third-party host."
                        ),
                        score_delta=40,
                    )
                    is_impersonating = True
                    break

        # 7. High-Risk / Disposable Top-Level Domain (TLD)
        labels = host.split(".") if host else []
        tld = labels[-1] if labels else ""
        if tld in HIGH_RISK_TLDS and not is_impersonating and not is_subdomain_spoof:
            add_flag(
                category="Suspicious Link",
                evidence=evidence,
                explanation=(
                    f"Domain uses a high-risk or disposable top-level domain (.{tld}) "
                    "commonly associated with short-lived phishing campaigns."
                ),
                score_delta=20,
            )

        # 8. Deceptive Academic Action / Lure in Link Path
        if not _is_legitimate_domain(host):
            for lure in ACADEMIC_LURE_KEYWORDS:
                if lure in path or lure in query:
                    add_flag(
                        category="Suspicious Link",
                        evidence=evidence,
                        explanation=(
                            f"Link targets urgent student actions ('{lure}') on an unverified external domain."
                        ),
                        score_delta=25,
                    )
                    break

        # 9. Unusual Port Usage
        if port is not None and port not in (80, 443):
            add_flag(
                category="Suspicious Link",
                evidence=evidence,
                explanation=(
                    f"URL uses non-standard port :{port}, abnormal for official institutional web services."
                ),
                score_delta=20,
            )

        # 10. Insecure HTTP Usage for Sensitive Operations
        is_sensitive = any(s in path or s in query or s in host for s in SENSITIVE_KEYWORDS)
        if scheme == "http" and is_sensitive:
            add_flag(
                category="Suspicious Link",
                evidence=evidence,
                explanation=(
                    "Uses unencrypted HTTP for sensitive student operations (fees, credentials, or exam access), "
                    "exposing data to interception."
                ),
                score_delta=20,
            )

    final_score = min(100, max(0, total_score))
    return {
        "score": final_score,
        "flags": flags,
    }
