"""
main.py - ThreatLens AI Backend API
Role: Senior Backend Engineer

FastAPI application orchestrating:
- detector.py (text classification & psychological tactics)
- link_scanner.py (URL heuristics)
- safety.py (actionable recommendations)

Endpoints:
- POST /api/analyze: Evaluates student messages for phishing risks
- GET /health: Operational health and module readiness
- GET /docs: Built-in Swagger API documentation
"""

import email.utils
import logging
import re
from contextlib import asynccontextmanager
from typing import Any, Dict, List, Optional

from fastapi import FastAPI, HTTPException, Request, status
from fastapi.middleware.cors import CORSMiddleware
from fastapi.responses import JSONResponse
from pydantic import BaseModel, Field, field_validator

# Configure minimal structured logger (zero sensitive message content logged)
logger = logging.getLogger("threatlens_api")
logger.setLevel(logging.INFO)


# =====================================================================
# Configured Institutional Domains
# =====================================================================
CONFIGURED_INSTITUTION_DOMAINS = {
    "vesit.ac.in",
    "vesit.edu",
    "tcs.com",
    "unstop.com",
    "mumbai.ac.in",
    "ac.in",
    "edu.in",
}

PUBLIC_WEBMAIL_DOMAINS = {
    "gmail.com",
    "yahoo.com",
    "outlook.com",
    "hotmail.com",
    "rediffmail.com",
    "live.com",
    "icloud.com",
    "protonmail.com",
}


# =====================================================================
# Dynamic Module Contract Loading
# =====================================================================
analyze_text_fn = None
analyze_links_fn = None
get_safe_action_fn = None
get_psychology_tactics_fn = None


def load_detection_modules():
    global analyze_text_fn, analyze_links_fn, get_safe_action_fn, get_psychology_tactics_fn
    try:
        from detector import analyze_text, get_psychology_tactics
        analyze_text_fn = analyze_text
        get_psychology_tactics_fn = get_psychology_tactics
    except ImportError:
        analyze_text_fn = None
        get_psychology_tactics_fn = None

    try:
        from link_scanner import analyze_links
        analyze_links_fn = analyze_links
    except ImportError:
        analyze_links_fn = None

    try:
        from safety import get_safe_action
        get_safe_action_fn = get_safe_action
    except ImportError:
        get_safe_action_fn = None


@asynccontextmanager
async def lifespan(app: FastAPI):
    load_detection_modules()
    yield


app = FastAPI(
    title="ThreatLens AI API",
    description="Explainable, student-focused phishing risk detection service.",
    version="1.0.0",
    docs_url="/docs",
    redoc_url="/redoc",
    lifespan=lifespan
)


# =====================================================================
# CORS Policy (Strictly for local Streamlit origins)
# =====================================================================
app.add_middleware(
    CORSMiddleware,
    allow_origins=[
        "http://localhost:8501",
        "http://127.0.0.1:8501"
    ],
    allow_credentials=False,
    allow_methods=["GET", "POST", "OPTIONS"],
    allow_headers=["*"],
)


# =====================================================================
# Domain Trust Assessment Helper
# =====================================================================
def assess_sender_domain(sender: str) -> Dict[str, str]:
    """
    Evaluates sender authenticity heuristics.
    Text sender headers alone cannot prove cryptographic SPF/DKIM authentication.
    """
    cleaned = (sender or "").strip()
    if not cleaned or "@" not in cleaned:
        return {
            "status": "Not Applicable",
            "reason": "No email domain present in sender identifier (e.g., SMS, chat handle, or phone number)."
        }

    # Extract email part via standard email address parser
    _, addr = email.utils.parseaddr(cleaned)
    if not addr or "@" not in addr:
        # Fallback to regex if parseaddr didn't catch display-name format
        match = re.search(r"[\w\.-]+@([\w\.-]+\.[a-zA-Z]{2,})", cleaned)
        domain = match.group(1).lower() if match else ""
    else:
        domain = addr.split("@")[-1].lower().strip()

    if not domain:
        return {
            "status": "Not Applicable",
            "reason": "Could not extract valid domain from sender."
        }

    # Check institutional match (exact or subdomain)
    is_inst = any(domain == inst or domain.endswith("." + inst) for inst in CONFIGURED_INSTITUTION_DOMAINS)
    if is_inst:
        return {
            "status": "Recognized Institutional Domain",
            "reason": "Recognized institutional domain; authenticity unverified via SPF/DKIM/DMARC."
        }

    # Check public webmail
    if domain in PUBLIC_WEBMAIL_DOMAINS:
        return {
            "status": "Unverified Domain",
            "reason": "Sender uses a generic public webmail domain; institutional authenticity not established."
        }

    return {
        "status": "Unverified",
        "reason": "Sender authenticity has not been independently confirmed."
    }


# =====================================================================
# Pydantic Schemas
# =====================================================================
class FlagItem(BaseModel):
    category: str = Field(..., description="Phishing cue classification")
    evidence: str = Field(..., description="Exact substring from input")
    explanation: str = Field(..., description="Plain-English explanation of risk")


class DomainAssessment(BaseModel):
    status: str
    reason: str


class AnalyzeRequest(BaseModel):
    sender: Optional[str] = Field(
        default="",
        max_length=320,
        description="Optional sender address or display name (max 320 chars)"
    )
    message: str = Field(
        ...,
        min_length=1,
        max_length=5000,
        description="Required suspicious message body (1 to 5,000 chars)"
    )

    @field_validator("message")
    @classmethod
    def validate_message_not_empty(cls, value: str) -> str:
        trimmed = value.strip()
        if not trimmed:
            raise ValueError("Message body cannot be empty or whitespace only.")
        return trimmed


class AnalyzeResponse(BaseModel):
    risk_score: int = Field(..., ge=0, le=100, description="Heuristic risk score between 0 and 100")
    label: str = Field(..., description="Classification band: Safe (0-29), Suspicious (30-59), High Risk (60-100)")
    flags: List[FlagItem] = Field(..., description="List of transparent evidence flags")
    safe_action: str = Field(..., description="Contextual safe next action recommendation")
    psychological_tactics: Optional[List[str]] = Field(
        default_factory=list,
        description="Behavioral manipulation techniques detected"
    )
    domain_assessment: Optional[DomainAssessment] = Field(
        default=None,
        description="Sender domain authenticity assessment"
    )
    analysis_mode: Optional[str] = Field(
        default="rules",
        description="Underlying engine mode (rules / future ML/LLM)"
    )
    disclaimer: Optional[str] = Field(
        default="No detected phishing indicators does not guarantee authenticity.",
        description="Heuristic assessment disclaimer"
    )


class HealthResponse(BaseModel):
    status: str
    version: str
    modules: Dict[str, bool]


# =====================================================================
# Global Exception Handler (Zero Stack-Trace Leaks)
# =====================================================================
@app.exception_handler(Exception)
async def unhandled_exception_handler(request: Request, exc: Exception):
    logger.error("Unhandled error processing request: %s", type(exc).__name__)
    return JSONResponse(
        status_code=status.HTTP_500_INTERNAL_SERVER_ERROR,
        content={"detail": "An internal error occurred during risk assessment. Please try again."}
    )


# =====================================================================
# Endpoints
# =====================================================================
@app.get("/health", response_model=HealthResponse, tags=["System"])
def health_check():
    """Returns system status and module readiness."""
    return HealthResponse(
        status="healthy",
        version="1.0.0",
        modules={
            "detector": analyze_text_fn is not None,
            "link_scanner": analyze_links_fn is not None,
            "safety": get_safe_action_fn is not None
        }
    )


@app.post(
    "/api/analyze",
    response_model=AnalyzeResponse,
    status_code=status.HTTP_200_OK,
    tags=["Analysis"]
)
def analyze(payload: AnalyzeRequest):
    """
    Analyzes sender info and message content across text, link, and safety heuristics.
    Never visits suspicious URLs, logs raw messages, or executes embedded instructions.
    """
    # Enforce that all core modules must be loaded
    if analyze_text_fn is None or analyze_links_fn is None or get_safe_action_fn is None:
        missing = []
        if analyze_text_fn is None:
            missing.append("detector.py")
        if analyze_links_fn is None:
            missing.append("link_scanner.py")
        if get_safe_action_fn is None:
            missing.append("safety.py")
        raise HTTPException(
            status_code=status.HTTP_503_SERVICE_UNAVAILABLE,
            detail=f"Detection engine incomplete. Missing modules: {', '.join(missing)}."
        )

    try:
        # 1. Text Analysis Module (Person 2)
        text_result = analyze_text_fn(payload.sender or "", payload.message)
        text_score = int(text_result.get("score", 0))
        text_flags = text_result.get("flags", [])

        # 2. Link Scanner Module (Person 3)
        link_result = analyze_links_fn(payload.message)
        link_score = int(link_result.get("score", 0))
        link_flags = link_result.get("flags", [])

        # 3. Combine Scores with Capped Bounds (min 100)
        combined_score = min(100, max(0, text_score + link_score))

        # 4. Remove Duplicate Flags while Preserving Order
        seen = set()
        deduped_flags: List[FlagItem] = []
        raw_flags = text_flags + link_flags

        for item in raw_flags:
            if isinstance(item, dict):
                cat = str(item.get("category", "")).strip()
                ev = str(item.get("evidence", "")).strip()
                exp = str(item.get("explanation", "")).strip()
                key = (cat, ev.lower())
                if key not in seen:
                    seen.add(key)
                    deduped_flags.append(FlagItem(category=cat, evidence=ev, explanation=exp))

        # 5. Determine Heuristic Risk Label Band
        if combined_score <= 29:
            label = "Safe"
        elif combined_score <= 59:
            label = "Suspicious"
        else:
            label = "High Risk"

        # 6. Generate Actionable Safe Next Action (Person 3)
        flags_dicts = [f.model_dump() for f in deduped_flags]
        safe_action = get_safe_action_fn(flags_dicts)

        # 7. Extract Psychological Tactics
        if get_psychology_tactics_fn:
            tactics = get_psychology_tactics_fn(flags_dicts)
        else:
            tactics = []

        # 8. Domain Trust Analysis
        domain_eval = assess_sender_domain(payload.sender or "")

        return AnalyzeResponse(
            risk_score=combined_score,
            label=label,
            flags=deduped_flags,
            safe_action=str(safe_action),
            psychological_tactics=tactics,
            domain_assessment=DomainAssessment(**domain_eval),
            analysis_mode="rules",
            disclaimer="No detected phishing indicators does not guarantee authenticity."
        )

    except HTTPException:
        raise
    except Exception as exc:
        logger.error("Processing failure in detection modules: %s", type(exc).__name__)
        raise HTTPException(
            status_code=status.HTTP_500_INTERNAL_SERVER_ERROR,
            detail="Failed to complete phishing risk assessment."
        )
