"""
main.py - ThreatLens AI Backend API
Role: Person 4 (Backend Integration & API Service)

FastAPI application orchestrating:
- detector.py (text classification)
- link_scanner.py (URL heuristics)
- safety.py (actionable recommendations)

Endpoints:
- POST /api/analyze: Evaluates student messages for phishing risks
- GET /health: Operational health and module availability status
- GET /docs: Built-in Swagger API documentation
"""

import logging
from typing import Dict, List, Optional, Any
from contextlib import asynccontextmanager

from fastapi import FastAPI, HTTPException, status, Request
from fastapi.middleware.cors import CORSMiddleware
from fastapi.responses import JSONResponse
from pydantic import BaseModel, Field, field_validator


# Configure minimal structured logger (zero sensitive message content logged)
logger = logging.getLogger("threatlens_api")
logger.setLevel(logging.INFO)


# =====================================================================
# Dynamic Module Contract Loading
# =====================================================================
# The detection engine imports modules dynamically based on team interfaces.
# If modules are not yet delivered, endpoints fail gracefully with HTTP 503
# rather than returning false "Safe" assessments.

analyze_text_fn = None
analyze_links_fn = None
get_safe_action_fn = None


def load_detection_modules():
    global analyze_text_fn, analyze_links_fn, get_safe_action_fn
    try:
        from detector import analyze_text
        analyze_text_fn = analyze_text
    except ImportError:
        analyze_text_fn = None

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
# CORS Policy
# =====================================================================
# Strictly restrict access to local Streamlit origins; avoid wildcard credentials
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
# Pydantic Schemas
# =====================================================================
class FlagItem(BaseModel):
    category: str = Field(..., description="Phishing cue classification")
    evidence: str = Field(..., description="Exact substring from input")
    explanation: str = Field(..., description="Plain-English explanation of risk")


class AnalyzeRequest(BaseModel):
    sender: Optional[str] = Field(
        default="",
        max_length=320,
        description="Optional sender address or display name (max 320 chars)"
    )
    message: str = Field(
        ...,
        min_length=1,
        max_length=10000,
        description="Required suspicious message body (1 to 10,000 chars)"
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
    label: str = Field(..., description="Classification band: Safe, Suspicious, or High Risk")
    flags: List[FlagItem] = Field(..., description="List of transparent evidence flags")
    safe_action: str = Field(..., description="Contextual safe next action recommendation")


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
        text_result = analyze_text_fn(payload.sender, payload.message)
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

        return AnalyzeResponse(
            risk_score=combined_score,
            label=label,
            flags=deduped_flags,
            safe_action=str(safe_action)
        )

    except HTTPException:
        raise
    except Exception as exc:
        logger.error("Processing failure in detection modules: %s", type(exc).__name__)
        raise HTTPException(
            status_code=status.HTTP_500_INTERNAL_SERVER_ERROR,
            detail="Failed to complete phishing risk assessment."
        )
