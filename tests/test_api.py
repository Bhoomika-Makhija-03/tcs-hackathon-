"""
tests/test_api.py - Automated API Test Suite for ThreatLens AI Backend
"""

import sys
import os

# Ensure project root is in sys.path
sys.path.insert(0, os.path.abspath(os.path.join(os.path.dirname(__file__), "..")))

import pytest
from fastapi.testclient import TestClient

import main
from main import app, assess_sender_domain


@pytest.fixture
def client():
    return TestClient(app)


# =====================================================================
# 1. Health Endpoint Tests
# =====================================================================
def test_health_endpoint(client):
    response = client.get("/health")
    assert response.status_code == 200
    data = response.json()
    assert data["status"] == "healthy"
    assert "version" in data
    assert "modules" in data
    assert isinstance(data["modules"], dict)
    assert "detector" in data["modules"]
    assert "link_scanner" in data["modules"]
    assert "safety" in data["modules"]


# =====================================================================
# 2. Validation & Input Limit Tests
# =====================================================================
def test_analyze_empty_message(client):
    response = client.post("/api/analyze", json={"sender": "test@example.com", "message": ""})
    assert response.status_code == 422


def test_analyze_whitespace_only_message(client):
    response = client.post("/api/analyze", json={"sender": "test@example.com", "message": "   \n\t  "})
    assert response.status_code == 422


def test_analyze_missing_message_field(client):
    response = client.post("/api/analyze", json={"sender": "test@example.com"})
    assert response.status_code == 422


def test_analyze_oversized_message_over_5000(client):
    oversized = "A" * 5001
    response = client.post("/api/analyze", json={"sender": "test@example.com", "message": oversized})
    assert response.status_code == 422


# =====================================================================
# 3. Missing Dependencies Test (Fails Gracefully, Never Returns Safe)
# =====================================================================
def test_analyze_missing_modules_returns_503(client, monkeypatch):
    monkeypatch.setattr(main, "analyze_text_fn", None)
    monkeypatch.setattr(main, "analyze_links_fn", None)
    monkeypatch.setattr(main, "get_safe_action_fn", None)

    response = client.post(
        "/api/analyze",
        json={"sender": "test@example.com", "message": "Please review this document."}
    )
    assert response.status_code == 503
    assert "Missing modules" in response.json()["detail"]


# =====================================================================
# 4. Domain Trust Assessment Logic Tests
# =====================================================================
def test_domain_assessment_institutional():
    eval_inst = assess_sender_domain("exam_cell@vesit.ac.in")
    assert eval_inst["status"] == "Recognized Institutional Domain"
    assert "SPF/DKIM/DMARC" in eval_inst["reason"]


def test_domain_assessment_public_webmail():
    eval_web = assess_sender_domain("tcs_hr_drive@gmail.com")
    assert eval_web["status"] == "Unverified Domain"


def test_domain_assessment_not_applicable_for_sms():
    eval_sms = assess_sender_domain("+919876543210")
    assert eval_sms["status"] == "Not Applicable"


def test_domain_assessment_unverified_custom_domain():
    eval_cust = assess_sender_domain("rewards@suspicious-scholarship.org")
    assert eval_cust["status"] == "Unverified"


# =====================================================================
# 5. End-to-End Contract Tests with Mock Modules
# =====================================================================
def test_analyze_mock_high_risk_message(client, monkeypatch):
    def mock_analyze_text(sender: str, message: str):
        return {
            "score": 55,
            "flags": [
                {
                    "category": "Urgency & Threat",
                    "evidence": "immediately",
                    "explanation": "Creates pressure to act quickly"
                },
                {
                    "category": "Payment Request",
                    "evidence": "Pay ₹500",
                    "explanation": "Requests upfront fees"
                }
            ]
        }

    def mock_analyze_links(message: str):
        return {
            "score": 30,
            "flags": [
                {
                    "category": "Suspicious Link",
                    "evidence": "http://bit.ly/claim-scholarship",
                    "explanation": "Shortened or deceptive URL"
                },
                # Duplicate flag to test deduplication
                {
                    "category": "Urgency & Threat",
                    "evidence": "immediately",
                    "explanation": "Creates pressure to act quickly"
                }
            ]
        }

    def mock_get_safe_action(flags: list):
        return "Verify the announcement using official college channels."

    def mock_get_psychology_tactics(flags: list):
        return ["Urgency / FOMO", "Financial Pressure"]

    monkeypatch.setattr(main, "analyze_text_fn", mock_analyze_text)
    monkeypatch.setattr(main, "analyze_links_fn", mock_analyze_links)
    monkeypatch.setattr(main, "get_safe_action_fn", mock_get_safe_action)
    monkeypatch.setattr(main, "get_psychology_tactics_fn", mock_get_psychology_tactics)

    payload = {
        "sender": "scholarship@unknown.example",
        "message": "Pay ₹500 immediately to claim your scholarship at http://bit.ly/claim-scholarship"
    }

    response = client.post("/api/analyze", json=payload)
    assert response.status_code == 200
    data = response.json()

    # Core contract checks
    assert data["risk_score"] == 85
    assert data["label"] == "High Risk"
    assert data["safe_action"] == "Verify the announcement using official college channels."
    assert len(data["flags"]) == 3
    assert [f["category"] for f in data["flags"]] == ["Urgency & Threat", "Payment Request", "Suspicious Link"]

    # Extended optional contract checks
    assert data["psychological_tactics"] == ["Urgency / FOMO", "Financial Pressure"]
    assert "domain_assessment" in data
    assert data["domain_assessment"]["status"] == "Unverified"
    assert data["analysis_mode"] == "rules"
    assert "disclaimer" in data


def test_analyze_mock_safe_message(client, monkeypatch):
    monkeypatch.setattr(main, "analyze_text_fn", lambda s, m: {"score": 0, "flags": []})
    monkeypatch.setattr(main, "analyze_links_fn", lambda m: {"score": 0, "flags": []})
    monkeypatch.setattr(main, "get_safe_action_fn", lambda f: "No action required. Message appears normal.")
    monkeypatch.setattr(main, "get_psychology_tactics_fn", lambda f: [])

    payload = {
        "sender": "exam_cell@vesit.ac.in",
        "message": "Timetable has been updated on the notice board."
    }
    response = client.post("/api/analyze", json=payload)
    assert response.status_code == 200
    data = response.json()
    assert data["risk_score"] == 0
    assert data["label"] == "Safe"
    assert data["flags"] == []
    assert data["domain_assessment"]["status"] == "Recognized Institutional Domain"


def test_analyze_optional_sender(client, monkeypatch):
    monkeypatch.setattr(main, "analyze_text_fn", lambda s, m: {"score": 10, "flags": []})
    monkeypatch.setattr(main, "analyze_links_fn", lambda m: {"score": 0, "flags": []})
    monkeypatch.setattr(main, "get_safe_action_fn", lambda f: "Standard verification.")
    monkeypatch.setattr(main, "get_psychology_tactics_fn", lambda f: [])

    response = client.post("/api/analyze", json={"message": "College orientation will begin at 10 AM."})
    assert response.status_code == 200
    assert response.json()["risk_score"] == 10
    assert response.json()["label"] == "Safe"
    assert response.json()["domain_assessment"]["status"] == "Not Applicable"
