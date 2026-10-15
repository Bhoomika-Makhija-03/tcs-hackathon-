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
from main import app


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
# 2. Validation & Input Limit Tests (Without Mocking)
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


def test_analyze_oversized_message(client):
    oversized = "A" * 10001
    response = client.post("/api/analyze", json={"sender": "test@example.com", "message": oversized})
    assert response.status_code == 422


# =====================================================================
# 3. Missing Dependencies Test (Fails Gracefully, Never Returns Safe)
# =====================================================================
def test_analyze_missing_modules_returns_503(client, monkeypatch):
    # Simulate missing modules
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
# 4. End-to-End Contract Tests with Mock Modules
# =====================================================================
def test_analyze_mock_high_risk_message(client, monkeypatch):
    """
    Simulates real detector, link_scanner, and safety modules to test
    score combination, flag deduplication, and labeling.
    """
    # Mock text analyzer (Person 2 contract)
    def mock_analyze_text(sender: str, message: str):
        return {
            "score": 55,
            "flags": [
                {
                    "category": "Urgency",
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

    # Mock link scanner (Person 3 contract)
    def mock_analyze_links(message: str):
        return {
            "score": 30,
            "flags": [
                {
                    "category": "Suspicious Link",
                    "evidence": "http://bit.ly/claim-scholarship",
                    "explanation": "Shortened or deceptive URL"
                },
                # Deliberate duplicate flag to test deduplication
                {
                    "category": "Urgency",
                    "evidence": "immediately",
                    "explanation": "Creates pressure to act quickly"
                }
            ]
        }

    # Mock safety advisor (Person 3 contract)
    def mock_get_safe_action(flags: list):
        return "Verify the announcement using official college channels."

    monkeypatch.setattr(main, "analyze_text_fn", mock_analyze_text)
    monkeypatch.setattr(main, "analyze_links_fn", mock_analyze_links)
    monkeypatch.setattr(main, "get_safe_action_fn", mock_get_safe_action)

    payload = {
        "sender": "scholarship@unknown.example",
        "message": "Pay ₹500 immediately to claim your scholarship at http://bit.ly/claim-scholarship"
    }

    response = client.post("/api/analyze", json=payload)
    assert response.status_code == 200
    data = response.json()

    # Score: 55 (text) + 30 (link) = 85 (High Risk >= 60)
    assert data["risk_score"] == 85
    assert data["label"] == "High Risk"
    assert data["safe_action"] == "Verify the announcement using official college channels."

    # Verify deduplication: 3 unique flags (Urgency appeared twice)
    assert len(data["flags"]) == 3
    categories = [f["category"] for f in data["flags"]]
    assert categories == ["Urgency", "Payment Request", "Suspicious Link"]


def test_analyze_mock_safe_message(client, monkeypatch):
    """Verifies Safe band (0-29)."""
    monkeypatch.setattr(main, "analyze_text_fn", lambda s, m: {"score": 0, "flags": []})
    monkeypatch.setattr(main, "analyze_links_fn", lambda m: {"score": 0, "flags": []})
    monkeypatch.setattr(main, "get_safe_action_fn", lambda f: "No action required. Message appears normal.")

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


def test_analyze_optional_sender(client, monkeypatch):
    """Verifies sender is optional and handles missing or empty string."""
    monkeypatch.setattr(main, "analyze_text_fn", lambda s, m: {"score": 10, "flags": []})
    monkeypatch.setattr(main, "analyze_links_fn", lambda m: {"score": 0, "flags": []})
    monkeypatch.setattr(main, "get_safe_action_fn", lambda f: "Standard verification.")

    # Omit sender completely
    response = client.post("/api/analyze", json={"message": "College orientation will begin at 10 AM."})
    assert response.status_code == 200
    assert response.json()["risk_score"] == 10
    assert response.json()["label"] == "Safe"
