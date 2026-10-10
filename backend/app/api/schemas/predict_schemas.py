"""Pydantic schemas for phishing detection API endpoints."""

from typing import Any, Dict, List, Optional
from pydantic import BaseModel, ConfigDict, Field


class PredictRequest(BaseModel):
    """Request payload for URL phishing prediction."""

    url: str = Field(
        ...,
        max_length=2048,
        description="Webpage URL to analyze for phishing risks (e.g. https://example.com).",
        examples=["https://example.com"],
    )
    html_content: Optional[str] = Field(
        default=None,
        description="Optional pre-fetched or client-rendered HTML content for offline or in-browser DOM analysis.",
    )
    fetch_html: Optional[bool] = Field(
        default=True,
        description="Whether the backend should attempt live HTTP fetching if html_content is omitted.",
    )

    model_config = ConfigDict(
        json_schema_extra={
            "example": {
                "url": "https://example.com",
            }
        }
    )


class PredictResponse(BaseModel):
    """Response payload returned by the phishing prediction endpoint."""

    url: str = Field(
        ...,
        description="Normalized URL that was analyzed.",
        examples=["https://example.com"],
    )
    status: str = Field(
        ...,
        description="Analysis verdict status: 'safe', 'suspicious', 'phishing', or 'error'.",
        examples=["safe"],
    )
    confidence: float = Field(
        ...,
        description="Phishing probability score ranging from 0.0 (benign) to 1.0 (phishing).",
        examples=[0.024],
    )
    risk_level: str = Field(
        ...,
        description="Categorical risk assessment: 'low', 'medium', 'high', or 'unknown'.",
        examples=["low"],
    )
    is_phishing: bool = Field(
        ...,
        description="Boolean flag indicating whether the URL is classified as phishing.",
        examples=[False],
    )
    html_available: bool = Field(
        ...,
        description="Whether live HTML content was successfully retrieved and analyzed.",
        examples=[True],
    )
    detected_indicators: List[str] = Field(
        default_factory=list,
        description="Human-readable explanations and risk factors detected during analysis.",
        examples=[["Valid HTTPS certificate verified.", "Legitimate anchor link ratio (85.2%)."]],
    )
    url_features_summary: Dict[str, Any] = Field(
        default_factory=dict,
        description="Key structural URL signals extracted for transparency.",
        examples=[{
            "uses_https": True,
            "domain_length": 11,
            "path_length": 0,
            "num_subdomains": 0,
            "has_ip_address": False,
            "has_suspicious_tld": False,
            "has_suspicious_keywords": False,
        }],
    )
    error_message: Optional[str] = Field(
        default=None,
        description="Diagnostic error description if analysis could not be completed or URL was invalid.",
        examples=[None],
    )
    analysis_timestamp: str = Field(
        ...,
        description="ISO 8601 UTC timestamp of when the analysis was performed.",
        examples=["2026-09-07T10:30:00+00:00"],
    )
    execution_time_ms: float = Field(
        default=0.0,
        description="End-to-end execution time in milliseconds.",
        examples=[125.4],
    )
    content_rendering_incomplete: bool = Field(
        default=False,
        description="Whether live HTML analysis was incomplete due to client-side JS rendering (SPA shell).",
        examples=[False],
    )
    risk_score: float = Field(
        default=0.0,
        description="Normalized risk score on a 0 to 100 scale.",
        examples=[2.4],
    )
    recommended_action: str = Field(
        default="Safe to proceed with normal browsing.",
        description="Actionable security recommendation for the user.",
        examples=["Safe to proceed with normal browsing."],
    )
    model_version: str = Field(
        default="v1.2-xgboost-calibrated",
        description="Active machine learning model artifact identifier.",
        examples=["v1.2-xgboost-calibrated"],
    )
    signals_breakdown: Optional[Dict[str, Any]] = Field(
        default_factory=dict,
        description="Categorized breakdown across URL lexical, domain/reputation, and DOM signals.",
        examples=[{
            "url_signals": {"https": True, "clean_domain": True},
            "domain_signals": {"reputation": "neutral_to_safe"},
            "html_signals": {"forms": 1, "password_fields": 0}
        }],
    )

    model_config = ConfigDict(
        json_schema_extra={
            "example": {
                "url": "https://example.com",
                "status": "safe",
                "confidence": 0.024,
                "risk_level": "low",
                "is_phishing": False,
                "html_available": True,
                "detected_indicators": [
                    "Valid HTTPS connection established.",
                    "Clean domain structure without deceptive homoglyphs or keywords.",
                ],
                "url_features_summary": {
                    "uses_https": True,
                    "domain_length": 11,
                    "path_length": 0,
                    "num_subdomains": 0,
                    "has_ip_address": False,
                    "has_suspicious_tld": False,
                    "has_suspicious_keywords": False,
                },
                "error_message": None,
                "analysis_timestamp": "2026-09-07T10:30:00+00:00",
                "execution_time_ms": 125.4,
            }
        }
    )
