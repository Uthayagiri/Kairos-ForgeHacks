import hmac
import logging
import re
import urllib.parse
from typing import Any, Dict, List, Optional

from fastapi import APIRouter, Depends, HTTPException, Query, Request, status

from app.api.schemas.predict_schemas import PredictRequest, PredictResponse
from app.core.config import get_runtime_session_token, settings
from app.services.detection_engine import DetectionEngine
from app.services.history_service import HistoryService
from app.services.ssrf_guard import sanitize_url_for_logging

logger = logging.getLogger(__name__)

router = APIRouter(tags=["Phishing Detection & Security Telemetry"])

# Reusable singleton instance of DetectionEngine across requests
_engine_instance: Optional[DetectionEngine] = None


def get_detection_engine() -> DetectionEngine:
    """Dependency provider returning the singleton DetectionEngine instance."""
    global _engine_instance
    if _engine_instance is None:
        _engine_instance = DetectionEngine()
    return _engine_instance


def get_history_service() -> HistoryService:
    """Dependency provider returning the singleton HistoryService instance."""
    return HistoryService.get_instance()


def verify_history_access(request: Request) -> None:
    """Validate that requests to scan history are authenticated and not from untrusted cross-site contexts."""
    # 1. Block cross-site browser fetches (CSRF defense)
    sec_fetch_site = request.headers.get("sec-fetch-site", "").lower()
    if sec_fetch_site in ("cross-site",):
        logger.warning("Rejected cross-site request to history endpoint: Sec-Fetch-Site=%s", sec_fetch_site)
        raise HTTPException(
            status_code=status.HTTP_403_FORBIDDEN,
            detail="Cross-site access to scan history is forbidden.",
        )

    # 2. Validate Origin if present (independent defense-in-depth)
    origin = request.headers.get("origin")
    if origin:
        normalized_origin = origin.rstrip("/")
        allowed = [o.rstrip("/") for o in settings.effective_cors_allowed_origins]
        is_allowed = normalized_origin in allowed
        if not is_allowed and settings.effective_cors_allow_origin_regex:
            is_allowed = bool(re.match(settings.effective_cors_allow_origin_regex, origin))
        if not is_allowed:
            logger.warning("Rejected forbidden origin accessing history: %s", origin)
            raise HTTPException(
                status_code=status.HTTP_403_FORBIDDEN,
                detail="Origin is not authorized to access scan history.",
            )

    # 3. Validate Referer if present and no Origin
    referer = request.headers.get("referer")
    if referer and not origin:
        try:
            ref_parsed = urllib.parse.urlsplit(referer)
            ref_origin = f"{ref_parsed.scheme}://{ref_parsed.netloc}".rstrip("/")
            allowed = [o.rstrip("/") for o in settings.effective_cors_allowed_origins]
            is_allowed = ref_origin in allowed
            if not is_allowed and settings.effective_cors_allow_origin_regex:
                is_allowed = bool(re.match(settings.effective_cors_allow_origin_regex, ref_origin))
            if not is_allowed:
                logger.warning("Rejected forbidden referer accessing history: %s", referer)
                raise HTTPException(
                    status_code=status.HTTP_403_FORBIDDEN,
                    detail="Referer origin is not authorized to access scan history.",
                )
        except Exception:
            pass

    # 4. Mandatory Authentication Check
    auth_header = request.headers.get("x-api-key") or request.headers.get("authorization")
    session_token = get_runtime_session_token()

    # In production (APP_ENV != "development") or when REQUIRE_HISTORY_AUTH is True, credentials are required.
    auth_required = settings.REQUIRE_HISTORY_AUTH or (settings.APP_ENV != "development")

    if auth_required and not auth_header:
        raise HTTPException(
            status_code=status.HTTP_401_UNAUTHORIZED,
            detail="Authentication credentials required to access scan history.",
        )

    if auth_header:
        provided = auth_header.replace("Bearer ", "").strip()
        matched = False

        if settings.HISTORY_API_KEY:
            if hmac.compare_digest(provided, settings.HISTORY_API_KEY):
                matched = True

        if session_token and hmac.compare_digest(provided, session_token):
            matched = True

        if not matched:
            raise HTTPException(
                status_code=status.HTTP_403_FORBIDDEN,
                detail="Invalid history access credentials.",
            )


@router.get(
    "/api/auth/token",
    summary="Acquire Ephemeral Dashboard Session Token",
    description="Issues an ephemeral session token for legitimate web dashboard telemetry and history operations.",
    tags=["Authentication"],
)
async def acquire_session_token(request: Request) -> Dict[str, Any]:
    """Issue active runtime session token to authorized origins."""
    sec_fetch_site = request.headers.get("sec-fetch-site", "").lower()
    if sec_fetch_site == "cross-site":
        logger.warning("Rejected cross-site request to acquire session token: Sec-Fetch-Site=%s", sec_fetch_site)
        raise HTTPException(
            status_code=status.HTTP_403_FORBIDDEN,
            detail="Cross-site requests cannot acquire session tokens.",
        )

    origin = request.headers.get("origin")
    if origin:
        normalized_origin = origin.rstrip("/")
        allowed = [o.rstrip("/") for o in settings.effective_cors_allowed_origins]
        is_allowed = normalized_origin in allowed
        if not is_allowed and settings.effective_cors_allow_origin_regex:
            is_allowed = bool(re.match(settings.effective_cors_allow_origin_regex, origin))
        if not is_allowed:
            logger.warning("Rejected forbidden origin requesting session token: %s", origin)
            raise HTTPException(
                status_code=status.HTTP_403_FORBIDDEN,
                detail="Origin is not authorized to acquire session tokens.",
            )

    return {
        "status": "authenticated",
        "token": get_runtime_session_token(),
        "token_type": "Bearer",
    }



@router.post(
    "/predict",
    response_model=PredictResponse,
    status_code=status.HTTP_200_OK,
    summary="Analyze URL for Phishing",
    description="Analyzes URL structure, SSRF safety, live DOM, and XGBoost classification.",
)
@router.post(
    "/api/analyze",
    response_model=PredictResponse,
    status_code=status.HTTP_200_OK,
    summary="Analyze URL for Phishing (API v1)",
    description="Unified phishing analysis endpoint providing categorized signals, risk score (0-100), and recommended actions.",
)
@router.post(
    "/api/predict",
    response_model=PredictResponse,
    status_code=status.HTTP_200_OK,
    summary="Analyze URL for Phishing (API Alias)",
    description="Alias endpoint for browser extension and web clients.",
)
async def predict_url(
    payload: PredictRequest,
    engine: DetectionEngine = Depends(get_detection_engine),
) -> PredictResponse:
    """Analyze a single URL for phishing characteristics."""
    try:
        fetch_flag = True if payload.fetch_html is None else payload.fetch_html
        result = await engine.analyze_url_async(
            url=payload.url,
            fetch_html=fetch_flag,
            html_content=payload.html_content,
        )
        return PredictResponse(**result.to_dict())

    except Exception as exc:
        safe_log_url = sanitize_url_for_logging(payload.url)
        logger.exception("Unexpected error during URL prediction for '%s': %s", safe_log_url, exc)
        raise HTTPException(
            status_code=status.HTTP_500_INTERNAL_SERVER_ERROR,
            detail="An internal server error occurred while analyzing the URL.",
        )


@router.get(
    "/api/history",
    summary="Get Scan History",
    description="Retrieve recent scan records with optional status filtering.",
    response_model=List[Dict[str, Any]],
    dependencies=[Depends(verify_history_access)],
)
async def get_history(
    limit: int = Query(default=50, ge=1, le=200),
    status: Optional[str] = Query(default=None, description="Filter by status: safe, suspicious, phishing"),
    history_svc: HistoryService = Depends(get_history_service),
) -> List[Dict[str, Any]]:
    """Retrieve historical scans."""
    return history_svc.get_history(limit=limit, status_filter=status)


@router.post(
    "/api/history/clear",
    summary="Clear Scan History",
    description="Purge all persisted scan records from the server session.",
    dependencies=[Depends(verify_history_access)],
)
async def clear_history(
    history_svc: HistoryService = Depends(get_history_service),
) -> Dict[str, Any]:
    """Clear all scan records."""
    count = history_svc.clear()
    return {"status": "cleared", "records_removed": count}


@router.get(
    "/api/stats",
    summary="Security Telemetry Statistics",
    description="Returns aggregate scan counts, risk distribution percentages, and latency metrics.",
    dependencies=[Depends(verify_history_access)],
)
async def get_stats(
    history_svc: HistoryService = Depends(get_history_service),
) -> Dict[str, Any]:
    """Return summary security analytics."""
    return history_svc.get_stats()


@router.get(
    "/api/health",
    summary="API Health Status",
    description="Verifies API and ML engine responsiveness.",
)
async def api_health() -> Dict[str, Any]:
    """API health check."""
    return {
        "status": "ok",
        "service": "PhishGuard AI Engine",
        "model": "XGBoost v1.2",
    }
