"""FastAPI Main Application Entrypoint.

Exposes REST API endpoints for the AI-Based Phishing Website Detection system.
Provides live health checks, interactive documentation (/docs, /redoc),
request timing middleware, and URL phishing risk prediction routes.
"""

import logging
import time
from contextlib import asynccontextmanager

from fastapi import FastAPI, Request, Response
from fastapi.middleware.cors import CORSMiddleware

from app.api import predict_router
from app.core.config import settings
from app.core.model_loader import ModelLoader

# Configure standard application logging
logging.basicConfig(
    level=logging.INFO,
    format="%(asctime)s [%(levelname)s] %(name)s: %(message)s",
)
logger = logging.getLogger("phishing_detector.api")


@asynccontextmanager
async def lifespan(app: FastAPI):
    """Lifespan context manager to pre-warm singletons on application startup."""
    logger.info("Initializing Phishing Detector API backend...")
    try:
        loader = ModelLoader.get_instance()
        loader.load()
        logger.info("Model singleton loaded successfully on startup.")
    except Exception as exc:
        logger.warning("Model could not be pre-loaded on startup (will load on first request): %s", exc)
    yield
    logger.info("Shutting down Phishing Detector API backend.")


app = FastAPI(
    title=settings.APP_NAME,
    description=(
        "AI-Based Phishing Website Detection API using multi-stage feature extraction "
        "(URL structural signals + live HTML DOM inspection) and XGBoost classification."
    ),
    version="0.1.0",
    lifespan=lifespan,
    docs_url="/docs",
    redoc_url="/redoc",
)

import re

# -----------------------------------------------------------------------------
# CORS Middleware Configuration:
# Restricted explicitly to approved frontend web dashboards (localhost:5173, localhost:3000)
# and explicitly configured Chromium browser extension IDs.
# -----------------------------------------------------------------------------
class DynamicCORSMiddleware(CORSMiddleware):
    """CORS Middleware that dynamically evaluates origin allowlists against active settings."""

    def is_allowed_origin(self, origin: str) -> bool:
        regex_str = settings.effective_cors_allow_origin_regex
        if regex_str and re.fullmatch(regex_str, origin):
            return True
        return origin in settings.effective_cors_allowed_origins


app.add_middleware(
    DynamicCORSMiddleware,
    allow_origins=settings.effective_cors_allowed_origins,
    allow_origin_regex=settings.effective_cors_allow_origin_regex,
    allow_credentials=False,
    allow_methods=["GET", "POST", "OPTIONS"],
    allow_headers=["*"],
)


@app.middleware("http")
async def log_requests_middleware(request: Request, call_next) -> Response:
    """Log incoming HTTP request method, path, response status, and processing duration."""
    start_time = time.perf_counter()
    response = await call_next(request)
    duration_ms = (time.perf_counter() - start_time) * 1000.0

    logger.info(
        "%s %s -> HTTP %d (%.2f ms)",
        request.method,
        request.url.path,
        response.status_code,
        duration_ms,
    )
    return response


# Include API Routers
app.include_router(predict_router)


@app.get(
    "/",
    summary="API Root Information",
    description="Returns top-level metadata, API status, and links to interactive OpenAPI documentation.",
    tags=["General"],
)
async def root():
    """Root endpoint returning basic API metadata and documentation links."""
    return {
        "name": settings.APP_NAME,
        "version": "0.1.0",
        "status": "running",
        "docs_url": "/docs",
        "redoc_url": "/redoc",
    }


@app.get(
    "/health",
    summary="Health Check",
    description="Verifies the API server is up, healthy, and capable of receiving requests.",
    tags=["General"],
)
async def health_check():
    """Health check endpoint confirming service operational status."""
    return {"status": "ok"}


@app.get(
    "/model/info",
    summary="Active Model Telemetry",
    description="Returns detailed telemetry, SHA256 hash, version, and load timestamp of the currently running model artifact.",
    tags=["Model Telemetry"],
)
async def get_model_telemetry():
    """Return runtime metadata and SHA256 integrity hash of the active model."""
    loader = ModelLoader.get_instance()
    return loader.get_status()


