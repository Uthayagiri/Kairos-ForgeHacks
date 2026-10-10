import secrets
from typing import List, Optional
from pydantic_settings import BaseSettings, SettingsConfigDict


_RUNTIME_SESSION_TOKEN: str = secrets.token_urlsafe(32)


def get_runtime_session_token() -> str:
    """Return the active server runtime session token generated on process startup."""
    global _RUNTIME_SESSION_TOKEN
    return _RUNTIME_SESSION_TOKEN


def rotate_runtime_session_token() -> str:
    """Generate and store a fresh server runtime session token (useful for test resets)."""
    global _RUNTIME_SESSION_TOKEN
    _RUNTIME_SESSION_TOKEN = secrets.token_urlsafe(32)
    return _RUNTIME_SESSION_TOKEN


class Settings(BaseSettings):
    APP_NAME: str = "Phishing Detection API"
    APP_ENV: str = "development"
    DEBUG: bool = True
    HOST: str = "127.0.0.1"
    PORT: int = 8000
    MODEL_PATH: str = "ml/models/phishing_model.pkl"

    # CORS configuration: strict explicit origins
    CORS_ALLOWED_ORIGINS: List[str] = [
        "http://localhost:5173",
        "http://127.0.0.1:5173",
        "http://localhost:3000",
        "http://127.0.0.1:3000",
    ]

    # Explicit allowlist of permitted browser extension IDs (e.g. 32-character Chromium IDs)
    # In production, operators MUST configure the published extension ID.
    ALLOWED_EXTENSION_IDS: List[str] = []

    # Development-only extension origin matching toggle:
    # When True and APP_ENV == "development", allows unpacked extensions matching standard 32-letter IDs.
    # In production (APP_ENV != "development"), unpacked matching is strictly disabled.
    ALLOW_DEV_EXTENSION_ORIGINS: bool = True

    # Scan history access control
    REQUIRE_HISTORY_AUTH: bool = False
    HISTORY_API_KEY: Optional[str] = None

    @property
    def effective_cors_allow_origin_regex(self) -> Optional[str]:
        """Compute the effective regex for CORS origins.

        In development with ALLOW_DEV_EXTENSION_ORIGINS enabled, allows standard 32-letter
        unpacked Chromium extension origins. In production, returns None to forbid unlisted extensions.
        """
        if self.APP_ENV == "development" and self.ALLOW_DEV_EXTENSION_ORIGINS:
            return r"^chrome-extension://[a-z]{32}$"
        return None

    @property
    def effective_cors_allowed_origins(self) -> List[str]:
        """Compute all permitted CORS origins including configured extension IDs."""
        origins = list(self.CORS_ALLOWED_ORIGINS)
        for ext_id in self.ALLOWED_EXTENSION_IDS:
            clean_id = ext_id.strip()
            if clean_id:
                origins.append(f"chrome-extension://{clean_id}")
                origins.append(f"moz-extension://{clean_id}")
        return origins

    @property
    def CORS_ALLOW_ORIGIN_REGEX(self) -> Optional[str]:
        """Backward-compatibility alias pointing to effective regex."""
        return self.effective_cors_allow_origin_regex

    model_config = SettingsConfigDict(
        env_file=".env",
        env_file_encoding="utf-8",
        extra="ignore",
    )


settings = Settings()


