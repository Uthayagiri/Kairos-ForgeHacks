"""Thread-safe Singleton Model and Artifact Loader with Stale-Model Protection.

Loads, caches, and automatically detects on-disk modifications to the trained phishing model
(phishing_model.joblib), feature column schema (feature_columns.json), and metadata (model_metadata.json).
Prevents serving stale in-memory models across live server lifecycles without requiring manual process restarts.
"""

import datetime
import hashlib
import json
import logging
import os
import threading
import time
from pathlib import Path
from typing import Any, Dict, List, Optional, Tuple

import joblib

logger = logging.getLogger(__name__)

# Default model directory pointing to backend/ml/models
DEFAULT_MODELS_DIR = Path(__file__).resolve().parents[2] / "ml" / "models"


class ModelLoader:
    """Thread-safe singleton model loader and cache manager with auto-reload protection."""

    _instance: Optional["ModelLoader"] = None
    _singleton_lock: threading.Lock = threading.Lock()

    def __init__(self, models_dir: Optional[Path] = None, check_interval_seconds: float = 0.5) -> None:
        self.models_dir = Path(models_dir or DEFAULT_MODELS_DIR)
        self.check_interval_seconds = check_interval_seconds

        self._lock = threading.RLock()
        self._model: Optional[Any] = None
        self._feature_columns: Optional[List[str]] = None
        self._metadata: Optional[Dict[str, Any]] = None

        self._model_mtime: float = 0.0
        self._model_sha256: str = ""
        self._load_timestamp: str = ""
        self._load_count: int = 0
        self._last_check_timestamp: float = 0.0
        self._initialized: bool = False

    @classmethod
    def get_instance(cls, models_dir: Optional[Path] = None) -> "ModelLoader":
        """Retrieve or create the singleton ModelLoader instance."""
        if cls._instance is None:
            with cls._singleton_lock:
                if cls._instance is None:
                    cls._instance = cls(models_dir=models_dir)
        return cls._instance

    @classmethod
    def reset(cls) -> None:
        """Reset the singleton instance (primarily used for isolated testing)."""
        with cls._singleton_lock:
            cls._instance = None

    def _compute_file_sha256(self, filepath: Path) -> str:
        """Compute SHA256 content hash of a file."""
        hasher = hashlib.sha256()
        with open(filepath, "rb") as f:
            while chunk := f.read(65536):
                hasher.update(chunk)
        return hasher.hexdigest()

    def _check_and_reload_if_stale(self) -> None:
        """Check if on-disk model artifact has changed and reload if stale."""
        now = time.monotonic()
        if self._initialized and (now - self._last_check_timestamp < self.check_interval_seconds):
            return

        self._last_check_timestamp = now
        model_path = self.models_dir / "phishing_model.joblib"

        if not model_path.exists():
            return

        try:
            current_mtime = model_path.stat().st_mtime
            if not self._initialized or current_mtime != self._model_mtime:
                self.load(force_reload=True)
        except Exception as exc:
            logger.warning("Error checking model file staleness: %s", exc)

    def load(self, force_reload: bool = False) -> Tuple[Any, List[str], Dict[str, Any]]:
        """Load or reload model artifacts from disk in a thread-safe atomic manner.

        Args:
            force_reload: If True, forces re-reading artifacts from disk even if cached.

        Returns:
            Tuple of (model, feature_columns, metadata).
        """
        with self._lock:
            model_path = self.models_dir / "phishing_model.joblib"
            columns_path = self.models_dir / "feature_columns.json"
            metadata_path = self.models_dir / "model_metadata.json"

            if not model_path.exists():
                raise FileNotFoundError(f"Model artifact not found at: {model_path}")
            if not columns_path.exists():
                raise FileNotFoundError(f"Feature columns definition not found at: {columns_path}")
            if not metadata_path.exists():
                raise FileNotFoundError(f"Model metadata not found at: {metadata_path}")

            current_mtime = model_path.stat().st_mtime

            if self._initialized and not force_reload and current_mtime == self._model_mtime:
                return self._model, self._feature_columns, self._metadata

            logger.info("Loading phishing model and artifacts from %s...", self.models_dir)

            # Atomic loading into temporary local variables first
            loaded_model = joblib.load(model_path)

            with open(columns_path, mode="r", encoding="utf-8") as f:
                loaded_columns = json.load(f)

            with open(metadata_path, mode="r", encoding="utf-8") as f:
                loaded_metadata = json.load(f)

            loaded_sha256 = self._compute_file_sha256(model_path)
            now_iso = datetime.datetime.now(datetime.timezone.utc).isoformat()

            # Atomic swap under lock
            self._model = loaded_model
            self._feature_columns = loaded_columns
            self._metadata = loaded_metadata
            self._model_mtime = current_mtime
            self._model_sha256 = loaded_sha256
            self._load_timestamp = now_iso
            self._load_count += 1
            self._initialized = True
            self._last_check_timestamp = time.monotonic()

            logger.info(
                "Model loaded successfully (Version: %s, SHA256: %s..., Load count: %d)",
                self._metadata.get("version", "unknown"),
                self._model_sha256[:12],
                self._load_count,
            )

            return self._model, self._feature_columns, self._metadata

    @property
    def model(self) -> Any:
        """Get the active model instance, verifying freshness."""
        self._check_and_reload_if_stale()
        if not self._initialized:
            self.load()
        return self._model

    @property
    def feature_columns(self) -> List[str]:
        """Get the cached feature column ordering, verifying freshness."""
        self._check_and_reload_if_stale()
        if not self._initialized:
            self.load()
        return self._feature_columns

    @property
    def metadata(self) -> Dict[str, Any]:
        """Get the cached model metadata, verifying freshness."""
        self._check_and_reload_if_stale()
        if not self._initialized:
            self.load()
        return self._metadata

    @property
    def load_count(self) -> int:
        """Return the number of times disk artifacts were loaded."""
        return self._load_count

    @property
    def sha256_hash(self) -> str:
        """Return the SHA256 content hash of the active in-memory model."""
        self._check_and_reload_if_stale()
        return self._model_sha256

    def get_status(self) -> Dict[str, Any]:
        """Retrieve structured telemetry about the active in-memory model."""
        self._check_and_reload_if_stale()
        model_path = self.models_dir / "phishing_model.joblib"
        mtime_iso = (
            datetime.datetime.fromtimestamp(self._model_mtime, tz=datetime.timezone.utc).isoformat()
            if self._model_mtime
            else None
        )
        return {
            "model_path": str(model_path.resolve()),
            "model_loaded": self._initialized,
            "sha256_hash": self._model_sha256,
            "model_version": self._metadata.get("version", "unknown") if self._metadata else "unknown",
            "model_name": self._metadata.get("model_name", "unknown") if self._metadata else "unknown",
            "algorithm": self._metadata.get("algorithm", "unknown") if self._metadata else "unknown",
            "load_count": self._load_count,
            "load_timestamp": self._load_timestamp,
            "file_mtime": mtime_iso,
            "features_count": len(self._feature_columns) if self._feature_columns else 0,
            "hyperparameters": self._metadata.get("hyperparameters", {}) if self._metadata else {},
        }


# Module-level convenience helper functions

def get_model(models_dir: Optional[Path] = None) -> Any:
    """Retrieve the active model singleton."""
    return ModelLoader.get_instance(models_dir).model


def get_feature_columns(models_dir: Optional[Path] = None) -> List[str]:
    """Retrieve the ordered feature column names."""
    return ModelLoader.get_instance(models_dir).feature_columns


def get_model_metadata(models_dir: Optional[Path] = None) -> Dict[str, Any]:
    """Retrieve the active model metadata."""
    return ModelLoader.get_instance(models_dir).metadata


def get_model_status(models_dir: Optional[Path] = None) -> Dict[str, Any]:
    """Retrieve runtime telemetry and SHA256 hash of the active model."""
    return ModelLoader.get_instance(models_dir).get_status()


def get_model_bundle(
    models_dir: Optional[Path] = None,
    force_reload: bool = False,
) -> Tuple[Any, List[str], Dict[str, Any]]:
    """Retrieve the full model bundle (model, feature_columns, metadata)."""
    return ModelLoader.get_instance(models_dir).load(force_reload=force_reload)
