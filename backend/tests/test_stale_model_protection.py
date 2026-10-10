"""Automated Verification Suite for Stale-Model Detection and Thread-Safe Reloading.

Validates that ModelLoader:
1. Automatically detects on-disk artifact changes and reloads without process restart.
2. Caches cleanly when files are unmodified (no redundant I/O).
3. Safely handles concurrent inference requests during a live model reload without race conditions.
4. Correctly exposes model artifact SHA-256 telemetry via get_status() and HTTP API endpoints.
"""

import concurrent.futures
import json
import shutil
import time
from pathlib import Path

import joblib
import pytest
from fastapi.testclient import TestClient

from app.core.model_loader import ModelLoader, get_model, get_model_status
from app.main import app

client = TestClient(app)


@pytest.fixture
def temp_models_dir(tmp_path: Path):
    """Create a temporary directory containing valid initial dummy model artifacts."""
    source_dir = Path(__file__).resolve().parents[1] / "ml" / "models"

    shutil.copy(source_dir / "phishing_model.joblib", tmp_path / "phishing_model.joblib")
    shutil.copy(source_dir / "feature_columns.json", tmp_path / "feature_columns.json")
    shutil.copy(source_dir / "model_metadata.json", tmp_path / "model_metadata.json")

    return tmp_path


def test_model_loader_stale_detection(temp_models_dir: Path):
    """Verify ModelLoader automatically detects when model artifact on disk is replaced."""
    loader = ModelLoader(models_dir=temp_models_dir, check_interval_seconds=0.01)
    
    # 1. Initial Load
    m1 = loader.model
    status1 = loader.get_status()
    initial_hash = status1["sha256_hash"]
    initial_count = loader.load_count

    assert m1 is not None
    assert initial_count == 1
    assert len(initial_hash) == 64

    # 2. Subsequent access without disk change must NOT reload
    time.sleep(0.05)
    m2 = loader.model
    assert m2 is m1
    assert loader.load_count == 1

    # 3. Simulate on-disk model update with legacy model
    legacy_model_path = Path(__file__).resolve().parents[1] / "ml" / "models" / "legacy_v1" / "phishing_model_v1.joblib"
    shutil.copy(legacy_model_path, temp_models_dir / "phishing_model.joblib")
    
    # Touch mtime to ensure filesystem timestamp difference
    new_mtime = time.time() + 10.0
    import os
    os.utime(temp_models_dir / "phishing_model.joblib", (new_mtime, new_mtime))

    time.sleep(0.05)

    # 4. Accessing .model must trigger auto-reload
    m3 = loader.model
    status2 = loader.get_status()
    new_hash = status2["sha256_hash"]

    assert loader.load_count == 2
    assert new_hash != initial_hash
    assert status2["sha256_hash"] == new_hash


def test_model_loader_concurrent_thread_safety(temp_models_dir: Path):
    """Verify concurrent requests during an active model reload never fail or observe broken state."""
    loader = ModelLoader(models_dir=temp_models_dir, check_interval_seconds=0.0)
    _ = loader.model

    errors = []
    models_seen = []

    def reader_worker():
        for _ in range(50):
            try:
                m = loader.model
                cols = loader.feature_columns
                meta = loader.metadata
                assert m is not None
                assert len(cols) == 43
                assert meta is not None
                models_seen.append(loader.sha256_hash)
            except Exception as e:
                errors.append(e)
            time.sleep(0.001)

    def writer_worker():
        for _ in range(5):
            time.sleep(0.01)
            # Toggle between prod and legacy models
            legacy_path = Path(__file__).resolve().parents[1] / "ml" / "models" / "legacy_v1" / "phishing_model_v1.joblib"
            shutil.copy(legacy_path, temp_models_dir / "phishing_model.joblib")
            import os
            os.utime(temp_models_dir / "phishing_model.joblib", None)

    with concurrent.futures.ThreadPoolExecutor(max_workers=8) as executor:
        futures = [executor.submit(reader_worker) for _ in range(6)]
        futures.append(executor.submit(writer_worker))
        concurrent.futures.wait(futures)

    assert len(errors) == 0, f"Concurrent read/write encountered errors: {errors}"
    assert len(models_seen) > 0


def test_api_health_and_model_info_endpoints():
    """Verify /health and /model/info return active model hash and runtime telemetry."""
    # Health endpoint
    resp = client.get("/health")
    assert resp.status_code == 200
    data = resp.json()
    assert data == {"status": "ok"}

    # Dedicated /model/info endpoint
    resp2 = client.get("/model/info")
    assert resp2.status_code == 200
    telemetry = resp2.json()
    assert "sha256_hash" in telemetry
    assert len(telemetry["sha256_hash"]) == 64
    assert "model_version" in telemetry
    assert "load_count" in telemetry
    assert telemetry["model_loaded"] is True
    assert telemetry["load_count"] >= 1

