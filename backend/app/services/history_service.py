"""History and Analytics Persistence Service.

Maintains recent scan records, computes aggregated security telemetry,
and provides retrieval and cleanup APIs.
"""

import datetime
import threading
from typing import Any, Dict, List, Optional


class HistoryService:
    """Thread-safe scan history and analytics manager."""

    _instance: Optional["HistoryService"] = None
    _lock = threading.Lock()

    def __init__(self, max_records: int = 200) -> None:
        self.max_records = max_records
        self._history: List[Dict[str, Any]] = []
        self._mutex = threading.Lock()

    @classmethod
    def get_instance(cls) -> "HistoryService":
        """Singleton accessor."""
        with cls._lock:
            if cls._instance is None:
                cls._instance = cls()
            return cls._instance

    def add_record(self, record: Dict[str, Any]) -> Dict[str, Any]:
        """Add a scan result record to the history buffer, redacting sensitive tokens and credentials."""
        with self._mutex:
            clean_record = dict(record)
            if "url" in clean_record and isinstance(clean_record["url"], str):
                from app.services.ssrf_guard import sanitize_url_for_logging
                clean_record["url"] = sanitize_url_for_logging(clean_record["url"])

            entry = {
                "id": f"scan_{len(self._history) + 1}_{int(datetime.datetime.now().timestamp())}",
                **clean_record,
            }
            # Prepend newest record
            self._history.insert(0, entry)
            if len(self._history) > self.max_records:
                self._history = self._history[: self.max_records]
            return entry

    def get_history(self, limit: int = 50, status_filter: Optional[str] = None) -> List[Dict[str, Any]]:
        """Retrieve historical scan records with optional status filtering."""
        with self._mutex:
            records = self._history
            if status_filter and status_filter.lower() != "all":
                records = [r for r in records if r.get("status", "").lower() == status_filter.lower()]
            return records[:limit]

    def get_stats(self) -> Dict[str, Any]:
        """Compute summary telemetry and risk distribution statistics."""
        with self._mutex:
            total = len(self._history)
            safe_count = sum(1 for r in self._history if r.get("status") == "safe")
            suspicious_count = sum(1 for r in self._history if r.get("status") == "suspicious")
            phishing_count = sum(1 for r in self._history if r.get("status") == "phishing")
            error_count = sum(1 for r in self._history if r.get("status") == "error")

            avg_latency = (
                round(sum(r.get("execution_time_ms", 0) for r in self._history) / total, 2)
                if total > 0
                else 0.0
            )
            avg_confidence = (
                round(sum(r.get("confidence", 0) for r in self._history) / total, 4)
                if total > 0
                else 0.0
            )

            return {
                "total_scans": total,
                "safe_count": safe_count,
                "suspicious_count": suspicious_count,
                "phishing_count": phishing_count,
                "error_count": error_count,
                "safe_percentage": round((safe_count / total) * 100, 1) if total > 0 else 0,
                "suspicious_percentage": round((suspicious_count / total) * 100, 1) if total > 0 else 0,
                "phishing_percentage": round((phishing_count / total) * 100, 1) if total > 0 else 0,
                "avg_latency_ms": avg_latency,
                "avg_confidence": avg_confidence,
            }

    def clear(self) -> int:
        """Clear all historical scan records."""
        with self._mutex:
            count = len(self._history)
            self._history.clear()
            return count
