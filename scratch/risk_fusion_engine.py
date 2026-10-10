"""Risk-Fusion Engine for Candidate Exp 5 (Isolated Controlled Experiment).

Applies out-of-band apex domain registration recency escalation exclusively
to ambiguous predictions (0.35 <= p_base <= 0.70) with strict 800ms RDAP timeout
and fail-neutral fallback (delta = 0.00).
"""

import datetime
import json
import logging
import time
from pathlib import Path
from typing import Any, Dict, Optional, Tuple
from urllib.parse import urlparse
import requests

# Experiment Log File
EXP_LOG_DIR = Path("c:/Users/Udhaya/S5_Phishing_Detector/scratch").resolve()
EXP_LOG_FILE = EXP_LOG_DIR / "exp5_escalation_events.log"

logger = logging.getLogger("phishguard.exp5_fusion")

def extract_apex_domain(url: str) -> str:
    """Extract registered domain (2-level or multi-part ccTLD apex)."""
    try:
        if not (url.startswith("http://") or url.startswith("https://")):
            url = "http://" + url
        parsed = urlparse(url)
        host = (parsed.netloc or "").lower().strip()
        if ":" in host:
            host = host.split(":")[0]
        if host.startswith("www."):
            host = host[4:]
        
        parts = host.split(".")
        if len(parts) <= 2:
            return host
        
        two_part_tlds = {
            "co.uk", "ac.uk", "gov.uk", "ac.in", "gov.in", "co.in", "edu.in",
            "com.au", "net.au", "co.jp", "com.br", "co.za"
        }
        last_two = f"{parts[-2]}.{parts[-1]}"
        if last_two in two_part_tlds and len(parts) >= 3:
            return f"{parts[-3]}.{last_two}"
        
        return f"{parts[-2]}.{parts[-1]}"
    except Exception:
        return url


def query_rdap_domain_age(
    apex_domain: str,
    timeout_seconds: float = 0.8,
    rdap_base_url: str = "https://rdap.org/domain/"
) -> Tuple[Optional[float], str, float]:
    """Query RDAP REST API for domain registration age in days with strict timeout.
    
    Returns:
        (age_days, status_string, query_latency_ms)
    """
    t0 = time.perf_counter()
    if not apex_domain or "." not in apex_domain:
        lat = (time.perf_counter() - t0) * 1000.0
        return None, "invalid_domain", round(lat, 2)
    
    try:
        url = f"{rdap_base_url.rstrip('/')}/{apex_domain}"
        headers = {
            "Accept": "application/rdap+json",
            "User-Agent": "PhishGuard-Exp5-Auditor/1.0"
        }
        resp = requests.get(url, timeout=timeout_seconds, headers=headers)
        lat = (time.perf_counter() - t0) * 1000.0
        
        if resp.status_code == 200:
            data = resp.json()
            events = data.get("events", [])
            for ev in events:
                if ev.get("eventAction") == "registration":
                    dt_str = ev.get("eventDate", "")
                    if dt_str:
                        dt_clean = dt_str.replace("Z", "+00:00")[:19]
                        dt_reg = datetime.datetime.fromisoformat(dt_clean).replace(tzinfo=datetime.timezone.utc)
                        now = datetime.datetime.now(datetime.timezone.utc)
                        age_days = (now - dt_reg).total_seconds() / 86400.0
                        return round(max(0.0, age_days), 2), "success", round(lat, 2)
            return None, "no_registration_event", round(lat, 2)
        elif resp.status_code == 429:
            return None, "http_429_rate_limit", round(lat, 2)
        elif resp.status_code == 404:
            return None, "http_404_not_found", round(lat, 2)
        else:
            return None, f"http_{resp.status_code}", round(lat, 2)
    except requests.exceptions.Timeout:
        lat = (time.perf_counter() - t0) * 1000.0
        return None, "timeout_exceeded", round(lat, 2)
    except requests.exceptions.RequestException as e:
        lat = (time.perf_counter() - t0) * 1000.0
        return None, f"network_error: {type(e).__name__}", round(lat, 2)
    except Exception as e:
        lat = (time.perf_counter() - t0) * 1000.0
        return None, f"error: {str(e)[:30]}", round(lat, 2)


class CandidateExp5RiskFusion:
    """Out-of-band risk fusion post-processor."""
    
    def __init__(
        self,
        ambiguous_low: float = 0.35,
        ambiguous_high: float = 0.70,
        age_threshold_days: float = 14.0,
        recency_delta: float = 0.05,
        timeout_seconds: float = 0.8,
        log_to_file: bool = True
    ):
        self.ambiguous_low = ambiguous_low
        self.ambiguous_high = ambiguous_high
        self.age_threshold_days = age_threshold_days
        self.recency_delta = recency_delta
        self.timeout_seconds = timeout_seconds
        self.log_to_file = log_to_file

    def apply_fusion(
        self,
        url: str,
        p_base: float,
        simulated_rdap_result: Optional[Tuple[Optional[float], str, float]] = None
    ) -> Dict[str, Any]:
        """Apply the risk-fusion rule to a base probability score."""
        p_base = float(np.clip(p_base, 0.0, 1.0)) if "np" in globals() else max(0.0, min(1.0, float(p_base)))
        apex = extract_apex_domain(url)
        
        # 1. Check if score is outside ambiguous band
        if p_base < self.ambiguous_low or p_base > self.ambiguous_high:
            return {
                "url": url,
                "domain": apex,
                "p_base": round(p_base, 4),
                "p_final": round(p_base, 4),
                "delta": 0.00,
                "is_ambiguous": False,
                "infrastructure_status": "skipped_high_confidence",
                "rdap_age_days": None,
                "rdap_status": "skipped",
                "fusion_latency_ms": 0.0
            }
        
        # 2. Inside ambiguous band: trigger out-of-band RDAP query
        if simulated_rdap_result is not None:
            age_days, rdap_status, lat_ms = simulated_rdap_result
        else:
            age_days, rdap_status, lat_ms = query_rdap_domain_age(apex, timeout_seconds=self.timeout_seconds)
            
        delta = 0.00
        infra_status = "unavailable_degraded"
        
        if rdap_status == "success" and age_days is not None:
            if age_days < self.age_threshold_days:
                delta = self.recency_delta
                infra_status = "escalated_young_domain"
            else:
                delta = 0.00
                infra_status = "evaluated_aged_domain"
        else:
            # Strict Fail-Neutral Fallback: delta = 0.00 on any failure/timeout/missing event
            delta = 0.00
            infra_status = "unavailable_degraded"
            
        p_final = max(0.0, min(1.0, p_base + delta))
        
        record = {
            "url": url,
            "domain": apex,
            "p_base": round(p_base, 4),
            "p_final": round(p_final, 4),
            "delta": round(delta, 4),
            "is_ambiguous": True,
            "infrastructure_status": infra_status,
            "rdap_age_days": age_days,
            "rdap_status": rdap_status,
            "fusion_latency_ms": round(lat_ms, 2)
        }
        
        if self.log_to_file:
            self._log_event(record)
            
        return record

    def _log_event(self, record: Dict[str, Any]):
        """Append escalation log event to separate experiment log file."""
        try:
            record_copy = dict(record)
            record_copy["timestamp"] = datetime.datetime.now(datetime.timezone.utc).isoformat()
            with open(EXP_LOG_FILE, "a", encoding="utf-8") as f:
                f.write(json.dumps(record_copy) + "\n")
        except Exception:
            pass
