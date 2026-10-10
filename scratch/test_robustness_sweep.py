"""Part D: Robustness Sweep Test Suite.

Tests API defenses against adversarial inputs, malformed payloads,
deeply nested JSON, unexpected content-types, and moderate concurrent load (30 requests).
"""

import concurrent.futures
import json
import time
import requests

BASE_URL = "http://127.0.0.1:8000"

def test_malformed_and_adversarial():
    print("==================================================")
    print("1. TESTING ADVERSARIAL & MALFORMED REQUESTS")
    print("==================================================")

    # 1.1 Deeply nested JSON payload
    deep_json = {"url": {"a": {"b": {"c": {"d": {"e": "invalid"}}}}}}
    r = requests.post(f"{BASE_URL}/predict", json=deep_json, timeout=5)
    print(f"Deeply nested JSON -> HTTP {r.status_code} (Expected 422)")
    assert r.status_code == 422

    # 1.2 Integer URL payload
    r = requests.post(f"{BASE_URL}/predict", json={"url": 123456}, timeout=5)
    print(f"Integer URL payload -> HTTP {r.status_code} (Expected 422)")
    assert r.status_code == 422

    # 1.3 Null URL payload
    r = requests.post(f"{BASE_URL}/predict", json={"url": None}, timeout=5)
    print(f"Null URL payload -> HTTP {r.status_code} (Expected 422)")
    assert r.status_code == 422

    # 1.4 Missing URL field (empty object)
    r = requests.post(f"{BASE_URL}/predict", json={}, timeout=5)
    print(f"Missing URL field -> HTTP {r.status_code} (Expected 422)")
    assert r.status_code == 422

    # 1.5 Unexpected Content-Type (text/plain)
    r = requests.post(
        f"{BASE_URL}/predict",
        data="https://example.com",
        headers={"Content-Type": "text/plain"},
        timeout=5,
    )
    print(f"Unexpected Content-Type text/plain -> HTTP {r.status_code} (Expected 422)")
    assert r.status_code == 422

    # 1.6 Garbage binary payload
    r = requests.post(
        f"{BASE_URL}/predict",
        data=b"\x00\x01\x02\x03\xff\xfe",
        headers={"Content-Type": "application/json"},
        timeout=5,
    )
    print(f"Garbage binary JSON -> HTTP {r.status_code} (Expected 422)")
    assert r.status_code == 422

    # 1.7 SQL Injection payload in URL
    sqli_url = "https://example.com/login?user=' OR '1'='1' --"
    r = requests.post(f"{BASE_URL}/predict", json={"url": sqli_url}, timeout=10)
    print(f"SQLi string in URL -> HTTP {r.status_code}, status={r.json().get('status')}")
    assert r.status_code == 200

    # 1.8 XSS script payload in URL
    xss_url = "https://example.com/search?q=<script>alert('xss')</script>"
    r = requests.post(f"{BASE_URL}/predict", json={"url": xss_url}, timeout=10)
    print(f"XSS string in URL -> HTTP {r.status_code}, status={r.json().get('status')}")
    assert r.status_code == 200

    print("[PASS] All adversarial and malformed requests handled safely without crashes.")

def test_concurrent_load(num_requests=30):
    print("\n==================================================")
    print(f"2. TESTING CONCURRENT BURST LOAD ({num_requests} concurrent requests)")
    print("==================================================")

    urls = [
        "https://example.com",
        "https://en.wikipedia.org",
        "http://192.168.1.100/paypal/login.php",
        "https://ps.bitsathy.ac.in",
        "https://news.ycombinator.com",
        "https://github.com",
    ]

    def send_req(i):
        target = urls[i % len(urls)]
        t0 = time.perf_counter()
        try:
            res = requests.post(f"{BASE_URL}/predict", json={"url": target}, timeout=15)
            elapsed = (time.perf_counter() - t0) * 1000.0
            return {
                "id": i,
                "target": target,
                "status_code": res.status_code,
                "elapsed_ms": elapsed,
                "ok": res.status_code == 200,
                "verdict": res.json().get("status") if res.status_code == 200 else None,
            }
        except Exception as e:
            return {
                "id": i,
                "target": target,
                "status_code": 0,
                "elapsed_ms": 0,
                "ok": False,
                "error": str(e),
            }

    t_start = time.perf_counter()
    with concurrent.futures.ThreadPoolExecutor(max_workers=10) as executor:
        futures = [executor.submit(send_req, i) for i in range(num_requests)]
        results = [f.result() for f in concurrent.futures.as_completed(futures)]
    total_time = time.perf_counter() - t_start

    success_count = sum(1 for r in results if r["ok"])
    print(f"Total Completed: {len(results)} in {total_time:.2f}s")
    print(f"Success Rate: {success_count}/{num_requests} ({success_count/num_requests*100:.1f}%)")

    latencies = [r["elapsed_ms"] for r in results if r["ok"]]
    if latencies:
        avg_lat = sum(latencies) / len(latencies)
        min_lat = min(latencies)
        max_lat = max(latencies)
        print(f"Latency: Avg={avg_lat:.1f}ms | Min={min_lat:.1f}ms | Max={max_lat:.1f}ms")

    assert success_count == num_requests, f"Expected all {num_requests} to succeed, got {success_count}"
    print("[PASS] Concurrent burst load test passed with 100% success rate.")

def test_server_health():
    print("\n==================================================")
    print("3. TESTING SERVER HEALTH POST-LOAD")
    print("==================================================")
    r = requests.get(f"{BASE_URL}/health", timeout=5)
    print(f"Health status: {r.status_code} -> {r.json()}")
    assert r.status_code == 200
    assert r.json() == {"status": "ok"}
    print("[PASS] Server remains healthy and operational.")

if __name__ == "__main__":
    test_malformed_and_adversarial()
    test_concurrent_load(30)
    test_server_health()
