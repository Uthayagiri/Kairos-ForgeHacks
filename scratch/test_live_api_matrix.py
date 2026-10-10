"""Live API Integration Verification for Matrix Items 1, 2, 3, 4, 6, 7, 8."""

import json
import time
import requests

BASE_URL = "http://127.0.0.1:8000"

def test_api_matrix():
    print("==================================================")
    print("1. TESTING SAFE URL: https://en.wikipedia.org")
    print("==================================================")
    t0 = time.perf_counter()
    r_safe = requests.post(f"{BASE_URL}/predict", json={"url": "https://en.wikipedia.org"}, timeout=15)
    t1 = time.perf_counter()
    safe_data = r_safe.json()
    print(f"Status: {r_safe.status_code}, Elapsed: {t1-t0:.2f}s")
    print(json.dumps(safe_data, indent=2))
    assert r_safe.status_code == 200
    assert safe_data["status"] == "safe"
    assert safe_data["risk_level"] == "low"
    assert safe_data["is_phishing"] is False

    print("\n==================================================")
    print("2. TESTING PHISHING URL: http://192.168.1.100/paypal/login.php")
    print("==================================================")
    t0 = time.perf_counter()
    r_phish = requests.post(f"{BASE_URL}/predict", json={"url": "http://192.168.1.100/paypal/login.php"}, timeout=15)
    t1 = time.perf_counter()
    phish_data = r_phish.json()
    print(f"Status: {r_phish.status_code}, Elapsed: {t1-t0:.2f}s")
    print(json.dumps(phish_data, indent=2))
    assert r_phish.status_code == 200
    assert phish_data["status"] == "phishing"
    assert phish_data["risk_level"] == "high"
    assert phish_data["is_phishing"] is True

    print("\n==================================================")
    print("3. TESTING SPA URL: https://ps.bitsathy.ac.in")
    print("==================================================")
    t0 = time.perf_counter()
    r_spa = requests.post(f"{BASE_URL}/predict", json={"url": "https://ps.bitsathy.ac.in"}, timeout=15)
    t1 = time.perf_counter()
    spa_data = r_spa.json()
    print(f"Status: {r_spa.status_code}, Elapsed: {t1-t0:.2f}s")
    print(json.dumps(spa_data, indent=2))
    assert r_spa.status_code == 200
    assert spa_data["status"] in ("suspicious", "safe")
    assert spa_data["risk_level"] in ("medium", "low")
    assert spa_data["is_phishing"] is False
    print("Checking content_rendering_incomplete in response:")
    print("content_rendering_incomplete key present?", "content_rendering_incomplete" in spa_data)
    if "content_rendering_incomplete" in spa_data:
        print("content_rendering_incomplete value:", spa_data["content_rendering_incomplete"])

    print("\n==================================================")
    print("4. TESTING ERROR / INVALID URLS")
    print("==================================================")
    r_empty = requests.post(f"{BASE_URL}/predict", json={"url": ""}, timeout=15)
    print("Empty URL status:", r_empty.status_code, r_empty.json())
    assert r_empty.status_code == 200
    assert r_empty.json()["status"] == "error"

    r_scheme = requests.post(f"{BASE_URL}/predict", json={"url": "javascript:alert(1)"}, timeout=15)
    print("Javascript scheme status:", r_scheme.status_code, r_scheme.json())
    assert r_scheme.status_code == 200
    assert r_scheme.json()["status"] == "error"

    r_oversized = requests.post(f"{BASE_URL}/predict", json={"url": "https://example.com/" + "a"*2100}, timeout=15)
    print("Oversized URL status:", r_oversized.status_code)
    assert r_oversized.status_code == 422

    print("\n==================================================")
    print("6. TESTING CORS HEADERS FROM WEB & EXTENSION ORIGINS")
    print("==================================================")
    web_origin = "http://localhost:5173"
    ext_origin = "chrome-extension://abcdefghijklmnopabcdefghijklmnop"

    # Preflight OPTIONS request from Web origin
    opt_web = requests.options(
        f"{BASE_URL}/predict",
        headers={
            "Origin": web_origin,
            "Access-Control-Request-Method": "POST",
            "Access-Control-Request-Headers": "content-type",
        },
    )
    print("Web origin preflight status:", opt_web.status_code)
    print("Web origin preflight headers:", dict(opt_web.headers))
    assert opt_web.headers.get("access-control-allow-origin") == "*" or opt_web.headers.get("access-control-allow-origin") == web_origin

    # POST from Web origin
    post_web = requests.post(
        f"{BASE_URL}/predict",
        json={"url": "https://example.com"},
        headers={"Origin": web_origin},
    )
    print("Web origin POST allow-origin header:", post_web.headers.get("access-control-allow-origin"))
    assert post_web.headers.get("access-control-allow-origin") == "*" or post_web.headers.get("access-control-allow-origin") == web_origin

    # Preflight OPTIONS request from Extension origin
    opt_ext = requests.options(
        f"{BASE_URL}/predict",
        headers={
            "Origin": ext_origin,
            "Access-Control-Request-Method": "POST",
            "Access-Control-Request-Headers": "content-type",
        },
    )
    print("Extension origin preflight status:", opt_ext.status_code)
    print("Extension origin preflight headers:", dict(opt_ext.headers))
    assert opt_ext.headers.get("access-control-allow-origin") == "*" or opt_ext.headers.get("access-control-allow-origin") == ext_origin

    # POST from Extension origin
    post_ext = requests.post(
        f"{BASE_URL}/predict",
        json={"url": "https://example.com"},
        headers={"Origin": ext_origin},
    )
    print("Extension origin POST allow-origin header:", post_ext.headers.get("access-control-allow-origin"))
    assert post_ext.headers.get("access-control-allow-origin") == "*" or post_ext.headers.get("access-control-allow-origin") == ext_origin

    print("\n==================================================")
    print("ALL API TESTS PASSED SUCCESSFULLY!")
    print("==================================================")

if __name__ == "__main__":
    test_api_matrix()
