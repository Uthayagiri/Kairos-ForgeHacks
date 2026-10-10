import subprocess
import time
import os

html_sample = """<!DOCTYPE html>
<html>
<head>
    <title>SPA Test Page</title>
</head>
<body>
    <div id="root">Loading application...</div>
    <script>
        setTimeout(() => {
            const root = document.getElementById('root');
            root.innerHTML = '<h2>Dashboard</h2><a href="/home">Home</a><a href="/settings">Settings</a><a href="https://partner.com">Partner</a>';
        }, 100);
    </script>
</body>
</html>
"""

test_html_path = os.path.abspath("scratch/spa_test.html")
with open(test_html_path, "w", encoding="utf-8") as f:
    f.write(html_sample)

chrome_paths = [
    r"C:\Program Files\Google\Chrome\Application\chrome.exe",
    r"C:\Program Files (x86)\Microsoft\Edge\Application\msedge.exe"
]
chrome_bin = next((p for p in chrome_paths if os.path.exists(p)), None)
print(f"Using browser binary: {chrome_bin}")

start_t = time.perf_counter()
cmd = [
    chrome_bin,
    "--headless=new",
    "--disable-gpu",
    "--no-sandbox",
    "--disable-software-rasterizer",
    "--virtual-time-budget=1000",
    "--dump-dom",
    f"file:///{test_html_path.replace(os.sep, '/')}"
]

try:
    res = subprocess.run(cmd, capture_output=True, text=True, timeout=5, encoding="utf-8", errors="replace")
    elapsed = time.perf_counter() - start_t
    print(f"Rendered in {elapsed:.3f}s. Exit code: {res.returncode}")
    print("DOM Output:")
    print(res.stdout[:500])
except Exception as e:
    print(f"Rendering error: {e}")
