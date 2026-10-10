import sys
from pathlib import Path
sys.path.insert(0, str(Path("backend")))

from ml.feature_extraction import extract_html_features, is_likely_unrendered_spa_shell

spa_shell_html = """<!doctype html><html lang="en"><head><meta charset="utf-8"/><title>App</title><link href="/static/css/main.chunk.css" rel="stylesheet"/><script defer="defer" src="/static/js/2.chunk.js"></script><script defer="defer" src="/static/js/main.chunk.js"></script><script defer="defer" src="/static/js/runtime.js"></script></head><body><div id="root"></div></body></html>"""

feats = extract_html_features(spa_shell_html, "https://portal.university.edu/dashboard")
print("Features extracted:", feats)
print("is_likely_unrendered_spa_shell:", is_likely_unrendered_spa_shell(feats))
