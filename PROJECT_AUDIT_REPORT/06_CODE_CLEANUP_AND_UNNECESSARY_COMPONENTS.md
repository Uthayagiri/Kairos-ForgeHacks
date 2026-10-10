# PhishGuard AI — Code Cleanup & Unnecessary Components Inventory

## 1. Inventory Framework

To ensure that the codebase remains clean, maintainable, and free of security dead-weight, this audit organizes components into four explicit categories:

1. **KEEP:** Essential production code providing active, verified functionality.
2. **IMPROVE:** Valuable components that contain security gaps, performance bottlenecks, or architectural flaws.
3. **POTENTIALLY REMOVE:** Dead, orphaned, duplicate, or obsolete code that adds maintenance burden without delivering user value.
4. **INVESTIGATE BEFORE REMOVING:** Scripts or assets whose usage cannot be confirmed without developer intent (e.g., benchmark tools or demo generators).

---

## 2. Category 1: KEEP (Core Production Architecture)

| Component Path | Function / Responsibility | Justification |
| :--- | :--- | :--- |
| `backend/app/main.py` | FastAPI application entry point, CORS, lifespan startup | Core REST application host. |
| `backend/app/api/routes/predict.py` | Route handlers for `/api/analyze`, `/predict`, `/api/history` | Primary API interface for clients. |
| `backend/app/services/detection_engine.py` | Central scanning orchestrator | Coordinates validation, fetch, extract, score. |
| `backend/app/services/risk_scoring.py` | Bounded risk mapping and explainable indicators | Core intelligence preventing ungrounded scores. |
| `backend/app/core/model_loader.py` | Singleton XGBoost loader | Thread-safe, cached model execution. |
| `backend/ml/feature_extraction/url_features.py` | Lexical 22-feature parser | Resilient, deterministic offline feature extractor. |
| `backend/ml/feature_extraction/html_features.py` | Static DOM 21-feature parser | DOM structure, form action, and iframe extractor. |
| `backend/ml/models/phishing_model.joblib` | Active XGBoost 2.1.0 binary | Production champion model artifact (Candidate A4). |
| `frontend/src/App.jsx` & `frontend/src/pages/*` | React 18 web interface | Primary user operations dashboard. |
| `extension/manifest.json` & `extension/popup/*` | Chromium MV3 advisory extension | Active tab URL scanner popup. |

---

## 3. Category 2: IMPROVE (Valuable but Flawed Components)

### Component: `backend/app/services/detection_engine.py` (`fetch_single_html`)
- **Reason:** Synchronous `requests.get()` freezes the FastAPI asyncio event loop on dead domains (DoS risk).
- **Required Improvement:** Refactor to asynchronous `httpx.AsyncClient` with non-blocking DNS resolution.

### Component: `backend/app/services/detection_engine.py` (`is_safe_ssrf_destination`)
- **Reason:** Bypassed by HTTP 302 redirects (`allow_redirects=True`).
- **Required Improvement:** Set `allow_redirects=False` and re-validate destination IP on each redirect hop.

### Component: `extension/background/service-worker.js`
- **Reason:** Does not listen to web navigation events; background scanning is completely inactive.
- **Required Improvement:** Add `chrome.webNavigation.onBeforeNavigate` with an asynchronous API cache lookup to enable genuine real-time background protection.

### Component: `backend/ml/feature_extraction/html_features.py` (`num_links`, `num_internal_links`)
- **Reason:** Accounts for 43% of model split weight, causing severe false positives on low-link legitimate landing pages.
- **Required Improvement:** Normalize link counts into ratios (`links_per_kb_of_html` or `internal_to_external_ratio`) rather than raw unbounded integers.

---

## 4. Category 3: POTENTIALLY REMOVE (Dead Code & Duplicates)

### Item 1: Orphaned About View
- **File Path:** `frontend/src/pages/About.jsx` (7,586 bytes)
- **Reason:** Dead code duplicate.
- **Evidence:** `frontend/src/App.jsx` imports `AboutPage.jsx` on line 11:
  `import AboutPage from './pages/AboutPage';`
  `About.jsx` is never imported, referenced, or routed anywhere in the React application.
- **Potential Consequence of Removal:** Zero runtime impact. Bundle size decreases slightly.
- **Safe Verification Step:**
  ```powershell
  # Search for any imports of About.jsx in frontend/src
  Select-String -Path "frontend\src\*.jsx", "frontend\src\**\*.jsx" -Pattern "pages/About'"
  ```

### Item 2: Unused Candidates Directory Trees
- **Directory Path:** `backend/ml/models/candidates_auth/`, `candidates_spw/`, `legacy_v1/`
- **Reason:** Experimental candidate models and legacy v1 models that are no longer referenced by `ModelLoader`.
- **Evidence:** `ModelLoader` explicitly loads only `backend/ml/models/phishing_model.joblib`.
- **Potential Consequence of Removal:** Frees repository disk space; reduces repository cloning footprint.
- **Safe Verification Step:** Confirm that no scripts in `backend/app/` reference subdirectories in `ml/models/`.

### Item 3: Residual Temporary Logs and Diagnostic Dumps in `scratch/`
- **File Paths:**
  - `scratch/diagnostic_summary.json` (25.7 KB)
  - `scratch/broad_url_test_results.json` (27.4 KB)
  - `scratch/hard_negative_candidates.json` (39.4 KB)
  - `scratch/exp5_escalation_events.log` (318 bytes)
- **Reason:** Ephemeral output artifacts generated during experimental sweeps.
- **Potential Consequence of Removal:** Cleans up developer workspace; does not affect application runtime.

---

## 5. Category 4: INVESTIGATE BEFORE REMOVING

### Item 1: Video Demo Generation Scripts (`frontend/generate_video_*.js`, `scratch/test_cdp_screencast.js`)
- **File Paths:**
  - `frontend/generate_video_01.js` (24.7 KB)
  - `frontend/generate_video_02.js` (25.6 KB)
  - `frontend/generate_video_03.js` (14.8 KB)
  - `frontend/generate_video_04.js` (17.9 KB)
  - `frontend/generate_video_05.js` (25.7 KB)
  - `frontend/render_demo_images.js` (54.6 KB)
  - `frontend/run_all_remaining_videos.js` (1.2 KB)
- **Investigation Note:** These scripts use Puppeteer to automate the browser and capture high-definition WebM/MP4 video walkthroughs for hackathon and academic competition submissions (e.g. ForgeHacks).
- **Recommendation:** **Retain in `forgehacks_submission/` or developer tools**, but do not bundle with production distribution.

### Item 2: Young Domain Cohort Harvester Scripts
- **File Paths:**
  - `backend/data/young_domain_cohort/cohort_a_exclusions.log`
  - `scratch/harvest_cohort_a_comprehensive.py`
  - `scratch/collect_young_domain_cohorts.py`
- **Investigation Note:** Used during Stage 12 research to study newly registered domains (< 30 days old).
- **Recommendation:** Archive into a dedicated research directory if future domain age modeling is planned.
