"""Module to systematically expand and diversify the legitimate training dataset.

Collects authentic legitimate URLs across underrepresented categories:
- Higher education & research (.edu, .ac.in, .ac.uk, .edu.au)
- Government & public administration (.gov, .gov.in, .gov.uk)
- Minimalist tools, utilities, developer services, and SaaS landing pages
- Tech communities, open-source projects, and non-profit organizations

Extracts both homepages and internal subpages to ensure realistic, balanced
link-count distributions (from sparse 0-10 links to rich 100+ links).
"""

import csv
import logging
import sys
import time
from concurrent.futures import ThreadPoolExecutor, as_completed
from pathlib import Path
from typing import Dict, List, Set, Tuple
from urllib.parse import urlparse

import requests
import urllib3
urllib3.disable_warnings(urllib3.exceptions.InsecureRequestWarning)

BACKEND_ROOT = Path(__file__).resolve().parents[2]
if str(BACKEND_ROOT) not in sys.path:
    sys.path.insert(0, str(BACKEND_ROOT))

from ml.data_collection.config import HTML_CACHE_DIR, MAX_WORKERS, USER_AGENT
from ml.data_collection.crawl_legitimate_deep_links import extract_internal_deep_links
from ml.data_collection.fetch_html import get_url_hash
from ml.training.build_training_dataset import TRAINING_COLUMNS, assemble_single_record

logging.basicConfig(level=logging.INFO, format="%(asctime)s [%(levelname)s] %(message)s")
logger = logging.getLogger(__name__)

DIVERSE_OUTPUT_CSV = BACKEND_ROOT / "data" / "processed" / "diverse_legitimate_records.csv"

# Curated high-reputation domains across diverse structural categories
DIVERSE_SEED_DOMAINS = [
    # 1. Higher Education & Research (.edu, .ac.in, .ac.uk, .edu.au, .ca, .ch, .sg)
    "https://www.harvard.edu",
    "https://www.mit.edu",
    "https://www.stanford.edu",
    "https://www.berkeley.edu",
    "https://www.ox.ac.uk",
    "https://www.cam.ac.uk",
    "https://www.iitm.ac.in",
    "https://www.iitb.ac.in",
    "https://www.iisc.ac.in",
    "https://www.bits-pilani.ac.in",
    "https://www.annauniv.edu",
    "https://www.ucla.edu",
    "https://www.princeton.edu",
    "https://www.yale.edu",
    "https://www.cmu.edu",
    "https://www.columbia.edu",
    "https://www.cornell.edu",
    "https://www.utoronto.ca",
    "https://www.nus.edu.sg",
    "https://www.unsw.edu.au",
    "https://www.anu.edu.au",
    "https://www.tudelft.nl",
    "https://www.ethz.ch",
    "https://www.imperial.ac.uk",
    "https://www.ucl.ac.uk",
    "https://www.ed.ac.uk",
    "https://www.kcl.ac.uk",
    "https://www.manchester.ac.uk",
    "https://www.ubc.ca",
    "https://www.mcgill.ca",
    "https://www.unimelb.edu.au",
    "https://www.sydney.edu.au",
    "https://www.uq.edu.au",
    "https://www.iitd.ac.in",
    "https://www.iitk.ac.in",
    "https://www.iitr.ac.in",
    "https://www.iitg.ac.in",
    "https://www.iith.ac.in",
    "https://www.jnu.ac.in",
    "https://www.du.ac.in",
    "https://www.bhu.ac.in",
    "https://www.caltech.edu",
    "https://www.gatech.edu",
    "https://www.utexas.edu",
    "https://www.washington.edu",
    "https://www.illinois.edu",
    "https://www.umich.edu",
    "https://www.purdue.edu",
    "https://www.northwestern.edu",
    "https://www.jhu.edu",

    # 2. Government & Public Sector (.gov, .gov.in, .gov.uk, .gov.au)
    "https://www.india.gov.in",
    "https://www.usa.gov",
    "https://www.gov.uk",
    "https://www.digital.gov",
    "https://www.weather.gov",
    "https://www.cdc.gov",
    "https://www.nih.gov",
    "https://www.nasa.gov",
    "https://www.loc.gov",
    "https://www.whitehouse.gov",
    "https://www.irs.gov",
    "https://www.state.gov",
    "https://www.transportation.gov",
    "https://www.energy.gov",
    "https://www.epa.gov",
    "https://www.ftc.gov",
    "https://www.fbi.gov",
    "https://www.archives.gov",
    "https://www.data.gov",
    "https://www.nps.gov",
    "https://www.noaa.gov",
    "https://www.usda.gov",
    "https://www.census.gov",
    "https://www.sec.gov",
    "https://www.fda.gov",
    "https://www.fcc.gov",
    "https://www.faa.gov",
    "https://www.pmindia.gov.in",
    "https://www.mygov.in",
    "https://uidai.gov.in",
    "https://www.incometax.gov.in",
    "https://www.gst.gov.in",
    "https://www.passportindia.gov.in",
    "https://eci.gov.in",
    "https://www.isro.gov.in",
    "https://www.drdo.gov.in",
    "https://www.cbse.gov.in",
    "https://nta.ac.in",
    "https://www.ugc.gov.in",
    "https://www.aicte-india.org",
    "https://www.australia.gov.au",
    "https://www.canada.ca",

    # 3. Minimalist Tools, Utilities & Technical Portals
    "https://pastebin.com",
    "https://excalidraw.com",
    "https://codepen.io",
    "https://codesandbox.io",
    "https://stackblitz.com",
    "https://replit.com",
    "https://glitch.com",
    "https://jsfiddle.net",
    "https://regex101.com",
    "https://jsonlint.com",
    "https://www.diffchecker.com",
    "https://www.wolframalpha.com",
    "https://archive.org",
    "https://distrowatch.com",
    "https://www.hackerone.com",
    "https://www.bugcrowd.com",
    "https://www.kaggle.com",
    "https://arxiv.org",
    "https://openalex.org",
    "https://www.crossref.org",
    "https://orcid.org",
    "https://zenodo.org",
    "https://www.biorxiv.org",
    "https://www.medrxiv.org",
    "https://paperswithcode.com",
    "https://www.semanticscholar.org",
    "https://www.uniprot.org",
    "https://www.ncbi.nlm.nih.gov",
    "https://www.ensembl.org",
    "https://www.rcsb.org",

    # 4. Tech Communities, Open Source & Documentation
    "https://dev.to",
    "https://hashnode.com",
    "https://lobste.rs",
    "https://news.ycombinator.com",
    "https://slashdot.org",
    "https://lwn.net",
    "https://arstechnica.com",
    "https://www.eff.org",
    "https://www.fsf.org",
    "https://www.apache.org",
    "https://www.linuxfoundation.org",
    "https://www.gnu.org",
    "https://www.kernel.org",
    "https://www.w3.org",
    "https://www.ietf.org",
    "https://www.iana.org",
    "https://www.icann.org",
    "https://docs.python.org",
    "https://developer.mozilla.org",
    "https://rust-lang.org",
    "https://golang.org",
    "https://nodejs.org",
    "https://react.dev",
    "https://vuejs.org",
    "https://svelte.dev",
    "https://tailwindcss.com",
    "https://vitejs.dev",
    "https://fastapi.tiangolo.com",
    "https://pydantic.dev",

    # 5. Non-Profit, Global & Public Interest Organizations
    "https://www.redcross.org",
    "https://www.unicef.org",
    "https://www.unesco.org",
    "https://www.who.int",
    "https://www.worldbank.org",
    "https://www.imf.org",
    "https://www.oecd.org",
    "https://www.weforum.org",
    "https://www.amnesty.org",
    "https://www.greenpeace.org",
    "https://www.nature.org",
    "https://www.worldwildlife.org",
    "https://www.rotary.org",
    "https://www.oxfam.org",
    "https://www.msf.org",
]


def fetch_url(url: str, session: requests.Session) -> Tuple[str, bool, str, int]:
    """Guarded fetch of a single URL returning content and status."""
    headers = {
        "User-Agent": USER_AGENT,
        "Accept": "text/html,application/xhtml+xml,application/xml;q=0.9,*/*;q=0.8",
        "Accept-Language": "en-US,en;q=0.5",
        "Connection": "close",
    }
    try:
        resp = session.get(url, headers=headers, timeout=(3.0, 4.0), verify=False, allow_redirects=True)
        if resp.status_code == 200 and "text/html" in resp.headers.get("content-type", "").lower():
            url_hash = get_url_hash(url)
            cache_file = HTML_CACHE_DIR / f"{url_hash}.html"
            cache_file.write_text(resp.text, encoding="utf-8", errors="replace")
            return url, True, resp.text, resp.status_code
        return url, False, "", resp.status_code
    except Exception:
        return url, False, "", 0


def collect_and_save_diverse_dataset(max_deep_per_domain: int = 5) -> int:
    """Crawl homepages and internal subpages from diverse seed domains and save to CSV."""
    logger.info("Starting diverse legitimate dataset collection across %d seed domains...", len(DIVERSE_SEED_DOMAINS))
    HTML_CACHE_DIR.mkdir(parents=True, exist_ok=True)
    
    session = requests.Session()
    adapter = requests.adapters.HTTPAdapter(pool_connections=32, pool_maxsize=32, max_retries=0)
    session.mount("http://", adapter)
    session.mount("https://", adapter)

    # 1. Fetch seed homepages
    homepage_results: List[Tuple[str, str]] = []
    with ThreadPoolExecutor(max_workers=32) as executor:
        futures = {executor.submit(fetch_url, u, session): u for u in DIVERSE_SEED_DOMAINS}
        for fut in as_completed(futures):
            url, success, html, status = fut.result()
            if success and html:
                homepage_results.append((url, html))

    logger.info("Successfully fetched %d seed homepages. Extracting deep links...", len(homepage_results))

    # 2. Extract internal deep links from each homepage
    all_candidate_urls: Set[str] = set()
    for base_url, html in homepage_results:
        all_candidate_urls.add(base_url)
        deep_links = extract_internal_deep_links(html, base_url, min_path_length=1)
        selected = deep_links[:max_deep_per_domain]
        for dl in selected:
            all_candidate_urls.add(dl)

    logger.info("Total candidate URLs identified for crawling: %d. Fetching subpages...", len(all_candidate_urls))

    # 3. Concurrently fetch all candidate subpages
    successful_records: List[Dict[str, object]] = []
    with ThreadPoolExecutor(max_workers=32) as executor:
        futures = {executor.submit(fetch_url, u, session): u for u in all_candidate_urls}
        for fut in as_completed(futures):
            url, success, html, status = fut.result()
            if success and html:
                record = assemble_single_record(url, label="legitimate", html_content=html)
                successful_records.append(record)

    logger.info("Successfully extracted and assembled %d diverse legitimate feature records.", len(successful_records))

    # 4. Save to CSV
    if successful_records:
        DIVERSE_OUTPUT_CSV.parent.mkdir(parents=True, exist_ok=True)
        with open(DIVERSE_OUTPUT_CSV, "w", newline="", encoding="utf-8") as f:
            writer = csv.DictWriter(f, fieldnames=TRAINING_COLUMNS)
            writer.writeheader()
            for rec in successful_records:
                writer.writerow(rec)
        logger.info("Saved %d diverse records to %s", len(successful_records), DIVERSE_OUTPUT_CSV)

    return len(successful_records)


if __name__ == "__main__":
    count = collect_and_save_diverse_dataset(max_deep_per_domain=5)
    print(f"COLLECTION COMPLETE: {count} diverse legitimate records saved.")
