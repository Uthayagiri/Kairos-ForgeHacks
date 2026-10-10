"""Unit tests for legitimate deep-link crawler and link extraction."""

import csv
from pathlib import Path
import pytest

from ml.data_collection.crawl_legitimate_deep_links import (
    extract_internal_deep_links,
    gather_candidate_deep_links,
    is_internal_link,
)


def test_is_internal_link():
    """Verify internal domain and subdomain detection."""
    base = "https://example.com"
    assert is_internal_link(base, "https://example.com/about") is True
    assert is_internal_link(base, "https://www.example.com/contact") is True
    assert is_internal_link(base, "https://blog.example.com/article/1") is True
    assert is_internal_link(base, "https://malicious-site.com/about") is False
    assert is_internal_link(base, "https://example.org/about") is False


def test_extract_internal_deep_links():
    """Verify link resolution, internal filtering, and exclusion of root/anchors/javascript."""
    base_url = "https://wikipedia.org"
    html = """
    <html>
    <body>
        <!-- Valid internal deep links -->
        <a href="/wiki/Phishing">Phishing Article</a>
        <a href="https://wikipedia.org/wiki/Computer_security">Security Article</a>
        <a href="https://en.wikipedia.org/wiki/Main_Page">Main Page Subdomain</a>
        
        <!-- Root links (should be excluded) -->
        <a href="/">Home Root</a>
        <a href="https://wikipedia.org/">Full Root</a>
        
        <!-- Anchors, JS, Mailto (should be excluded) -->
        <a href="#references">References Section</a>
        <a href="javascript:void(0)">JS Action</a>
        <a href="mailto:info@wikimedia.org">Contact Mail</a>
        
        <!-- External links (should be excluded) -->
        <a href="https://google.com/search">Google External</a>
        <a href="https://evil-phish.xyz/wiki/Phishing">Spoofed Domain</a>
        
        <!-- Media file (should be excluded) -->
        <a href="/images/logo.png">Logo Image</a>
    </body>
    </html>
    """

    links = extract_internal_deep_links(html, base_url)

    # Should contain exactly the 3 valid internal deep links
    assert "https://wikipedia.org/wiki/Phishing" in links
    assert "https://wikipedia.org/wiki/Computer_security" in links
    assert "https://en.wikipedia.org/wiki/Main_Page" in links

    # Should NOT contain root, anchor, mailto, js, external or media
    assert "https://wikipedia.org/" not in links
    assert "https://wikipedia.org" not in links
    assert not any("#" in l for l in links)
    assert not any("google.com" in l for l in links)
    assert not any("evil-phish.xyz" in l for l in links)
    assert not any(l.endswith(".png") for l in links)


def test_extract_internal_deep_links_no_valid_links():
    """Verify clean handling of pages with zero valid internal links."""
    base_url = "https://minimal-site.com"
    html = "<html><body><p>No links here</p><a href='#top'>Top</a><a href='https://external.com'>Ext</a></body></html>"

    links = extract_internal_deep_links(html, base_url)
    assert links == []


def test_gather_candidate_deep_links_synthetic(tmp_path):
    """Verify synthetic manifest scanning, HTML parsing, and deterministic sampling."""
    data_dir = tmp_path / "data"
    raw_dir = data_dir / "raw"
    cache_dir = raw_dir / "html_cache"
    processed_dir = data_dir / "processed"

    cache_dir.mkdir(parents=True)
    processed_dir.mkdir(parents=True)

    html1 = "<html><body><a href='/news/tech'>Tech News</a><a href='/about'>About</a><a href='/jobs'>Jobs</a></body></html>"
    html2 = "<html><body><a href='/docs/api'>API Docs</a></body></html>"

    f1 = cache_dir / "site1.html"
    f2 = cache_dir / "site2.html"
    f1.write_text(html1, encoding="utf-8")
    f2.write_text(html2, encoding="utf-8")

    manifest_file = processed_dir / "dataset_manifest.csv"
    manifest_rows = [
        {
            "url": "https://site1.org",
            "label": "legitimate",
            "html_file_path": f"raw/html_cache/{f1.name}",
            "http_status": "200",
            "fetch_success": "True",
            "fetch_timestamp": "2026-09-07T00:00:00Z",
            "source": "Tranco Top-1M",
        },
        {
            "url": "https://site2.org",
            "label": "legitimate",
            "html_file_path": f"raw/html_cache/{f2.name}",
            "http_status": "200",
            "fetch_success": "True",
            "fetch_timestamp": "2026-09-07T00:00:00Z",
            "source": "Tranco Top-1M",
        },
    ]

    with open(manifest_file, mode="w", newline="", encoding="utf-8") as f:
        writer = csv.DictWriter(f, fieldnames=list(manifest_rows[0].keys()))
        writer.writeheader()
        writer.writerows(manifest_rows)

    candidates = gather_candidate_deep_links(
        manifest_path=manifest_file,
        samples_per_domain=2,
        random_state=42,
        base_dir=tmp_path,
    )

    # site1 has 3 links, sampled max 2; site2 has 1 link, sampled 1 -> Total = 3
    assert len(candidates) == 3
    assert all(c["label"] == "legitimate" for c in candidates)
    assert all(c["source"] == "tranco_internal_link_crawl" for c in candidates)
    assert any("site1.org" in c["url"] for c in candidates)
    assert any("site2.org" in c["url"] for c in candidates)
