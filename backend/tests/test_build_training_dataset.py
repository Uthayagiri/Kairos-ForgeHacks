"""Unit tests for combined training dataset assembly pipeline."""

import csv
from pathlib import Path

import pandas as pd
import pytest

from ml.training.build_training_dataset import (
    TRAINING_COLUMNS,
    assemble_single_record,
    build_training_dataset,
)


def test_assemble_single_record_structure():
    """1. Verify single record assembly produces all expected columns and valid numeric/integer types."""
    url = "https://secure-login.bank-update.xyz/auth/verify?session=123"
    html = """
    <html>
    <head><title>Secure Sign In</title></head>
    <body>
        <form action="/auth" method="POST">
            <input type="text" name="username" />
            <input type="password" name="password" />
        </form>
    </body>
    </html>
    """
    record = assemble_single_record(url, label="phishing", html_content=html)

    assert set(record.keys()) == set(TRAINING_COLUMNS)
    assert record["url"] == url
    assert record["label_binary"] == 1
    assert record["label"] == "phishing"
    assert record["has_login_form"] == 1
    assert record["has_suspicious_tld"] == 1  # .xyz
    assert record["has_suspicious_keywords"] == 1  # login / auth / verify


def test_build_training_dataset_excludes_unfetched_rows(tmp_path):
    """2. Verify build_training_dataset strictly excludes rows where fetch_success=False."""
    data_dir = tmp_path / "data"
    raw_dir = data_dir / "raw"
    cache_dir = raw_dir / "html_cache"
    processed_dir = data_dir / "processed"

    raw_dir.mkdir(parents=True)
    cache_dir.mkdir(parents=True)
    processed_dir.mkdir(parents=True)

    # Valid HTML file
    html_file = cache_dir / "legit.html"
    html_file.write_text("<html><head><title>Valid</title></head><body>Hello</body></html>", encoding="utf-8")

    manifest_file = processed_dir / "dataset_manifest.csv"
    output_dataset_file = processed_dir / "training_dataset.csv"

    manifest_rows = [
        {
            "url": "https://valid-site.com",
            "label": "legitimate",
            "html_file_path": f"raw/html_cache/{html_file.name}",
            "http_status": "200",
            "fetch_success": "True",
            "fetch_timestamp": "2026-09-07T00:00:00Z",
            "source": "Tranco",
        },
        {
            "url": "https://unfetched-site.com",
            "label": "legitimate",
            "html_file_path": "",
            "http_status": "404",
            "fetch_success": "False",
            "fetch_timestamp": "2026-09-07T00:00:00Z",
            "source": "Tranco",
        },
        {
            "url": "http://failed-phish.com",
            "label": "phishing",
            "html_file_path": "",
            "http_status": "500",
            "fetch_success": "False",
            "fetch_timestamp": "2026-09-07T00:00:00Z",
            "source": "OpenPhish",
        },
    ]

    with open(manifest_file, mode="w", newline="", encoding="utf-8") as f:
        writer = csv.DictWriter(f, fieldnames=list(manifest_rows[0].keys()))
        writer.writeheader()
        writer.writerows(manifest_rows)

    df = build_training_dataset(
        manifest_path=manifest_file,
        output_path=output_dataset_file,
        base_dir=tmp_path,
    )

    assert len(df) == 1
    assert df["url"].iloc[0] == "https://valid-site.com"
    assert "https://unfetched-site.com" not in df["url"].values
    assert "http://failed-phish.com" not in df["url"].values


def test_build_training_dataset_handles_missing_file_drift(tmp_path, caplog):
    """3. Defensive drift test: row marked fetch_success=True but file missing on disk is skipped and logged."""
    data_dir = tmp_path / "data"
    raw_dir = data_dir / "raw"
    cache_dir = raw_dir / "html_cache"
    processed_dir = data_dir / "processed"

    raw_dir.mkdir(parents=True)
    cache_dir.mkdir(parents=True)
    processed_dir.mkdir(parents=True)

    # Valid HTML file
    html_file = cache_dir / "existing.html"
    html_file.write_text("<html><head><title>Existing</title></head><body>Existing</body></html>", encoding="utf-8")

    manifest_file = processed_dir / "dataset_manifest.csv"
    output_dataset_file = processed_dir / "training_dataset.csv"

    manifest_rows = [
        {
            "url": "https://existing-site.com",
            "label": "legitimate",
            "html_file_path": f"raw/html_cache/{html_file.name}",
            "http_status": "200",
            "fetch_success": "True",
            "fetch_timestamp": "2026-09-07T00:00:00Z",
            "source": "Tranco",
        },
        {
            "url": "http://phantom-missing.org",
            "label": "phishing",
            "html_file_path": "raw/html_cache/non_existent_file.html",
            "http_status": "200",
            "fetch_success": "True",
            "fetch_timestamp": "2026-09-07T00:00:00Z",
            "source": "PhishTank",
        },
    ]

    with open(manifest_file, mode="w", newline="", encoding="utf-8") as f:
        writer = csv.DictWriter(f, fieldnames=list(manifest_rows[0].keys()))
        writer.writeheader()
        writer.writerows(manifest_rows)

    df = build_training_dataset(
        manifest_path=manifest_file,
        output_path=output_dataset_file,
        base_dir=tmp_path,
    )

    assert len(df) == 1
    assert df["url"].iloc[0] == "https://existing-site.com"
    assert "http://phantom-missing.org" not in df["url"].values
    assert "Cached HTML file not found" in caplog.text


def test_build_training_dataset_end_to_end_synthetic(tmp_path):
    """4. Comprehensive synthetic manifest test checking balanced labels, feature integrity, and CSV persistence."""
    data_dir = tmp_path / "data"
    raw_dir = data_dir / "raw"
    cache_dir = raw_dir / "html_cache"
    processed_dir = data_dir / "processed"

    raw_dir.mkdir(parents=True)
    cache_dir.mkdir(parents=True)
    processed_dir.mkdir(parents=True)

    html_file1 = cache_dir / "legit1.html"
    html_file1.write_text("<html><head><title>Legit Home</title></head><body>Welcome</body></html>", encoding="utf-8")

    html_file2 = cache_dir / "phish1.html"
    html_file2.write_text(
        "<html><head><title>Login</title></head><body><form><input type='password' /></form></body></html>",
        encoding="utf-8",
    )

    manifest_file = processed_dir / "dataset_manifest.csv"
    output_dataset_file = processed_dir / "training_dataset.csv"

    manifest_rows = [
        {
            "url": "https://company.org/home",
            "label": "legitimate",
            "html_file_path": f"raw/html_cache/{html_file1.name}",
            "http_status": "200",
            "fetch_success": "True",
            "fetch_timestamp": "2026-09-07T00:00:00Z",
            "source": "Tranco",
        },
        {
            "url": "http://evil-phish.xyz/login",
            "label": "phishing",
            "html_file_path": f"raw/html_cache/{html_file2.name}",
            "http_status": "200",
            "fetch_success": "True",
            "fetch_timestamp": "2026-09-07T00:00:00Z",
            "source": "OpenPhish",
        },
    ]

    with open(manifest_file, mode="w", newline="", encoding="utf-8") as f:
        writer = csv.DictWriter(f, fieldnames=list(manifest_rows[0].keys()))
        writer.writeheader()
        writer.writerows(manifest_rows)

    df = build_training_dataset(
        manifest_path=manifest_file,
        output_path=output_dataset_file,
        base_dir=tmp_path,
    )

    assert len(df) == 2
    assert list(df.columns) == TRAINING_COLUMNS
    assert df["label_binary"].tolist() == [0, 1]
    assert df.isnull().sum().sum() == 0
    assert output_dataset_file.exists()

    # Read back from CSV to verify serialization formats
    df_read = pd.read_csv(output_dataset_file)
    assert len(df_read) == 2
    assert df_read.isnull().sum().sum() == 0
