import argparse
import gzip
import json
import os
from datetime import datetime, timedelta, timezone
from pathlib import Path

import requests

BASE = Path("data/sample_raw")
HEADERS = {"User-Agent": "Mozilla/5.0 (student-project; data-eng-threat-intel-pipeline)"}

KEV_URL = "https://www.cisa.gov/sites/default/files/feeds/known_exploited_vulnerabilities.json"
KEV_MIRROR = "https://raw.githubusercontent.com/aboutcode-org/aboutcode-mirror-kev/main/known_exploited_vulnerabilities.json"
EPSS_URL = "https://epss.empiricalsecurity.com/epss_scores-current.csv.gz"
NVD_URL = "https://services.nvd.nist.gov/rest/json/cves/2.0"


def out_path(load, name):
    folder = BASE / ("full_load" if load == "full" else "incremental")
    folder.mkdir(parents=True, exist_ok=True)
    return folder / name


def fetch_kev(load):
    try:
        r = requests.get(KEV_URL, headers=HEADERS, timeout=60)
        r.raise_for_status()
    except requests.RequestException as e:
        print(f"CISA download failed ({e}); trying GitHub mirror")
        r = requests.get(KEV_MIRROR, headers=HEADERS, timeout=60)
        r.raise_for_status()
    data = r.json()

    if load == "incremental":
        cutoff = (datetime.now(timezone.utc) - timedelta(days=30)).strftime("%Y-%m-%d")
        data["vulnerabilities"] = [v for v in data["vulnerabilities"] if v["dateAdded"] >= cutoff]

    path = out_path(load, f"kev_{load}_sample.json")
    path.write_text(json.dumps(data, indent=2))
    print(f"Saved {path} ({len(data['vulnerabilities'])} entries)")


def fetch_epss(load, max_rows=50_000):
    r = requests.get(EPSS_URL, headers=HEADERS, timeout=120, allow_redirects=True)
    r.raise_for_status()
    text = gzip.decompress(r.content).decode("utf-8")
    lines = text.splitlines()
    trimmed = lines[: max_rows + 2]

    path = out_path(load, f"epss_{load}_sample.csv")
    path.write_text("\n".join(trimmed) + "\n")
    print(f"Saved {path} ({len(trimmed) - 2} rows). First line: {lines[0]}")


def fetch_nvd(load, days=2, per_page=500):
    headers = dict(HEADERS)
    key = os.getenv("NVD_API_KEY")
    if key:
        headers["apiKey"] = key
    else:
        print("Warning: NVD_API_KEY not set (5 requests / 30s limit)")

    params = {"resultsPerPage": per_page, "startIndex": 0}
    if load == "incremental":
        end = datetime.now(timezone.utc)
        start = end - timedelta(days=days)
        fmt = "%Y-%m-%dT%H:%M:%S.000"
        params["lastModStartDate"] = start.strftime(fmt)
        params["lastModEndDate"] = end.strftime(fmt)

    r = requests.get(NVD_URL, headers=headers, params=params, timeout=120)
    r.raise_for_status()
    data = r.json()

    path = out_path(load, f"nvd_cves_{load}_sample.json")
    path.write_text(json.dumps(data, indent=2))
    print(f"Saved {path} ({len(data.get('vulnerabilities', []))} of {data.get('totalResults')} total CVEs)")


if __name__ == "__main__":
    ap = argparse.ArgumentParser()
    ap.add_argument("source", choices=["kev", "epss", "nvd"])
    ap.add_argument("--load", choices=["full", "incremental"], required=True)
    ap.add_argument("--days", type=int, default=2, help="NVD incremental window in days")
    a = ap.parse_args()

    if a.source == "kev":
        fetch_kev(a.load)
    elif a.source == "epss":
        fetch_epss(a.load)
    else:
        fetch_nvd(a.load, a.days)