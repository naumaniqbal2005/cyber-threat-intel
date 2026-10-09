import argparse
import gzip
import json
import os
import time
from datetime import datetime, timedelta, timezone
from pathlib import Path

import requests

BASE = Path("data/sample_raw")
HEADERS = {"User-Agent": "Mozilla/5.0 (student-project; data-eng-threat-intel-pipeline)"}

KEV_URL = "https://www.cisa.gov/sites/default/files/feeds/known_exploited_vulnerabilities.json"
KEV_MIRROR = "https://raw.githubusercontent.com/aboutcode-org/aboutcode-mirror-kev/main/known_exploited_vulnerabilities.json"
EPSS_URL = "https://epss.empiricalsecurity.com/epss_scores-current.csv.gz"
NVD_URL = "https://services.nvd.nist.gov/rest/json/cves/2.0"

BATCH_ID = None  # set from --batch-id CLI arg or auto-generated


def out_path(load, name):
    if load == "full":
        folder = BASE / "full_load"
    else:
        batch = BATCH_ID or datetime.now(timezone.utc).strftime("%Y-%m-%d_%H%M%S")
        folder = BASE / "incremental" / batch
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

    if load == "full":
        kev_file = "kev_full_sample.json"
    else:
        # CISA has no delta API — download the full catalog, then filter
        # to only entries added in the last 24 hours for the daily delta.
        cutoff = (datetime.now(timezone.utc) - timedelta(days=1)).strftime("%Y-%m-%d")
        all_entries = data["vulnerabilities"]
        new_entries = [v for v in all_entries if v["dateAdded"] >= cutoff]
        data["vulnerabilities"] = new_entries
        kev_file = f"kev_{BATCH_ID}.json"
        print(f"KEV: {len(new_entries)} new entries in last 24h (of {len(all_entries)} total)")

    path = out_path(load, kev_file)
    path.write_text(json.dumps(data, indent=2))
    print(f"Saved {path} ({len(data['vulnerabilities'])} entries)")


def fetch_epss_full_raw(date=None):
    url = EPSS_URL if date is None else f"https://epss.empiricalsecurity.com/epss_scores-{date}.csv.gz"
    r = requests.get(url, headers=HEADERS, timeout=120, allow_redirects=True)
    r.raise_for_status()
    text = gzip.decompress(r.content).decode("utf-8")
    lines = text.splitlines()
    header_line = lines[0]
    rows = {}
    for line in lines[2:]:
        cve, epss, pct = line.split(",")
        rows[cve] = (float(epss), float(pct))
    return rows, header_line


def fetch_epss_filtered_by_nvd(nvd_file):
    """Fetch EPSS scores only for CVEs present in the NVD sample."""
    with open(nvd_file) as f:
        nvd_data = json.load(f)
    nvd_cves = {v["cve"]["id"] for v in nvd_data["vulnerabilities"]}
    print(f"NVD sample has {len(nvd_cves)} CVEs")

    r = requests.get(EPSS_URL, headers=HEADERS, timeout=120, allow_redirects=True)
    r.raise_for_status()
    text = gzip.decompress(r.content).decode("utf-8")
    lines = text.splitlines()
    header_line = lines[0]

    matches = []
    for line in lines[2:]:
        cve = line.split(",")[0]
        if cve in nvd_cves:
            matches.append(line)

    path = out_path("full", "epss_full_sample.csv")
    with open(path, "w") as f:
        f.write(header_line + "\ncve,epss,percentile\n")
        for line in matches:
            f.write(line + "\n")

    print(f"Saved {path} ({len(matches)} matching EPSS rows)")


def fetch_epss(load, max_rows=None, date=None, baseline_date=None):
    """Fetch EPSS scores.

    Both full and incremental load a complete daily snapshot — EPSS scores
    shift entirely each day, so a full reload is always required.
    """
    if load == "full":
        epss_file = "epss_full_sample.csv"
    else:
        epss_file = f"epss_{BATCH_ID}.csv"

    rows, header_line = fetch_epss_full_raw(date)
    items = list(rows.items()) if max_rows is None else list(rows.items())[:max_rows]
    path = out_path(load, epss_file)
    with open(path, "w") as f:
        f.write(header_line + "\ncve,epss,percentile\n")
        for cve, (epss, pct) in items:
            f.write(f"{cve},{epss},{pct}\n")
    print(f"Saved {path} ({len(items)} rows). First line: {header_line}")


def fetch_nvd(load, days=1, per_page=2000, start_year=2019):
    """Fetch NVD CVEs.

    full load: paginate through 120-day windows from start_year (1999) to present.
    incremental load: fetch CVEs modified in the last `days` days.
    """
    headers = dict(HEADERS)
    key = os.getenv("NVD_API_KEY")
    if key:
        headers["apiKey"] = key
        print("Using NVD API key")
    else:
        print("Warning: NVD_API_KEY not set (5 requests / 30s limit)")

    fmt = "%Y-%m-%dT%H:%M:%S.000"
    end = datetime.now(timezone.utc)
    delay = 0.6 if key else 6.0

    if load == "incremental":
        start = end - timedelta(days=days)
        params = {
            "resultsPerPage": per_page,
            "startIndex": 0,
            "lastModStartDate": start.strftime(fmt),
            "lastModEndDate": end.strftime(fmt),
        }
        all_vulns = []
        while True:
            r = requests.get(NVD_URL, headers=headers, params=params, timeout=120)
            r.raise_for_status()
            data = r.json()
            vulns = data.get("vulnerabilities", [])
            all_vulns.extend(vulns)
            total = data.get("totalResults", 0)
            start_idx = params["startIndex"] + len(vulns)
            if start_idx >= total:
                break
            params["startIndex"] = start_idx
            time.sleep(delay)

        output = {
            "resultsPerPage": len(all_vulns),
            "startIndex": 0,
            "totalResults": len(all_vulns),
            "format": "NVD_CVE",
            "version": "2.0",
            "vulnerabilities": all_vulns,
        }
        path = out_path(load, f"nvd_{BATCH_ID}.json")
        path.write_text(json.dumps(output, indent=2))
        print(f"Saved {path} ({len(all_vulns)} of {total} total CVEs)")
        return

    # ---- full load: paginate 120-day windows from start_year to present ----
    window_start = datetime(start_year, 1, 1, tzinfo=timezone.utc)
    window_size = timedelta(days=120)
    all_vulns = []
    window_num = 0

    while window_start < end:
        window_end = min(window_start + window_size, end)
        params = {
            "resultsPerPage": per_page,
            "startIndex": 0,
            "pubStartDate": window_start.strftime(fmt),
            "pubEndDate": window_end.strftime(fmt),
        }
        window_total = 0
        while True:
            r = requests.get(NVD_URL, headers=headers, params=params, timeout=120)
            r.raise_for_status()
            data = r.json()
            vulns = data.get("vulnerabilities", [])
            all_vulns.extend(vulns)
            window_total = data.get("totalResults", 0)
            start_idx = params["startIndex"] + len(vulns)
            if start_idx >= window_total:
                break
            params["startIndex"] = start_idx
            time.sleep(delay)

        window_num += 1
        print(f"Window {window_num} ({window_start.strftime('%Y-%m-%d')} → {window_end.strftime('%Y-%m-%d')}): "
              f"{window_total} CVEs | cumulative: {len(all_vulns)}")
        window_start = window_end
        time.sleep(delay)

    output = {
        "resultsPerPage": len(all_vulns),
        "startIndex": 0,
        "totalResults": len(all_vulns),
        "format": "NVD_CVE",
        "version": "2.0",
        "vulnerabilities": all_vulns,
    }
    path = out_path(load, f"nvd_cves_{load}_sample.json")
    path.write_text(json.dumps(output, indent=2))
    print(f"Saved {path} ({len(all_vulns)} total CVEs from {start_year} to present)")


def fetch_nvd_for_kev(kev_file, max_windows=5):
    """Fetch NVD data for CVEs that are in the KEV catalog.
    Uses multiple 120-day windows (NVD API max range)."""
    import time

    with open(kev_file) as f:
        kev_data = json.load(f)
    kev_cves = {v["cveID"] for v in kev_data["vulnerabilities"]}
    print(f"KEV catalog has {len(kev_cves)} CVEs")

    headers = dict(HEADERS)
    key = os.getenv("NVD_API_KEY")
    if key:
        headers["apiKey"] = key
        print("Using NVD API key")
    else:
        print("Warning: NVD_API_KEY not set (5 requests / 30s limit)")

    matched_vulns = []
    seen_ids = set()
    fmt = "%Y-%m-%dT%H:%M:%S.000"
    end = datetime.now(timezone.utc)

    for window in range(max_windows):
        window_end = end - timedelta(days=window * 120)
        window_start = window_end - timedelta(days=120)

        params = {
            "resultsPerPage": 2000,
            "startIndex": 0,
            "lastModStartDate": window_start.strftime(fmt),
            "lastModEndDate": window_end.strftime(fmt),
        }

        r = requests.get(NVD_URL, headers=headers, params=params, timeout=120)
        r.raise_for_status()
        data = r.json()

        page_vulns = data.get("vulnerabilities", [])
        page_matches = [v for v in page_vulns
                        if v["cve"]["id"] in kev_cves and v["cve"]["id"] not in seen_ids]

        for v in page_matches:
            seen_ids.add(v["cve"]["id"])
        matched_vulns.extend(page_matches)

        print(f"Window {window + 1} ({window_start.strftime('%Y-%m-%d')} to {window_end.strftime('%Y-%m-%d')}): {len(page_vulns)} CVEs, {len(page_matches)} KEV matches (cumulative: {len(matched_vulns)})")

        if not key:
            time.sleep(6)

    output = {
        "resultsPerPage": len(matched_vulns),
        "startIndex": 0,
        "totalResults": len(matched_vulns),
        "format": "NVD_CVE",
        "version": "2.0",
        "vulnerabilities": matched_vulns,
    }

    path = out_path("full", "nvd_cves_for_kev_sample.json")
    path.write_text(json.dumps(output, indent=2))
    print(f"Saved {path} ({len(matched_vulns)} KEV-matched NVD CVEs)")


if __name__ == "__main__":
    ap = argparse.ArgumentParser()
    ap.add_argument("source", choices=["kev", "epss", "nvd", "epss_filtered", "nvd_for_kev"])
    ap.add_argument("--load", choices=["full", "incremental"], required=True)
    ap.add_argument("--days", type=int, default=1, help="NVD incremental window in days (default: 1 = 24h)")
    ap.add_argument("--date", type=str, default=None, help="EPSS: pull a specific historical date (YYYY-MM-DD)")
    ap.add_argument("--baseline-date", type=str, default=None, help="EPSS: the full-load date to diff against")
    ap.add_argument("--start-year", type=int, default=2019, help="NVD full load: start year for historical fetch")
    ap.add_argument("--batch-id", type=str, default=None, help="Incremental: batch ID for timestamped folder/filenames")
    a = ap.parse_args()

    BATCH_ID = a.batch_id

    if a.source == "kev":
        fetch_kev(a.load)
    elif a.source == "epss":
        fetch_epss(a.load, date=a.date, baseline_date=a.baseline_date)
    elif a.source == "epss_filtered":
        fetch_epss_filtered_by_nvd("data/sample_raw/full_load/nvd_cves_full_sample.json")
    elif a.source == "nvd_for_kev":
        fetch_nvd_for_kev("data/sample_raw/full_load/kev_full_sample.json")
    else:
        fetch_nvd(a.load, a.days, start_year=a.start_year)