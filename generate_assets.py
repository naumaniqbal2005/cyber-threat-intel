"""
generate_assets.py
Builds a synthetic asset inventory for the fictional company "Cortexa".
Software/versions are chosen to fall inside (or just outside) real affected
ranges found in data/sample_raw/full_load/nvd_cves_full_sample.json, so the
Silver/Gold layers can join assets to CVEs.

Usage (from repo root):
    python generate_assets.py                # writes to data/sample_raw/
    python generate_assets.py --out some/dir

Fixed seed => same output every run.

PII-style columns (hashed / dropped in Silver per the proposal):
    hostname, ip_address -> SHA-256 hash | owner_email -> dropped
"""
import argparse
import csv
import random
from datetime import date, timedelta
from pathlib import Path

SEED = 42
FULL_SCAN_DATE = date(2026, 9, 29)
INCR_DATE = date(2026, 9, 30)

# bad  = versions inside a real CVE affected range (NVD vendor/product names)
# good = version outside every range seen (empty = no fix exists)
CATALOG = {
    "search_frontend": {
        "count": 12, "subnet": "10.10.1", "prefix": "search",
        "criticality": ["high", "high", "critical", "medium"],
        "products": [
            dict(vendor="remix-run", product="react-router", slug="rrouter", weight=3,
                 bad=["7.12.0", "7.13.1", "6.30.2"], good=["7.14.1"]),
            dict(vendor="dedecms", product="DedeCMS", slug="cms", weight=1,
                 bad=["5.7.88"], good=[]),
        ],
    },
    "data_pipeline": {
        "count": 12, "subnet": "10.20.2", "prefix": "dp",
        "criticality": ["critical", "high", "high", "medium"],
        "products": [
            dict(vendor="aio-libs", product="aiohttp", slug="aiohttp", weight=3,
                 bad=["3.12.15", "3.13.2"], good=["3.14.1"]),
            dict(vendor="AWS", product="Graph Explorer", slug="graphx", weight=1,
                 bad=["2.4.0", "3.0.0"], good=["3.0.1"]),
        ],
    },
    "corporate_it": {
        "count": 14, "subnet": "10.30.3", "prefix": "it",
        "criticality": ["medium", "medium", "high", "low"],
        "products": [
            dict(vendor="goauthentik", product="authentik", slug="sso", weight=2,
                 bad=["2025.12.3", "2026.2.1"], good=["2026.2.3"]),
            dict(vendor="SolarWinds", product="Web Help Desk", slug="whd", weight=2,
                 bad=["2025.2", "2026.1"], good=["2026.2"]),
            dict(vendor="Mozilla", product="Firefox", slug="wks", weight=4,
                 bad=["150.0.2", "151.0.1"], good=["151.0.3"]),
        ],
    },
    "internal_tools": {
        "count": 12, "subnet": "10.40.4", "prefix": "tool",
        "criticality": ["medium", "medium", "low", "high"],
        "products": [
            dict(vendor="nextlevelbuilder", product="GoClaw", slug="goclaw", weight=2,
                 bad=["3.11.0", "3.11.2", "3.11.3"], good=["3.11.4"]),  # 3.11.4 = synthetic fix
            dict(vendor="pterodactyl", product="panel", slug="panel", weight=2,
                 bad=["1.11.9", "1.12.1"], good=["1.12.3"]),
        ],
    },
}

FIRST = ["ayesha", "bilal", "hamza", "sana", "usman", "maryam", "zain", "hira", "talha", "noor"]
LAST = ["khan", "malik", "raza", "sheikh", "butt", "qureshi", "ahmed", "javed"]
ENVS = ["prod", "staging", "dev"]
ENV_W = [0.6, 0.25, 0.15]

FIELDS = ["asset_id", "hostname", "ip_address", "software_vendor", "software_product",
          "software_version", "asset_group", "environment", "business_criticality",
          "owner_email", "patch_status", "last_patched_date", "last_scanned_date"]


def make_asset(rng, n, group, cfg, host_no, scan_date, force_vulnerable=False):
    prod = rng.choices(cfg["products"], weights=[p["weight"] for p in cfg["products"]])[0]
    env = rng.choices(ENVS, weights=ENV_W)[0]
    vulnerable = force_vulnerable or not prod["good"] or rng.random() < 0.65
    if vulnerable:
        version = rng.choice(prod["bad"])
        status = rng.choices(["unpatched", "patch_pending"], weights=[0.7, 0.3])[0]
        patched = scan_date - timedelta(days=rng.randint(60, 200))  # last routine patch cycle
    else:
        version = rng.choice(prod["good"])
        status = "patched"
        patched = scan_date - timedelta(days=rng.randint(1, 30))
    return {
        "asset_id": f"A-{n:04d}",
        "hostname": f"{cfg['prefix']}-{prod['slug']}-{env}-{host_no:02d}.cortexa.internal",
        "ip_address": f"{cfg['subnet']}.{10 + host_no}",
        "software_vendor": prod["vendor"],
        "software_product": prod["product"],
        "software_version": version,
        "asset_group": group,
        "environment": env,
        "business_criticality": rng.choice(cfg["criticality"]),
        "owner_email": f"{rng.choice(FIRST)}.{rng.choice(LAST)}@cortexa.example",
        "patch_status": status,
        "last_patched_date": patched.isoformat(),
        "last_scanned_date": scan_date.isoformat(),
    }


def product_of(row):
    for g in CATALOG.values():
        for p in g["products"]:
            if p["vendor"] == row["software_vendor"] and p["product"] == row["software_product"]:
                return p


def build_full(rng):
    rows, n = [], 1
    for group, cfg in CATALOG.items():
        for host_no in range(1, cfg["count"] + 1):
            rows.append(make_asset(rng, n, group, cfg, host_no, FULL_SCAN_DATE))
            n += 1
    return rows


def build_incremental(rng, full):
    out, used = [], set()

    def emit(row, change):
        row = dict(row, change_type=change, last_updated=INCR_DATE.isoformat(),
                   last_scanned_date=INCR_DATE.isoformat())
        out.append(row)
        used.add(row["asset_id"])

    # 1) three vulnerable assets get patched
    fixable = [r for r in full if r["patch_status"] != "patched" and product_of(r)["good"]]
    for r in rng.sample(fixable, 3):
        emit(dict(r, software_version=rng.choice(product_of(r)["good"]),
                  patch_status="patched", last_patched_date=INCR_DATE.isoformat()), "UPDATE")

    # 2) one upgrade that is still vulnerable
    multi = [r for r in full if r["asset_id"] not in used and len(product_of(r)["bad"]) > 1
             and r["patch_status"] != "patched"]
    r = rng.choice(multi)
    other = [v for v in product_of(r)["bad"] if v != r["software_version"]]
    emit(dict(r, software_version=rng.choice(other), patch_status="unpatched"), "UPDATE")

    # 3) two new servers
    next_id = len(full) + 1
    for i, group in enumerate(rng.sample(list(CATALOG), 2)):
        cfg = CATALOG[group]
        emit(make_asset(rng, next_id + i, group, cfg, cfg["count"] + 1, INCR_DATE,
                        force_vulnerable=True), "INSERT")

    # 4) one decommissioned server
    gone = rng.choice([r for r in full if r["asset_id"] not in used])
    emit(dict(gone, patch_status="decommissioned"), "DELETE")
    return out


def write_csv(path, rows, fields):
    path.parent.mkdir(parents=True, exist_ok=True)
    with open(path, "w", newline="", encoding="utf-8") as f:
        w = csv.DictWriter(f, fieldnames=fields)
        w.writeheader()
        w.writerows(rows)
    print(f"wrote {len(rows):>3} rows -> {path}")


if __name__ == "__main__":
    ap = argparse.ArgumentParser()
    ap.add_argument("--out", default="data/sample_raw")
    out = Path(ap.parse_args().out)

    rng = random.Random(SEED)
    full = build_full(rng)
    incr = build_incremental(rng, full)
    write_csv(out / "full_load" / "cortexa_assets_full_sample.csv", full, FIELDS)
    write_csv(out / "incremental" / "cortexa_assets_incremental_sample.csv", incr,
              FIELDS + ["change_type", "last_updated"])