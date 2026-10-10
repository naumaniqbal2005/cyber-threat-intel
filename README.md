# Cyber Threat Intelligence Pipeline (Bronze + Silver)

Phase 2 of our Spark/Databricks medallion pipeline. It ingests vulnerability data (NVD), exploit-likelihood scores (EPSS), known-exploited vulnerabilities (CISA KEV) and a synthetic asset inventory (Cortexa) into **Bronze** Delta tables, then merges the three CVE feeds into one deduplicated **Silver** table.

**Team:** _<name 1>, <name 2>_

---

## 1. Architecture

```
data/sample_raw/                    Bronze (Delta, append-only)            Silver (Delta, MERGE)
  full_load/*          ──►  01_landing_to_bronze  ──►  bronze_nvd    ─┐
  incremental/<batch>/*                                bronze_epss    ├─►  02_bronze_to_silver  ──►  silver_cve_unified
                                                       bronze_kev    ─┘
                                                       bronze_assets   (not used in Silver yet)

Every load writes a row to pipeline_execution_logs.
```

All tables live in `<current catalog>.cyber_threat`.

## 2. Repository layout

| Path | Purpose |
|---|---|
| `notebooks/00_config_and_logging` | Table names, explicit source schemas, log table and `write_log()` helper. Pulled in by the other notebooks with `%run`. |
| `notebooks/00b_reset_bronze` | Truncates the Bronze tables (and optionally the log table) for a clean re-run. |
| `notebooks/01_landing_to_bronze` | Raw files to Bronze. Supports `full`, `incremental` and `backfill` loads and detects schema changes. |
| `notebooks/02_bronze_to_silver` | Dedup, flatten, join, then `MERGE` into the Silver table. |
| `data/sample_raw/full_load/` | Full-load sample files for each source. |
| `data/sample_raw/incremental/<YYYY-MM-DD_HHMMSS>/` | One folder per incremental batch (`epss_<batch>.csv`, `kev_<batch>.json`, `nvd_<batch>.json`). |
| `data/sample_raw/incremental/2026-10-01_000000/` | Schema change demo batch (see section 7). |
| `fetch_samples.py` | Downloads the raw source files. `full` mode builds the full-load samples; `incremental` mode writes one timestamped batch folder with `epss_<batch>.csv`, `kev_<batch>.json` and `nvd_<batch>.json`. |
| `.github/workflows/daily_incremental_fetch.yml` | GitHub Actions job that runs `fetch_samples.py` every day at 00:00 UTC (or manually) and commits a new batch folder under `data/sample_raw/incremental/`. |

## 3. Data sources

| Source | Format | Used for |
|---|---|---|
| NVD CVE feed | JSON (wrapper object with a nested `vulnerabilities` array) | CVE details, CVSS metrics, CWE weaknesses |
| EPSS | CSV (comment header line starting with `#`) | Exploit prediction score and percentile per CVE |
| CISA KEV | JSON (wrapper object with a `vulnerabilities` array) | CVEs known to be exploited, due dates, ransomware use |
| Cortexa assets | CSV (synthetic) | Fictional company asset inventory, matched to real CVEs |

**How the raw files are produced** (`fetch_samples.py`):
- **NVD:** the full load pages through 120-day publication windows; an incremental batch contains the CVEs modified in the last 24 hours.
- **EPSS:** both full and incremental files are a complete daily snapshot, because EPSS scores shift every day.
- **KEV:** the full load is the whole CISA catalog; an incremental batch contains only entries added in the last 24 hours, so it can be empty or very small.
- **Assets:** the Cortexa inventory is synthetic and only exists as a full-load file. The daily workflow does not generate asset files.

## 4. Data models

### 4.1 Bronze

Bronze keeps the source structure as read with an **explicit schema** (defined in `00_config_and_logging`). Every Bronze table also gets three audit columns: `load_timestamp TIMESTAMP`, `source_file STRING`, `load_type STRING`. Bronze is **append-only**: every load adds rows and nothing is updated or deleted.

**`bronze_epss`**

| Column | Type |
|---|---|
| cve | STRING |
| epss | DOUBLE |
| percentile | DOUBLE |

**`bronze_kev`** (one row per entry of `vulnerabilities[]`)

| Column | Type |
|---|---|
| cveID, vendorProject, product, vulnerabilityName, shortDescription, requiredAction, knownRansomwareCampaignUse, forensicTriage, notes | STRING |
| dateAdded, dueDate | STRING (cast to DATE in Silver) |
| cwes | ARRAY&lt;STRING&gt; |

**`bronze_nvd`** (one row per `vulnerabilities[].cve`)

| Column | Type |
|---|---|
| id | STRING (the CVE id) |
| sourceIdentifier, vulnStatus | STRING |
| published, lastModified | TIMESTAMP |
| descriptions | ARRAY&lt;STRUCT&lt;lang, value&gt;&gt; |
| metrics | STRUCT of `cvssMetricV2`, `cvssMetricV30`, `cvssMetricV31`, `cvssMetricV40` (each an array of structs holding `cvssData`, `exploitabilityScore`, `impactScore`, ...) |
| weaknesses | ARRAY&lt;STRUCT&lt;source, type, description[]&gt;&gt; |
| affected | ARRAY&lt;STRUCT&lt;source, affectedData[]&gt;&gt; |
| references | ARRAY&lt;STRUCT&lt;url, source, tags[]&gt;&gt; |

**`bronze_assets`** (full load): `asset_id, hostname, ip_address, os_name, os_version, software_name, software_version, department, owner, criticality, exposure, environment, location, status` (all STRING). Incremental asset files use a slimmer schema with a `change_type` column instead of the descriptive columns.

### 4.2 Silver

**`silver_cve_unified`**: one row per CVE, **key = `cve_id`**. NVD is the base table; EPSS and KEV are left-joined on `cve_id`.

| Column | Type | Source / logic |
|---|---|---|
| cve_id | STRING | NVD `id` (EPSS `cve` and KEV `cveID` renamed to match) |
| description | STRING | English entry of NVD `descriptions` |
| cvss_v31_score / cvss_v30_score / cvss_v2_score | DOUBLE | First metric of each CVSS version |
| cvss_v31_severity / cvss_v30_severity / cvss_v2_severity | STRING | Same |
| cvss_v31_vector | STRING | CVSS v3.1 vector string |
| cvss_base_score, cvss_severity | DOUBLE, STRING | `coalesce` of v3.1, then v3.0, then v2 |
| cvss_vector | STRING | v3.1 vector |
| cwe_ids | ARRAY&lt;STRING&gt; | Flattened `weaknesses[].description[].value` |
| vuln_status, source_identifier | STRING | NVD |
| published_date, last_modified | TIMESTAMP | NVD `published`, `lastModified` |
| epss_score, epss_percentile | DOUBLE | EPSS |
| kev_date_added, kev_due_date | DATE | KEV (cast from string) |
| vendor_project, product, vulnerability_name, short_description, required_action, known_ransomware_use, kev_notes | STRING | KEV |
| kev_cwes | ARRAY&lt;STRING&gt; | KEV `cwes` |
| is_in_kev | BOOLEAN | `true` when `kev_date_added` is not null |
| silver_load_timestamp | TIMESTAMP | Time the row was built |

**Deduplication before the join** (`row_number()` per `cve_id`, keep rank 1):
- NVD: newest `lastModified`, ties broken by newest `load_timestamp`
- EPSS and KEV: newest `load_timestamp`

## 5. Run instructions

**Requirements:** Databricks workspace with the repo cloned under `/Workspace/Users/<you>/cyber-threat-intel`, attached to **General/serverless compute** (not a SQL warehouse, the notebooks use PySpark).

`01_landing_to_bronze` has three widgets:

| Widget | Values | Notes |
|---|---|---|
| `load_type` | `full`, `incremental`, `backfill` | Press Enter after editing |
| `batch_id` | e.g. `2026-10-09_185004` | Only used for `backfill` |
| `repo_path` | `/Workspace/Users/<you>/cyber-threat-intel` | Set to your own workspace path |

### Clean start (optional)
Run `00b_reset_bronze`. It truncates the four Bronze tables and, if `reset_log = True`, the log table too. Set `reset_log = False` to keep the log history. It does **not** touch Silver; to reset Silver as well run `DROP TABLE IF EXISTS <catalog>.cyber_threat.silver_cve_unified`.

### Full load
1. `01_landing_to_bronze` with `load_type = full`, Run all.
2. `02_bronze_to_silver`, Run all.

### Incremental load
1. `01_landing_to_bronze` with `load_type = incremental`. It automatically picks the **latest** folder under `data/sample_raw/incremental/`.
2. `02_bronze_to_silver`, Run all.

### Backfill
Loads a specific, usually older, batch into Bronze.
1. `01_landing_to_bronze` with `load_type = backfill` and `batch_id` set to an existing folder name. An unknown batch id raises an error that lists the available batches.
2. `02_bronze_to_silver`, Run all.

Because Silver is merged on `cve_id` and the dedup/`MERGE` conditions compare `last_modified`, an older backfilled record does not overwrite a newer one.

> Always run Bronze first, then Silver. Silver only reads whatever is already in Bronze.

## 6. How the MERGE avoids duplicates

Silver is written by `02_bronze_to_silver` with:

```sql
MERGE INTO silver_cve_unified t
USING silver_updates s
ON t.cve_id = s.cve_id
WHEN MATCHED AND (
       s.last_modified > t.last_modified
    OR NOT (s.epss_score <=> t.epss_score)
    OR NOT (s.is_in_kev   <=> t.is_in_kev)
) THEN UPDATE SET *
WHEN NOT MATCHED THEN INSERT *
```

- `cve_id` is the merge key, so a CVE that already exists is never inserted twice.
- A matched row is only updated if something actually changed (newer NVD version, changed EPSS score, changed KEV flag). `<=>` is a null-safe comparison.
- Bronze can contain repeated rows (it is append-only and EPSS is a full snapshot every day), but the dedup step reduces each source to one row per CVE before the MERGE.
- The notebook ends with a duplicate check (`total rows` vs `distinct cve_id`) and logs the real inserted/updated counts taken from Delta's MERGE metrics.

**Re-running the same load inserts 0 rows and updates 0 rows.**

## 7. Schema change handling

- All sources are read with explicit schemas, so types are enforced and nothing is inferred. The schemas can be printed with `printSchema()` at the end of `01_landing_to_bronze` (Bronze) and `02_bronze_to_silver` (Silver).
- **EPSS** has drift detection (`csv_header()` and `detect_drift()` in `01_landing_to_bronze`): the incoming file's header is compared with the expected schema before loading.
  - **New columns** are kept, read as STRING, and added to `bronze_epss` with `mergeSchema`.
  - **Missing columns** are filled with NULL.
  - Every change is written to the log table with `status = 'Schema Change'` and the details in `error_message` (e.g. `added=['epss_trend'] | missing=[]`).
- KEV, NVD and asset files are read with their explicit schemas; unexpected extra fields in them are ignored rather than detected.
- Silver selects its columns explicitly, so a new Bronze column does not automatically appear in Silver. It has to be added on purpose.

**Try it yourself:** the batch folder `data/sample_raw/incremental/2026-10-01_000000` contains an EPSS file with an extra column (`epss_trend`) and made-up CVE ids that never reach Silver. In `01_landing_to_bronze` set `load_type = backfill` and `batch_id = 2026-10-01_000000`, then Run all. The log shows a `Schema Change` row, `bronze_epss` gains the `epss_trend` column, and the KEV, NVD and asset loads are logged as `Skipped` because this batch has no files for them. Normal `incremental` runs ignore this folder because it sorts before the real batches. Don't run `02_bronze_to_silver` after this batch.

## 8. Log table: `pipeline_execution_logs`

One row per load of one source into one table.

| Column | Meaning |
|---|---|
| run_id | UUID per source load |
| layer | `Raw-to-Bronze` or `Bronze-to-Silver` |
| load_type | `full`, `incremental`, `backfill`, or `merge` (Silver) |
| source_param | Source file name (or `bronze_*` for Silver) |
| target_table | Table written |
| start_time, end_time, load_timestamp | Timing |
| status | `Success`, `Failure`, `Skipped`, or `Schema Change` |
| rows_inserted, rows_updated | Row counts (Silver values come from the MERGE metrics) |
| error_message | Error text, skip reason, or schema change details |

`Skipped` is logged when an incremental/backfill batch has no file for a source (assets, KEV or NVD). Failures are logged and then re-raised.

> **Note on the log:** the `Failure` row for `kev_2026-10-01_000000.json` comes from an earlier test run of the schema-change batch, before skip handling was added to the KEV and NVD loads. The later run of the same batch shows the final behaviour (`Skipped`). We left the row in the log on purpose instead of deleting history.

## 9. Results from our runs

| Step | Silver MERGE result | Silver rows | Duplicates |
|---|---|---|---|
| Full load | 500 inserted, 0 updated | 500 | 0 |
| Re-run of the same MERGE | 0 inserted, 0 updated | 500 | 0 |
| Incremental batch `2026-10-10_045631` | 1,177 inserted, 0 updated | 1,677 | 0 |
| Re-run | 0 inserted, 0 updated | 1,677 | 0 |
| Backfill batch `2026-10-09_185004` | 1,188 inserted, 0 updated | 2,865 | 0 |
| Re-run | 0 inserted, 0 updated | 2,865 | 0 |
| Schema change batch `2026-10-01_000000` (extra `epss_trend` column) | Logged as `Schema Change`, column added to `bronze_epss`, KEV/NVD/assets `Skipped` | n/a | n/a |

## 10. Known limitations

- Bronze is append-only, so repeated loads stack rows there. Silver stays clean because of the dedup and MERGE. Use `00b_reset_bronze` for a clean start.
- EPSS publishes a full snapshot each day, so each EPSS incremental batch is as large as the full load.
- `bronze_assets` is loaded by the full load but not used in Silver yet. The daily workflow does not produce asset files, so incremental and backfill loads log the asset step as `Skipped`.
- Schema drift detection is implemented for EPSS only.
- The MERGE only updates on newer NVD data, changed EPSS score, or changed KEV flag; other KEV field changes alone do not trigger an update.
- The daily workflow keeps adding new batch folders, so a later `incremental` run loads a newer batch than the one in the results table (section 9) and the counts will differ. The `backfill` batches named in this README stay fixed.