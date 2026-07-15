"""Splunk API client for fetching APM MMS (Monitoring MetricSets) data."""
from __future__ import annotations

import csv
import io
import time
from concurrent.futures import ThreadPoolExecutor, as_completed
from typing import Optional

import requests


def _api_get(path: str, params: dict, token: str, realm: str) -> dict:
    base = f"https://api.{realm}.signalfx.com"
    headers = {"X-SF-TOKEN": token, "Content-Type": "application/json"}
    for attempt in range(3):
        resp = requests.get(f"{base}{path}", headers=headers, params=params, timeout=30)
        if resp.status_code in (429,) or resp.status_code >= 500:
            if attempt < 2:
                time.sleep(2 ** attempt)
                continue
        resp.raise_for_status()
        return resp.json()
    return {}


def fetch_from_splunk(
    token: str,
    realm: str,
    environment: Optional[str] = None,
    hard_limit: int = 0,
) -> list[dict]:
    """
    Fetch all APM MMS rows from Splunk Observability API.

    Uses the _exists_:sf_mms_id filter to retrieve all APM Monitoring MetricSet
    time series. Returns one dict per MTS_ID (raw, not deduplicated) matching
    the engineering export format.

    Each dict: {"mts_id": str, "operation": str, "service": str, "environment": str}
    """
    query = "_exists_:sf_mms_id"
    if environment:
        env_q = f'"{environment}"' if " " in environment else environment
        query += f" AND sf_environment:{env_q}"

    page_size = 10_000

    # Page 0: get total count + first page
    try:
        first = _api_get("/v2/metrictimeseries", {
            "query": query, "limit": page_size, "offset": 0,
        }, token, realm)
    except Exception as e:
        raise RuntimeError(f"Splunk API error: {e}") from e

    total_count = first.get("count", 0)
    first_results = first.get("results", [])

    if total_count == 0:
        return []

    effective_limit = hard_limit if hard_limit > 0 else total_count
    fetch_up_to = min(total_count, effective_limit)
    n_pages = (fetch_up_to + page_size - 1) // page_size
    offsets = [i * page_size for i in range(1, n_pages)]

    print(f"  {total_count:,} total MTS in org — fetching {fetch_up_to:,} across {n_pages} page(s) in parallel...", flush=True)
    if total_count > effective_limit:
        print(f"  Warning: truncating to {effective_limit:,}. Set MMS_FETCH_LIMIT=0 or --limit 0 to fetch all.", flush=True)

    all_results: list = list(first_results)

    if offsets:
        def _fetch_page(offset: int) -> list:
            return _api_get("/v2/metrictimeseries", {
                "query": query, "limit": page_size, "offset": offset,
            }, token, realm).get("results", [])

        workers = min(8, len(offsets))
        with ThreadPoolExecutor(max_workers=workers) as pool:
            futures = {pool.submit(_fetch_page, off): off for off in offsets}
            done = 0
            for fut in as_completed(futures):
                done += 1
                try:
                    all_results.extend(fut.result())
                except Exception as e:
                    print(f"  Warning: page fetch error: {e}")
                print(f"  {done}/{len(offsets)} pages done...", end="\r", flush=True)
        print()

    ops = []
    for mts in all_results:
        dims = mts.get("dimensions", {})
        op = dims.get("sf_operation", "")
        if not op:
            continue
        ops.append({
            "mts_id":      mts.get("id", ""),
            "operation":   op,
            "service":     dims.get("sf_service", ""),
            "environment": dims.get("sf_environment", ""),
        })

    return ops


def read_from_tsv(file_path: str) -> list[dict]:
    """
    Parse a raw MMS dump file in the engineering export format:
        MTS_ID\\t"operation"\\t"service"\\t"environment"

    Returns list of dicts with the same shape as fetch_from_splunk().
    """
    ops = []
    with open(file_path, encoding="utf-8") as fh:
        for line in fh:
            line = line.rstrip("\n")
            if not line:
                continue
            # Tab-separated; values may be quoted
            reader = csv.reader(io.StringIO(line), delimiter="\t", quotechar='"')
            for parts in reader:
                if len(parts) < 4:
                    continue
                mts_id, operation, service, environment = parts[0], parts[1], parts[2], parts[3]
                if not operation:
                    continue
                ops.append({
                    "mts_id":      mts_id.strip(),
                    "operation":   operation.strip(),
                    "service":     service.strip(),
                    "environment": environment.strip(),
                })
    return ops


def write_tsv(ops: list[dict], file_path: str) -> None:
    """Write ops list to a TSV file matching the engineering export format."""
    with open(file_path, "w", encoding="utf-8") as fh:
        for op in ops:
            fh.write(f'{op["mts_id"]}\t"{op["operation"]}"\t"{op["service"]}"\t"{op["environment"]}"\n')
