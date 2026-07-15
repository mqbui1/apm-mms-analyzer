"""Fetcher for custom (IM) metrics data — engineering CSV export."""
from __future__ import annotations

import csv
import json


def read_from_csv(file_path: str) -> list[dict]:
    """
    Parse the engineering custom metrics CSV export.

    Expected columns:
        METRIC_NAME, CATEGORY_TYPE, DETECTORS, CHARTS, MTS_COUNT,
        COMMON_DIMENSIONS, DIMENSION_CARDINALITY, MTS_PER_TOKEN, EXAMPLE_MTS

    Returns list of dicts with normalised fields.
    """
    rows = []
    with open(file_path, newline="", encoding="utf-8") as fh:
        reader = csv.DictReader(fh)
        for row in reader:
            mts = _parse_int(row.get("MTS_COUNT", "0"))
            if mts == 0:
                continue

            dim_card: dict = {}
            try:
                raw = row.get("DIMENSION_CARDINALITY") or "{}"
                dim_card = json.loads(raw)
            except Exception:
                pass

            mts_per_token: dict = {}
            try:
                raw = row.get("MTS_PER_TOKEN") or "{}"
                mts_per_token = json.loads(raw)
            except Exception:
                pass

            example_mts: dict = {}
            try:
                raw = row.get("EXAMPLE_MTS") or "{}"
                example_mts = json.loads(raw)
            except Exception:
                pass

            rows.append({
                "metric_name":          row.get("METRIC_NAME", "").strip('"').strip(),
                "category_type":        row.get("CATEGORY_TYPE", ""),
                "mts_count":            mts,
                "dimension_cardinality": dim_card,
                "mts_per_token":        {str(k): int(v) for k, v in mts_per_token.items()},
                "example_mts":          example_mts,
            })
    return rows


def _parse_int(val: str) -> int:
    try:
        return int(str(val).replace(",", ""))
    except Exception:
        return 0
