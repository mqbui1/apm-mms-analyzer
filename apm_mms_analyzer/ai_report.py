"""
Claude (via AWS Bedrock) analysis of APM MMS data.

Builds a structured prompt from the deterministic analysis results and calls
Claude to produce an actionable narrative report with prioritized remediation
steps and OTel Collector config snippets.
"""
from __future__ import annotations

import json
import os

DEFAULT_MODEL = os.environ.get(
    "BEDROCK_MODEL_ID",
    "arn:aws:bedrock:us-west-2:387769110234:application-inference-profile/fky19kpnw2m7",
)
DEFAULT_REGION = os.environ.get("AWS_DEFAULT_REGION", "us-west-2")
MTS_COST_PER_MONTH = float(os.environ.get("MTS_COST_PER_MONTH", "0.002"))


def _build_prompt(analysis: dict) -> str:
    total_mms    = analysis["total_mms"]
    total_mts    = analysis["total_mts"]
    mms_saveable = analysis["total_mms_saveable"]
    excl_mms     = analysis["total_excl_mms"]
    reduction    = analysis["reduction_pct"]
    prod_mts     = analysis["prod_mts"]
    nonprod_mts  = analysis["nonprod_mts"]
    prod_pct     = round(prod_mts / max(total_mts, 1) * 100, 1)

    # MTS cost is still the right financial metric
    monthly_cost   = total_mts * MTS_COST_PER_MONTH
    mts_saveable   = analysis["total_mts_saveable"]
    excl_mts       = analysis["total_excl_mts"]
    potential_save = (mts_saveable + excl_mts) * MTS_COST_PER_MONTH

    # Top 30 consolidation patterns — expressed in MMS
    top_patterns = analysis["consolidation"][:30]
    pattern_rows = []
    for i, p in enumerate(top_patterns, 1):
        svcs = ", ".join(p["services"][:2]) + ("…" if len(p["services"]) > 2 else "")
        vals = p["unique_values"]
        samples = " | ".join(p["val_samples"][:3]) if p["val_samples"] else "—"
        pattern_rows.append(
            f"| {i:2} | `{p['pattern']}` | {p['mms_count']:,} | {vals} | {p['mms_saved']:,} | {svcs or '—'} |"
        )
    pattern_table = "\n".join(pattern_rows) if pattern_rows else "_No parameterizable patterns found._"

    # Attack summary — in MMS
    if analysis["attacks"]:
        attack_lines = []
        for atype, ops in analysis["attack_by_type"].items():
            sample = ops[0]["operation"] if ops else ""
            attack_lines.append(f"- **{atype}** ({len(ops)} MMS): `{sample[:80]}`")
        attack_summary = "\n".join(attack_lines)
    else:
        attack_summary = "_None detected._"

    # Exclusion summary — in MMS
    excl_lines = []
    for cls, ops in analysis["exclusions"].items():
        sample = ops[0]["operation"] if ops else ""
        excl_lines.append(f"- **{cls}** ({len(ops)} MMS): `{sample[:60]}`")
    excl_summary = "\n".join(excl_lines) if excl_lines else "_None detected._"

    # Environment distribution — in MMS
    env_mms: dict[str, int] = {}
    for op in analysis.get("_deduped", []):  # fallback: count from env_distribution
        pass
    # Derive MMS per environment from env_distribution (which is MTS-weighted)
    # Use a proportional estimate: env_distribution[env] / avg_mts_per_mms
    avg_mts = total_mts / max(total_mms, 1)
    env_lines = []
    for env, mts_count in list(analysis["env_distribution"].items())[:15]:
        est_mms = round(mts_count / avg_mts)
        pct = round(est_mms / max(total_mms, 1) * 100, 1)
        prod_tag = " *(prod)*" if env.startswith("prod-") else ""
        env_lines.append(f"- `{env}`: ~{est_mms:,} MMS ({pct}%){prod_tag}")
    env_section = "\n".join(env_lines) if env_lines else "_No environment data._"

    # Top services — expressed as approx MMS
    svc_lines = []
    for svc, mts_count in list(analysis["service_distribution"].items())[:15]:
        est_mms = round(mts_count / avg_mts)
        pct = round(est_mms / max(total_mms, 1) * 100, 1)
        svc_lines.append(f"- `{svc}`: ~{est_mms:,} MMS ({pct}%)")
    svc_section = "\n".join(svc_lines) if svc_lines else "_No service data._"

    prompt = f"""You are analyzing APM Monitoring MetricSets (MMS) data exported from a Splunk Observability org.

## Background

An APM **Monitoring MetricSet (MMS)** is created for every unique combination of
(sf_operation, sf_service, sf_environment). MMS is the primary APM billing unit in
Splunk Observability — the customer pays per MMS, not per raw MTS.

Each MMS generates 2–8 underlying MTS (metric time series) — one per metric variant:
request count, error count, latency p50/p90/p99, etc. But when discussing APM cardinality
and cost, MMS is the right unit to reason about.

High MMS count means:
- Higher APM subscription cost (billed per MMS)
- Noisy APM service maps and dashboards
- Hard-to-find signal in a sea of operations

The primary remediation tool is the **OpenTelemetry Collector `transform` processor**,
which rewrites span attributes (especially `http.route` or `url.path`) before they reach
Splunk, collapsing many unique operation values into a single parameterized pattern and
reducing the MMS count.

---

## Data Summary

| Metric | Value |
|--------|-------|
| **Total APM MMS** | **{total_mms:,}** |
| Total underlying MTS | {total_mts:,} (avg {avg_mts:.1f} MTS/MMS) |
| Production MTS | {prod_mts:,} ({prod_pct}%) |
| Non-production MTS | {nonprod_mts:,} ({100-prod_pct}%) |
| Estimated monthly cost | ${monthly_cost:,.2f} |
| **MMS saveable via parameterization** | **{mms_saveable:,}** |
| **MMS saveable via exclusion** | **{excl_mms:,}** |
| **Estimated MMS reduction** | **{reduction}%** |
| Estimated monthly savings potential | ${potential_save:,.2f} |

---

## Top Parameterizable Patterns

Each row is a group of MMS that share a common pattern (e.g. `/case/12345`, `/case/67890`
are both instances of the `/case/{{id}}` pattern). Parameterizing collapses all MMS in the
group into a single MMS.

| # | Pattern | MMS Count | Unique Values | MMS Saved | Services |
|---|---------|-----------|---------------|-----------|----------|
{pattern_table}

---

## Attack / Probe Signatures Detected

{attack_summary}

---

## Exclusion Candidates

Operations that should be filtered from APM MMS entirely:

{excl_summary}

---

## Environment Distribution (estimated MMS)

{env_section}

---

## Top Services by MMS Count (estimated)

{svc_section}

---

## Instructions

Please provide a comprehensive analysis as a markdown document.
Frame everything in MMS terms — MMS count, MMS saved, MMS eliminated.
Only mention MTS when discussing the underlying metric billing mechanics.
Be specific and reference the actual patterns and services from the data above.

### Executive Summary
2–3 sentences: what kind of system/business does this appear to be? What is the MMS
cardinality situation and urgency?

### Architecture Observations
Based on the operation names and service names, what technology stack, business domain,
and architectural patterns can you infer? Be specific.

### Top 5 Prioritized Actions

For each action, provide:
- **Action**: What to do
- **MMS Impact**: How many MMS this eliminates (use exact numbers from the data above)
- **Effort**: Low / Medium / High
- **OTel Collector Config** (where applicable): Complete YAML for the Splunk OTel Collector.

OTel Collector transform processor format:
```yaml
processors:
  transform:
    trace_statements:
      - context: span
        statements:
          - replace_pattern(attributes["http.route"], "REGEX", "REPLACEMENT")
```

### Cost Analysis
Break down estimated monthly savings. Use ${MTS_COST_PER_MONTH}/MTS/month for financials,
but express reduction in MMS terms as the primary metric.

### Additional Observations
Any other patterns, risks, or opportunities (misconfigured service names, environment
proliferation, duplicate telemetry, etc.).
"""
    return prompt


def call_bedrock(prompt: str, model_id: str = DEFAULT_MODEL, region: str = DEFAULT_REGION) -> str:
    """Invoke Claude via AWS Bedrock. Returns the response text."""
    try:
        import boto3
        from botocore.config import Config
    except ImportError:
        return "[boto3 not installed — run: pip install boto3]"

    try:
        client = boto3.client(
            "bedrock-runtime",
            region_name=region,
            config=Config(read_timeout=300, connect_timeout=10),
        )
        body = {
            "anthropic_version": "bedrock-2023-05-31",
            "max_tokens": 8192,
            "messages": [{"role": "user", "content": prompt}],
        }
        resp = client.invoke_model(modelId=model_id, body=json.dumps(body))
        return json.loads(resp["body"].read())["content"][0]["text"]
    except Exception as e:
        return f"[AI analysis unavailable: {e}]"


def generate(
    analysis: dict,
    model_id: str = DEFAULT_MODEL,
    region: str = DEFAULT_REGION,
) -> str:
    """Build prompt from analysis and call Claude. Returns the markdown report text."""
    prompt = _build_prompt(analysis)
    return call_bedrock(prompt, model_id=model_id, region=region)
