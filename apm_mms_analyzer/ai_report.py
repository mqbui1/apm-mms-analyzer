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
    total       = analysis["total_mts"]
    unique_ops  = analysis["total_unique_ops"]
    saveable    = analysis["total_mts_saveable"]
    excl_mts    = analysis["total_excl_mts"]
    reduction   = analysis["reduction_pct"]
    prod_mts    = analysis["prod_mts"]
    nonprod_mts = analysis["nonprod_mts"]
    prod_pct    = round(prod_mts / max(total, 1) * 100, 1)

    monthly_cost   = total * MTS_COST_PER_MONTH
    potential_save = (saveable + excl_mts) * MTS_COST_PER_MONTH

    # Top 30 consolidation patterns
    top_patterns = analysis["consolidation"][:30]
    pattern_rows = []
    for i, p in enumerate(top_patterns, 1):
        svcs = ", ".join(p["services"][:2]) + ("…" if len(p["services"]) > 2 else "")
        vals = p["unique_values"]
        samples = " | ".join(p["val_samples"][:3]) if p["val_samples"] else "—"
        pattern_rows.append(
            f"| {i:2} | `{p['pattern']}` | {p['mts_count']:,} | {vals} | {p['mts_saved']:,} | {svcs or '—'} |"
        )
    pattern_table = "\n".join(pattern_rows) if pattern_rows else "_No parameterizable patterns found._"

    # Attack summary
    if analysis["attacks"]:
        attack_lines = []
        for atype, ops in analysis["attack_by_type"].items():
            sample = ops[0]["operation"] if ops else ""
            attack_lines.append(f"- **{atype}** ({len(ops)} MTS): `{sample[:80]}`")
        attack_summary = "\n".join(attack_lines)
    else:
        attack_summary = "_None detected._"

    # Exclusion summary
    excl_lines = []
    for cls, ops in analysis["exclusions"].items():
        mts = sum(o["mts_count"] for o in ops)
        sample = ops[0]["operation"] if ops else ""
        excl_lines.append(f"- **{cls}** ({mts:,} MTS, {len(ops)} ops): `{sample[:60]}`")
    excl_summary = "\n".join(excl_lines) if excl_lines else "_None detected._"

    # Environment distribution (top 15)
    env_lines = []
    for env, count in list(analysis["env_distribution"].items())[:15]:
        pct = round(count / max(total, 1) * 100, 1)
        prod_tag = " *(prod)*" if env.startswith("prod-") else ""
        env_lines.append(f"- `{env}`: {count:,} MTS ({pct}%){prod_tag}")
    env_section = "\n".join(env_lines) if env_lines else "_No environment data._"

    # Top services (top 15)
    svc_lines = []
    for svc, count in list(analysis["service_distribution"].items())[:15]:
        pct = round(count / max(total, 1) * 100, 1)
        svc_lines.append(f"- `{svc}`: {count:,} MTS ({pct}%)")
    svc_section = "\n".join(svc_lines) if svc_lines else "_No service data._"

    prompt = f"""You are analyzing APM Monitoring MetricSets (MMS) data exported from a Splunk Observability org.

## Background

APM MMS are created for every unique combination of (sf_operation, sf_service, sf_environment).
Each combination generates 2–8 metric time series (MTS) — one per metric type: request count,
error count, latency percentiles (p50/p90/p99), etc. MTS = billing units.

High cardinality in APM MMS means:
- Higher monthly cost (each MTS billed separately)
- Noisy APM dashboards with hundreds of operation-level entries
- Slower query performance in Splunk Observability

The primary remediation tool is the **OpenTelemetry Collector `transform` processor**,
which can rewrite span attributes (especially `http.route` or `url.path`) before they
reach Splunk, collapsing many unique values into a single parameterized pattern.

---

## Data Summary

| Metric | Value |
|--------|-------|
| Total MTS (billing rows) | {total:,} |
| Unique operations | {unique_ops:,} |
| Production MTS | {prod_mts:,} ({prod_pct}%) |
| Non-production MTS | {nonprod_mts:,} ({100-prod_pct}%) |
| Estimated monthly cost | ${monthly_cost:,.2f} |
| MTS saveable via parameterization | {saveable:,} |
| MTS saveable via exclusion | {excl_mts:,} |
| Estimated cardinality reduction | {reduction}% |
| Estimated monthly savings potential | ${potential_save:,.2f} |

---

## Top Parameterizable Patterns

These operation name patterns contain variable segments (IDs, hashes, dates) that can be
normalized to a single template, collapsing many MTS into one.

| # | Pattern | MTS Count | Unique Values | MTS Saved | Services |
|---|---------|-----------|---------------|-----------|----------|
{pattern_table}

---

## Attack / Probe Signatures Detected

{attack_summary}

---

## Exclusion Candidates

Operations that should be filtered from APM MMS entirely (they add no diagnostic value):

{excl_summary}

---

## Environment Distribution

{env_section}

---

## Top Services by MTS Count

{svc_section}

---

## Instructions

Please provide a comprehensive analysis as a markdown document with the following sections.
Be specific and reference the actual patterns and services from the data above.

### Executive Summary
2–3 sentences: what kind of system/business does this appear to be based on the operation
names and services? What is the overall cardinality situation and urgency?

### Architecture Observations
Based on the operation names and service names, what technology stack, business domain,
and architectural patterns can you infer? Be specific (e.g. "the `/case/` and `/rebuttal/`
patterns suggest a case management or dispute resolution system").

### Top 5 Prioritized Actions

For each action, provide:
- **Action**: Clear description of what to do
- **MTS Impact**: How many MTS this eliminates (use exact numbers from the data)
- **Effort**: Low / Medium / High
- **OTel Collector Config** (where applicable): Provide the complete `transform` processor
  YAML for the Splunk OTel Collector. Use `replace_pattern` or `replace_all_pattern` on
  the `http.route`, `url.path`, or `rpc.method` span attribute as appropriate.

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
Break down the estimated monthly savings by action category (parameterization, exclusion,
attack filtering). Use ${MTS_COST_PER_MONTH}/MTS/month.

### Additional Observations
Any other patterns, risks, or opportunities you notice (e.g. unusual environments,
signs of misconfiguration, services that appear to be sending duplicate telemetry, etc.).
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
