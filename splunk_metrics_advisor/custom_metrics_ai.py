"""
Claude (via AWS Bedrock) analysis of custom (IM) metrics cardinality data.

Builds a structured prompt from the deterministic cardinality analysis and calls
Claude to produce an actionable narrative with prioritised remediation steps and
OTel Collector YAML snippets.
"""
from __future__ import annotations

import os

DEFAULT_MODEL = os.environ.get(
    "BEDROCK_MODEL_ID",
    "arn:aws:bedrock:us-west-2:387769110234:application-inference-profile/fky19kpnw2m7",
)
DEFAULT_REGION = os.environ.get("AWS_DEFAULT_REGION", "us-west-2")
MTS_COST_PER_MONTH = float(os.environ.get("MTS_COST_PER_MONTH", "0.002"))


def _build_prompt(analysis: dict) -> str:
    total_mts      = analysis["total_mts"]
    total_metrics  = analysis["total_metrics"]
    reduction_est  = analysis["reduction_estimate"]
    reduction_pct  = analysis["reduction_pct"]
    monthly_cost   = total_mts * MTS_COST_PER_MONTH
    savings        = reduction_est * MTS_COST_PER_MONTH

    # ── Top 20 metrics table ──────────────────────────────────────────────────
    top_rows = []
    for i, m in enumerate(analysis["top_metrics"][:20], 1):
        pct = round(m["mts_count"] / max(total_mts, 1) * 100, 1)
        top_rows.append(f"| {i} | `{m['metric_name']}` | {m['mts_count']:,} | {pct}% |")
    top_table = "\n".join(top_rows) if top_rows else "_No metrics._"

    # ── Metric groups table ───────────────────────────────────────────────────
    group_rows = []
    for g in analysis["metric_groups"][:10]:
        group_rows.append(
            f"| `{g['prefix']}.*` | {g['metric_count']} | {g['mts_count']:,} | {g['pct']}% |"
        )
    group_table = "\n".join(group_rows) if group_rows else "_No groups._"

    # ── Cardinality culprits table ────────────────────────────────────────────
    culprit_rows = []
    for c in analysis["cardinality_culprits"][:10]:
        affected = ", ".join(f"`{m}`" for m in c["affected_metrics"][:3])
        if c["affected_metric_count"] > 3:
            affected += f" +{c['affected_metric_count'] - 3} more"
        culprit_rows.append(
            f"| `{c['dimension']}` | {c['total_mts']:,} | {c['pct_of_total']}% "
            f"| {c['reason']} | {affected} |"
        )
    culprit_table = (
        "\n".join(culprit_rows) if culprit_rows else "_No high-cardinality dimensions detected._"
    )

    # ── Token distribution table ──────────────────────────────────────────────
    token_rows = []
    for t in analysis["token_distribution"][:5]:
        top3 = ", ".join(f"`{name}`" for name, _ in t["top_metrics"][:3])
        token_rows.append(f"| `{t['token_id']}` | {t['mts_count']:,} | {t['pct']}% | {top3} |")
    token_table = "\n".join(token_rows) if token_rows else "_No token data._"

    return f"""You are analyzing custom Infrastructure Monitoring (IM) metrics exported from a \
Splunk Observability Cloud org.

## Background

**Custom metrics** in Splunk Observability are user-defined metric time series (MTS) billed per
MTS per month. Each unique combination of (metric name + dimension values) = one MTS.

**Cardinality explosion** happens when ephemeral dimensions are attached to metrics. On AWS ECS
Fargate, dimensions like `aws.ecs.task.arn`, `service.instance.id`, and `process.pid` change every
time a task restarts, deployment occurs, or auto-scaling fires — each change mints new MTS that
survive for ~25 hours before expiring.

The primary remediation is the **OpenTelemetry Collector `transform` processor**, which drops or
normalises high-cardinality dimensions before metrics reach Splunk.

---

## Data Summary

| Metric | Value |
|--------|-------|
| **Total custom metric names** | {total_metrics:,} |
| **Total MTS** | {total_mts:,} |
| **Est. monthly cost** | ${monthly_cost:,.2f} |
| **Est. MTS reduction potential** | {reduction_est:,} ({reduction_pct}%) |
| **Est. monthly savings** | ${savings:,.2f} |

---

## Top 20 Metrics by MTS Count

| # | Metric Name | MTS Count | % of Total |
|---|-------------|-----------|------------|
{top_table}

---

## Metric Groups

| Group | # Metrics | Total MTS | % of Total |
|-------|-----------|-----------|------------|
{group_table}

---

## High-Cardinality Dimension Culprits

Dimensions that change per task/container/process restart, causing unbounded MTS accumulation:

| Dimension | MTS Contributed | % of Total | Why It Is High-Cardinality | Affected Metrics |
|-----------|----------------|------------|---------------------------|------------------|
{culprit_table}

---

## Token / Account Distribution

| Token ID | MTS Count | % of Total | Top Metrics |
|----------|-----------|------------|-------------|
{token_table}

---

## Instructions

Provide a comprehensive analysis as a markdown document. Be specific — reference actual metric
names, dimension names, and numbers from the data. Do not pad with generic advice.

### Executive Summary
2–3 sentences: what type of workload is this, what is the cardinality situation, and what is the
urgency relative to subscription limits?

### Root Cause Analysis
Explain exactly why MTS counts are high. Reference the specific dimensions and the ECS Fargate task
lifecycle (task restarts on deploy, scale-out, health-check failure) that drives unbounded growth.
Include how old MTS persist for ~25 hours after a task exits, causing spike-then-stabilise patterns
during initial rollout waves.

### Top 5 Prioritised Actions

For each action provide:
- **Action**: What to do, concisely
- **MTS Impact**: Estimated MTS reduction (cite numbers from the data above)
- **Effort**: Low / Medium / High
- **OTel Collector Config** (where applicable): complete, copy-pasteable YAML

OTel Collector `transform` processor for metric datapoints:
```yaml
processors:
  transform/drop_high_cardinality:
    metric_statements:
      - context: datapoint
        statements:
          - delete_matching_keys(attributes, "regex_pattern")
```

### Cost Analysis
Monthly cost breakdown and savings per action. Use ${MTS_COST_PER_MONTH}/MTS/month.

### Additional Observations
Other patterns visible in the data: metric version skew (duplicate JVM metrics from mixed agent
versions), non-prod vs prod separation, AWS CloudWatch metric redundancy, `spans.*` metric
proliferation, or any other anomalies worth flagging.
"""


def generate(
    analysis: dict,
    model_id: str = DEFAULT_MODEL,
    region: str = DEFAULT_REGION,
) -> str:
    """Build prompt from analysis and call Claude. Returns markdown report text."""
    from .ai_report import call_bedrock
    prompt = _build_prompt(analysis)
    return call_bedrock(prompt, model_id=model_id, region=region)
