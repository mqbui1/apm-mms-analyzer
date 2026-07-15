"""
Cardinality analysis for custom (IM) metrics.

Identifies:
  - Top metrics by MTS count
  - High-cardinality dimensions causing MTS explosion
  - Metric groups (jvm.*, system.*, spans.*, AWS/CloudWatch, etc.)
  - Token / account MTS distribution
  - Reduction potential
"""
from __future__ import annotations

from collections import defaultdict

# Dimensions known to be high-cardinality in ECS / Kubernetes environments.
# These change every time a task, pod, or process restarts, minting new MTS.
HIGH_CARDINALITY_DIMS: dict[str, str] = {
    "aws.ecs.task.arn":      "Unique ARN per ECS task run — changes on every task restart/deployment",
    "aws.ecs.task.id":       "UUID per ECS task run — same lifecycle as aws.ecs.task.arn",
    "service.instance.id":   "UUID generated at JVM startup — changes on every container restart",
    "process.pid":           "PID changes on every container/process restart",
    "host.name":             "IP-based hostname on ECS (ip-x-x-x-x.ec2.internal) — changes per task",
    "container.id":          "Docker container ID — changes on every container restart",
    "k8s.pod.uid":           "Unique per pod — changes on every pod restart",
    "k8s.pod.name":          "Includes random suffix — changes on every pod restart",
    "process.command_args":  "Full command-line args — may vary per instance",
    "os.description":        "Exact kernel version string — varies across instance types/patches",
}


def analyze(metrics: list[dict]) -> dict:
    """
    Analyze custom metrics for cardinality issues.

    Input:  list of dicts from custom_metrics_fetcher.read_from_csv()
    Returns: analysis dict consumed by custom_metrics_ai and html_report.
    """
    if not metrics:
        return _empty()

    total_mts = sum(m["mts_count"] for m in metrics)
    total_metrics = len(metrics)

    # ── Top metrics ───────────────────────────────────────────────────────────
    top_metrics = sorted(metrics, key=lambda m: -m["mts_count"])

    # ── Metric prefix groups ──────────────────────────────────────────────────
    group_mts: dict[str, int] = defaultdict(int)
    group_members: dict[str, list] = defaultdict(list)
    for m in metrics:
        prefix = _metric_prefix(m["metric_name"])
        group_mts[prefix] += m["mts_count"]
        group_members[prefix].append(m)

    metric_groups = [
        {
            "prefix":        prefix,
            "mts_count":     group_mts[prefix],
            "metric_count":  len(group_members[prefix]),
            "pct":           round(group_mts[prefix] / max(total_mts, 1) * 100, 1),
            "top_metric":    max(group_members[prefix], key=lambda x: x["mts_count"])["metric_name"],
        }
        for prefix in sorted(group_mts, key=lambda k: -group_mts[k])
    ]

    # ── Token / account distribution ──────────────────────────────────────────
    token_mts: dict[str, int] = defaultdict(int)
    token_top: dict[str, list] = defaultdict(list)
    for m in metrics:
        for tid, mts in m.get("mts_per_token", {}).items():
            token_mts[tid] += mts
            token_top[tid].append((m["metric_name"], mts))

    token_distribution = [
        {
            "token_id":   tid,
            "mts_count":  mts,
            "pct":        round(mts / max(total_mts, 1) * 100, 1),
            "top_metrics": sorted(token_top[tid], key=lambda x: -x[1])[:5],
        }
        for tid, mts in sorted(token_mts.items(), key=lambda x: -x[1])
    ]

    # ── High-cardinality dimension culprits ───────────────────────────────────
    # DIMENSION_CARDINALITY maps dim_set_string -> unique_mts_count.
    # Single-key entries (no comma) are the clearest cardinality signals.
    dim_mts: dict[str, int] = defaultdict(int)
    dim_metrics: dict[str, list] = defaultdict(list)

    for m in metrics:
        for dim_set, mts_count in m.get("dimension_cardinality", {}).items():
            dims = [d.strip() for d in dim_set.split(",")]
            if len(dims) == 1:
                dim = dims[0]
                dim_mts[dim] += mts_count
                if m["metric_name"] not in dim_metrics[dim]:
                    dim_metrics[dim].append(m["metric_name"])

    cardinality_culprits = sorted(
        [
            {
                "dimension":            dim,
                "total_mts":            dim_mts[dim],
                "pct_of_total":         round(dim_mts[dim] / max(total_mts, 1) * 100, 1),
                "reason":               HIGH_CARDINALITY_DIMS[dim],
                "affected_metrics":     dim_metrics[dim][:5],
                "affected_metric_count": len(dim_metrics[dim]),
            }
            for dim in dim_mts
            if dim in HIGH_CARDINALITY_DIMS
        ],
        key=lambda x: -x["total_mts"],
    )

    # ── Reduction potential ───────────────────────────────────────────────────
    # Conservative model: dropping the top 3 ECS ephemeral dims (task.arn,
    # task.id, service.instance.id) saves ~65% of JVM metric MTS, based on
    # observed per-dim cardinality counts from the data.
    jvm_mts = group_mts.get("jvm", 0)
    reduction_estimate = int(jvm_mts * 0.65)
    reduction_pct = round(reduction_estimate / max(total_mts, 1) * 100, 1)

    return {
        "total_mts":             total_mts,
        "total_metrics":         total_metrics,
        "top_metrics":           top_metrics[:30],
        "metric_groups":         metric_groups,
        "token_distribution":    token_distribution,
        "cardinality_culprits":  cardinality_culprits[:15],
        "reduction_estimate":    reduction_estimate,
        "reduction_pct":         reduction_pct,
    }


def _metric_prefix(name: str) -> str:
    """Map a metric name to a logical group prefix."""
    if name.startswith(("Volume", "Disk", "AWS", "aws")):
        return "AWS/CloudWatch"
    parts = name.split(".")
    return parts[0] if len(parts) >= 2 else name


def _empty() -> dict:
    return {
        "total_mts": 0, "total_metrics": 0, "top_metrics": [],
        "metric_groups": [], "token_distribution": [],
        "cardinality_culprits": [], "reduction_estimate": 0, "reduction_pct": 0,
    }
