"""CLI entry point for splunk-metrics-advisor."""
from __future__ import annotations

import argparse
import os
import subprocess
import sys
from datetime import datetime, timezone

from . import fetcher, patterns, ai_report, html_report


# ---------------------------------------------------------------------------
# Deterministic summary printers
# ---------------------------------------------------------------------------

def _print_apm_summary(analysis: dict) -> None:
    total_mms = analysis["total_mms"]
    total_mts = analysis["total_mts"]
    mms_save  = analysis["total_mms_saveable"]
    excl_mms  = analysis["total_excl_mms"]
    attacks   = len(analysis["attacks"])
    pct       = analysis["reduction_pct"]
    prod_mts  = analysis["prod_mts"]
    prod_pct  = round(prod_mts / max(total_mts, 1) * 100, 1)
    cost      = total_mts * float(os.environ.get("MTS_COST_PER_MONTH", "0.002"))

    print("\n" + "=" * 66)
    print("APM MMS ANALYSIS")
    print("=" * 66)
    print(f"  Total APM MMS:               {total_mms:>10,}")
    print(f"  Total underlying MTS:        {total_mts:>10,}")
    print(f"  Production MTS:              {prod_mts:>10,}  ({prod_pct}%)")
    print(f"  Est. monthly cost:           ${cost:>10,.2f}")
    print(f"  Attack payloads:             {attacks:>10,}  MMS")
    print(f"  MMS saveable (param):        {mms_save:>10,}  MMS")
    print(f"  MMS saveable (exclusion):    {excl_mms:>10,}  MMS")
    print(f"  Est. MMS reduction:          {pct:>9.1f}%")
    print()

    top = analysis["consolidation"][:20]
    if top:
        print(f"  TOP PARAMETERISABLE PATTERNS  (top {len(top)})")
        print(f"  {'#':>3}  {'MMS':>6}  {'Saved':>6}  {'Uniq':>5}  Pattern")
        print("  " + "─" * 70)
        for i, p in enumerate(top, 1):
            print(f"  {i:>3}  {p['mms_count']:>6,}  {p['mms_saved']:>6,}  {p['unique_values']:>5}  {p['pattern']}")
        print()

    if analysis["attacks"]:
        print("  ATTACK / PROBE SIGNATURES DETECTED")
        for atype, ops in analysis["attack_by_type"].items():
            sample = ops[0]["operation"][:60] if ops else ""
            print(f"    {atype} ({len(ops)} MMS): {sample}")
        print()

    if analysis["exclusions"]:
        print("  EXCLUSION CANDIDATES")
        for cls, ops in analysis["exclusions"].items():
            print(f"    {cls}: {len(ops)} MMS")
        print()


def _print_custom_summary(analysis: dict) -> None:
    total_mts     = analysis["total_mts"]
    total_metrics = analysis["total_metrics"]
    reduction     = analysis["reduction_estimate"]
    reduction_pct = analysis["reduction_pct"]
    cost          = total_mts * float(os.environ.get("MTS_COST_PER_MONTH", "0.002"))

    print("\n" + "=" * 66)
    print("CUSTOM METRICS CARDINALITY ANALYSIS")
    print("=" * 66)
    print(f"  Total custom metric names:   {total_metrics:>10,}")
    print(f"  Total MTS:                   {total_mts:>10,}")
    print(f"  Est. monthly cost:           ${cost:>10,.2f}")
    print(f"  Est. MTS reduction:          {reduction:>10,}  ({reduction_pct}%)")
    print()

    top = analysis["top_metrics"][:10]
    if top:
        print(f"  TOP 10 METRICS BY MTS")
        print(f"  {'#':>3}  {'MTS':>10}  {'%':>6}  Metric")
        print("  " + "─" * 62)
        for i, m in enumerate(top, 1):
            pct = round(m["mts_count"] / max(total_mts, 1) * 100, 1)
            print(f"  {i:>3}  {m['mts_count']:>10,}  {pct:>5.1f}%  {m['metric_name']}")
        print()

    culprits = analysis["cardinality_culprits"][:5]
    if culprits:
        print("  HIGH-CARDINALITY DIMENSIONS")
        for c in culprits:
            print(f"    {c['dimension']}: {c['total_mts']:,} MTS ({c['pct_of_total']}%)")
        print()


# ---------------------------------------------------------------------------
# Main
# ---------------------------------------------------------------------------

def main(argv: list[str] | None = None) -> None:
    parser = argparse.ArgumentParser(
        prog="metrics-advisor",
        description="AI-powered metrics cardinality analysis for Splunk Observability Cloud",
    )

    # Mode
    parser.add_argument(
        "--mode", "-m", choices=["apm", "custom"], default="apm",
        help="Analysis mode: apm (APM Monitoring MetricSets) or custom (IM custom metrics). Default: apm",
    )

    # APM data source
    src = parser.add_mutually_exclusive_group()
    src.add_argument("--input", "-i", metavar="FILE",
                     help="[apm] Read from TSV dump instead of live Splunk API fetch")
    src.add_argument("--dump", "-d", metavar="FILE",
                     help="[apm] Dump raw MTS to TSV and exit")

    # Custom metrics data source
    parser.add_argument("--custom-input", metavar="CSV",
                        help="[custom] Path to engineering custom metrics CSV export")

    # Splunk API
    parser.add_argument("--token", default=os.environ.get("SPLUNK_ACCESS_TOKEN", ""),
                        help="Splunk API token (or SPLUNK_ACCESS_TOKEN env var)")
    parser.add_argument("--realm", default=os.environ.get("SPLUNK_REALM", "us1"),
                        help="Splunk realm, e.g. us1 (or SPLUNK_REALM env var)")
    parser.add_argument("--environment", "-e", default=None,
                        help="[apm] Filter by sf_environment value")
    parser.add_argument("--limit", type=int,
                        default=int(os.environ.get("MMS_FETCH_LIMIT", "0")),
                        help="[apm] Max MTS rows to fetch (0 = unlimited)")

    # AI
    parser.add_argument("--no-ai", action="store_true",
                        help="Skip AI analysis, print deterministic summary only")
    parser.add_argument("--model", default=None,
                        help="Bedrock model ID or ARN (or BEDROCK_MODEL_ID env var)")
    parser.add_argument("--aws-region", default=None,
                        help="AWS region for Bedrock (or AWS_DEFAULT_REGION env var)")

    # Output
    parser.add_argument("--output", "-o", metavar="FILE",
                        help="Write report to file (default: stdout / auto reports/ dir for html)")
    parser.add_argument("--format", "-f", choices=["md", "html"], default="md",
                        help="Output format: md (default) or html")

    args = parser.parse_args(argv)

    model_id = args.model or ai_report.DEFAULT_MODEL
    region   = args.aws_region or ai_report.DEFAULT_REGION
    ts       = datetime.now(timezone.utc).strftime("%Y-%m-%d %H:%M UTC")

    # ── Custom metrics mode ───────────────────────────────────────────────────
    if args.mode == "custom":
        from . import custom_metrics_fetcher, custom_metrics_patterns, custom_metrics_ai

        if not args.custom_input:
            print("Error: --custom-input CSV is required for --mode custom", file=sys.stderr)
            print("       e.g. metrics-advisor --mode custom --custom-input export.csv --format html",
                  file=sys.stderr)
            sys.exit(1)

        print(f"Reading custom metrics from {args.custom_input}...", file=sys.stderr)
        cm_data = custom_metrics_fetcher.read_from_csv(args.custom_input)
        total_mts = sum(m["mts_count"] for m in cm_data)
        print(f"  {len(cm_data):,} metrics loaded — {total_mts:,} total MTS", file=sys.stderr)

        print("Analysing cardinality...", file=sys.stderr)
        cm_analysis = custom_metrics_patterns.analyze(cm_data)

        _print_custom_summary(cm_analysis)

        if args.no_ai:
            return

        print(f"Calling Claude ({model_id[:60]}...)...", file=sys.stderr)
        cm_report = custom_metrics_ai.generate(cm_analysis, model_id=model_id, region=region)

        if args.format == "html":
            out_path = args.output
            if not out_path:
                os.makedirs("reports", exist_ok=True)
                stamp = datetime.now(timezone.utc).strftime("%Y%m%d_%H%M%S")
                out_path = f"reports/custom_metrics_{stamp}.html"
            rendered = html_report.generate_custom(cm_analysis, cm_report, generated_at=ts)
            with open(out_path, "w", encoding="utf-8") as fh:
                fh.write(rendered)
            print(f"\nHTML report: {out_path}", file=sys.stderr)
            subprocess.Popen(["open", out_path])
        else:
            header_lines = [
                "# Custom Metrics Cardinality Report",
                "",
                f"**Generated:** {ts}  ",
                f"**Total MTS:** {cm_analysis['total_mts']:,}  ",
                f"**Total Metrics:** {cm_analysis['total_metrics']:,}  ",
                f"**Reduction Potential:** {cm_analysis['reduction_pct']}%  ",
                "",
                "---",
                "",
            ]
            full_report = "\n".join(header_lines) + "\n" + cm_report
            if args.output:
                with open(args.output, "w", encoding="utf-8") as fh:
                    fh.write(full_report)
                print(f"\nReport saved to: {args.output}", file=sys.stderr)
            else:
                print(full_report)
        return

    # ── APM MMS mode ──────────────────────────────────────────────────────────

    if args.dump:
        if not args.token:
            print("Error: --token or SPLUNK_ACCESS_TOKEN required for live fetch", file=sys.stderr)
            sys.exit(1)
        print(f"Fetching all MTS from {args.realm}...", file=sys.stderr)
        ops = fetcher.fetch_from_splunk(args.token, args.realm, args.environment, args.limit)
        fetcher.write_tsv(ops, args.dump)
        print(f"Wrote {len(ops):,} rows to {args.dump}", file=sys.stderr)
        return

    if args.input:
        print(f"Reading from {args.input}...", file=sys.stderr)
        ops = fetcher.read_from_tsv(args.input)
        print(f"  {len(ops):,} rows loaded.", file=sys.stderr)
    else:
        if not args.token:
            print("Error: --token or SPLUNK_ACCESS_TOKEN required", file=sys.stderr)
            print("       Use --input FILE to analyse a TSV dump without the API", file=sys.stderr)
            sys.exit(1)
        print(f"Fetching APM MMS from {args.realm}...", file=sys.stderr)
        ops = fetcher.fetch_from_splunk(args.token, args.realm, args.environment, args.limit)
        if not ops:
            print("No APM MMS data found. This org may not have APM MMS activated.", file=sys.stderr)
            sys.exit(0)

    print("Analysing patterns...", file=sys.stderr)
    analysis = patterns.analyze(ops)

    _print_apm_summary(analysis)

    if args.no_ai:
        return

    print(f"Calling Claude ({model_id[:60]}...)...", file=sys.stderr)
    report = ai_report.generate(analysis, model_id=model_id, region=region)

    if args.format == "html":
        out_path = args.output
        if not out_path:
            os.makedirs("reports", exist_ok=True)
            stamp = datetime.now(timezone.utc).strftime("%Y%m%d_%H%M%S")
            out_path = f"reports/apm_mms_{stamp}.html"
        rendered = html_report.generate(analysis, report, realm=args.realm, generated_at=ts)
        with open(out_path, "w", encoding="utf-8") as fh:
            fh.write(rendered)
        print(f"\nHTML report: {out_path}", file=sys.stderr)
        subprocess.Popen(["open", out_path])
    else:
        header_lines = [
            "# APM MMS Analysis Report",
            "",
            f"**Generated:** {ts}  ",
            f"**Total MTS:** {analysis['total_mts']:,}  ",
            f"**Unique operations:** {analysis['total_unique_ops']:,}  ",
            f"**Reduction potential:** {analysis['reduction_pct']}%  ",
            "",
            "---",
            "",
        ]
        full_report = "\n".join(header_lines) + "\n" + report
        if args.output:
            with open(args.output, "w", encoding="utf-8") as fh:
                fh.write(full_report)
            print(f"\nReport saved to: {args.output}", file=sys.stderr)
        else:
            print(full_report)


if __name__ == "__main__":
    main()
