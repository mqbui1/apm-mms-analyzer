# splunk-metrics-advisor

AI-powered metrics cardinality analysis for Splunk Observability Cloud.

Analyses both **APM Monitoring MetricSets (MMS)** and **custom Infrastructure Monitoring (IM) metrics** — identifies cardinality root causes, quantifies reduction potential, and generates actionable remediation steps with OTel Collector YAML.

## Modes

### `--mode apm` (default) — APM MMS analysis

Fetches APM MMS rows, detects high-cardinality operation name patterns (parameterisable IDs, attack probes, exclusion candidates), and calls Claude to produce a prioritised remediation report with OTel Collector `transform` processor config.

### `--mode custom` — Custom IM metrics analysis

Reads the engineering custom metrics CSV export, identifies high-cardinality dimensions causing MTS explosion (e.g. `aws.ecs.task.arn`, `service.instance.id` on JVM metrics), analyses per-account token distribution, and calls Claude to produce a remediation report with OTel Collector YAML.

## Install

```bash
pip install -e .
# or with uv:
uv pip install -e .
```

## Usage

### APM MMS — live fetch

```bash
export SPLUNK_ACCESS_TOKEN=your_token
export SPLUNK_REALM=us1
export AWS_DEFAULT_REGION=us-west-2

metrics-advisor --format html
```

### APM MMS — from TSV dump

```bash
metrics-advisor --input ops_dump.tsv --format html
```

### APM MMS — dump raw TSV and exit

```bash
metrics-advisor --dump ops_dump.tsv
```

### Custom metrics — from engineering CSV

```bash
metrics-advisor --mode custom --custom-input custom-metrics-analysis.csv --format html
```

### Common options

```bash
# Skip AI, deterministic summary only
metrics-advisor --mode custom --custom-input export.csv --no-ai

# Save markdown report to file
metrics-advisor --mode custom --custom-input export.csv --output report.md

# Filter APM by environment
metrics-advisor --environment prod-us --format html
```

## Configuration

| Env var | CLI flag | Default | Description |
|---------|----------|---------|-------------|
| `SPLUNK_ACCESS_TOKEN` | `--token` | required (apm mode) | Splunk API token |
| `SPLUNK_REALM` | `--realm` | `us1` | Splunk realm |
| `BEDROCK_MODEL_ID` | `--model` | Claude Sonnet via Bedrock | Bedrock model ARN or ID |
| `AWS_DEFAULT_REGION` | `--aws-region` | `us-west-2` | AWS region for Bedrock |
| `MTS_COST_PER_MONTH` | — | `0.002` | $/MTS/month for cost estimates |
| `MMS_FETCH_LIMIT` | `--limit` | `0` (unlimited) | Max rows to fetch (apm mode) |

## AWS credentials

Uses the default AWS credential chain (`~/.aws/credentials`, env vars, instance profile).
Requires `bedrock:InvokeModel` on the configured model.

## Output

HTML reports open automatically in the browser. Markdown reports print to stdout or save to `--output FILE`.

HTML reports include:
- **APM mode**: stat grid, parameterisable patterns table, AI analysis, environment distribution, attack signatures
- **Custom mode**: stat grid, high-cardinality culprits table, AI analysis, top metrics, metric groups, token/account distribution
