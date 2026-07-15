# apm-mms-analyzer

AI-powered analysis of APM Monitoring MetricSets (MMS) for Splunk Observability Cloud.

Fetches raw MMS data, detects high-cardinality patterns, and calls Claude (via AWS Bedrock) to produce an actionable analysis report — including OTel Collector config snippets for the top remediation opportunities.

## What it does

1. **Fetches** all APM MMS rows from your Splunk Observability org (or reads from a TSV dump)
2. **Analyzes** operation name patterns: parameterizable IDs, attack probes, exclusion candidates
3. **Calls Claude** with the structured analysis to produce a narrative report with prioritized actions and OTel Collector YAML

## Install

```bash
pip install -e .
# or with uv:
uv pip install -e .
```

## Usage

### Live fetch + AI analysis

```bash
export SPLUNK_ACCESS_TOKEN=your_token
export SPLUNK_REALM=us1          # us1, us2, eu0, ap0, etc.
export AWS_DEFAULT_REGION=us-west-2

apm-mms-analyze
```

### Filter by environment

```bash
apm-mms-analyze --environment prod-us
```

### Read from existing TSV dump (no Splunk API call)

The TSV format matches the raw engineering export:
`MTS_ID\t"operation"\t"service"\t"environment"`

```bash
apm-mms-analyze --input ops_dump.tsv
```

### Dump raw TSV and exit (no AI)

```bash
apm-mms-analyze --dump ops_dump.tsv
```

### Save report to file

```bash
apm-mms-analyze --output report.md
```

### Skip AI analysis (deterministic only)

```bash
apm-mms-analyze --no-ai
```

## Configuration

| Env var | CLI flag | Default | Description |
|---------|----------|---------|-------------|
| `SPLUNK_ACCESS_TOKEN` | `--token` | required | Splunk API token |
| `SPLUNK_REALM` | `--realm` | `us1` | Splunk realm |
| `BEDROCK_MODEL_ID` | `--model` | see below | Bedrock model ARN or ID |
| `AWS_DEFAULT_REGION` | `--aws-region` | `us-west-2` | AWS region for Bedrock |

Default Bedrock model: `arn:aws:bedrock:us-west-2:387769110234:application-inference-profile/fky19kpnw2m7`

## AWS credentials

The tool uses your default AWS credential chain (env vars, `~/.aws/credentials`, instance profile).
Ensure the credentials have `bedrock:InvokeModel` permission on the configured model.

## Output example

```
APM MMS Analysis
================
Total MTS:         53,417
Unique operations:    279
Environments:          12

## Executive Summary
This org appears to be a mortgage/financial services platform...

## Top 5 Actions
1. Parameterize /case/{id} and /rebuttal/{id} — saves 630 MTS
   OTel Collector config:
   ...
```
