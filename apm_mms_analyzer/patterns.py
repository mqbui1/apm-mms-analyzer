"""
Pattern detection and consolidation analysis for APM MMS operation names.

Identifies:
  - Parameterizable patterns (e.g. /case/12345 → /case/{id})
  - Security probes and attack payloads
  - Exclusion candidates (health checks, static assets, swagger, JVM classnames)
  - Environment distribution
"""
from __future__ import annotations

import re
from collections import Counter, defaultdict

# ---------------------------------------------------------------------------
# Attack / probe signatures
# ---------------------------------------------------------------------------

ATTACK_SIGNATURES: list[tuple[re.Pattern, str]] = [
    (re.compile(r'oastify\.com|burpcollaborator\.net|interact\.sh', re.I), 'DNS OOB (Burp Collaborator)'),
    (re.compile(r'xp_dirtree|exec\s+master', re.I),                        'SQL injection — MSSQL'),
    (re.compile(r'load_file\s*\(|into\s+outfile', re.I),                   'SQL injection — MySQL'),
    (re.compile(r"'\s*(and|or)\s*\d+=\d+", re.I),                          'SQL injection — boolean'),
    (re.compile(r'nslookup\s+-q=', re.I),                                  'DNS exfiltration'),
    (re.compile(r'declare\s+@\w+\s+varchar', re.I),                        'SQL injection — MSSQL declare'),
    (re.compile(r'\{\{.*?\}\}|#set\s*\(|\$\{[^}]+\}', re.I),              'SSTI (template injection)'),
    (re.compile(r'response\.write\s*\(', re.I),                            'SSTI — ColdFusion'),
    (re.compile(r'__import__\s*\(', re.I),                                  'Python RCE'),
    (re.compile(r'%2e%2e|\.\.[\\/]|\.\.%5c|\.\.%2f', re.I),               'Path traversal'),
    (re.compile(r'(phpinfo|adminer|lfm|webshell|c99|r57|shell)\.php', re.I), 'PHP shell probe'),
    (re.compile(r'/\.env($|[/?#])',),                                       '.env file probe'),
    (re.compile(r'WEB-INF|win\.ini|winnt[\\/]|etc[\\/]passwd', re.I),      'File enumeration'),
    (re.compile(r'<script|javascript:|onerror\s*=', re.I),                  'XSS probe'),
    (re.compile(r'\|\s*echo\s+\w+|\|\s*id\b|\|\s*whoami', re.I),           'OS command injection'),
    (re.compile(r'/[a-z0-9]{6,12}\.jsp($|[/?#])', re.I),                   'Random JSP filename probe (scanner)'),
]

# ---------------------------------------------------------------------------
# Exclusion categories
# ---------------------------------------------------------------------------

EXCLUSION_CLASSES: dict[str, re.Pattern] = {
    "health_check": re.compile(
        r'^/(health|healthcheck|ping|ready|live|liveness|readiness)(/|$)'
        r'|/actuator/(health|info|metrics|prometheus|env)(/|$)', re.I),
    "static_asset": re.compile(
        r'\.(js|css|woff2?|ttf|eot|ico|png|jpg|jpeg|gif|svg|map|webp)(\?|$)'
        r'|tfe-eks-p2x'
        r'|chunk-[A-Z0-9]{6,}\.js', re.I),
    "swagger_docs": re.compile(
        r'swagger-ui|api-docs|openapi|swagger-resources|v3/api-docs', re.I),
    "jvm_classname": re.compile(
        r'\$\$Lambda\$\d+/0x[0-9a-f]+@'
        r'|org\.springframework\.'
        r'|com\.sun\.proxy\.\$Proxy'),
    "bare_method": re.compile(
        r'^(GET|POST|PUT|DELETE|PATCH|OPTIONS|HEAD)$'),
}

# ---------------------------------------------------------------------------
# Pattern normalization
# ---------------------------------------------------------------------------

def _normalize(op: str) -> str:
    """Replace variable path segments with typed placeholders."""
    # UUIDs first (before numeric, since UUIDs contain digits)
    op = re.sub(
        r'/[0-9a-f]{8}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{12}(?=/|$)',
        '/{UUID}', op, flags=re.IGNORECASE)
    # Numeric IDs
    op = re.sub(r'/\d{1,20}(?=/|$)', '/{ID}', op)
    # 32-char hex (MD5 hashes)
    op = re.sub(r'/[0-9a-fA-F]{32}(?=/|$)', '/{HASH}', op)
    # Webpack chunk IDs (base36: A-Z, 0-9)
    op = re.sub(r'chunk-[A-Z0-9]{6,}\.js', 'chunk-{HASH}.js', op, flags=re.IGNORECASE)
    # Content-addressed asset hashes (.abc123.js)
    op = re.sub(r'\.[0-9a-f]{6,}\.(js|css|woff2?|ttf|eot)', '.{HASH}.\\1', op, flags=re.IGNORECASE)
    # ISO dates
    op = re.sub(r'/\d{4}-\d{2}-\d{2}(?=/|$)', '/{DATE}', op)
    # JVM lambda classnames
    op = re.sub(r'\$\$Lambda\$\d+/0x[0-9a-f]+@[0-9a-f]+', '{JVM_LAMBDA}', op, flags=re.IGNORECASE)
    return op


# Placeholder split + extraction regex (for surfacing actual parameter values)
_PH_SPLIT = re.compile(r'(\{ID\}|\{HASH\}|\{DATE\}|\{UUID\}|\{JVM_LAMBDA\})')
_PH_RX: dict[str, str] = {
    '{ID}':         r'(\d{1,20})',
    '{HASH}':       r'([0-9A-Za-z]{6,64})',
    '{DATE}':       r'(\d{4}-\d{2}-\d{2})',
    '{UUID}':       r'([0-9a-f]{8}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{12})',
    '{JVM_LAMBDA}': r'(.+?)',
}


def _extraction_regex(pattern: str) -> re.Pattern | None:
    """Build a capture-group regex from a normalized pattern, or None if no placeholders."""
    if not _PH_SPLIT.search(pattern):
        return None
    parts = _PH_SPLIT.split(pattern)
    rx_parts = [_PH_RX[p] if p in _PH_RX else re.escape(p) for p in parts]
    try:
        return re.compile("".join(rx_parts), re.IGNORECASE)
    except re.error:
        return None


# ---------------------------------------------------------------------------
# Main analysis
# ---------------------------------------------------------------------------

def analyze(ops: list[dict]) -> dict:
    """
    Analyze a list of MMS operation records (one per MTS_ID).

    Returns:
        total_mts           — total MTS rows (billing units)
        total_unique_ops    — unique (op, svc, env) triples
        consolidation       — list of parameterization opportunities, sorted by MTS savings
        attacks             — list of ops matching attack signatures
        attack_by_type      — dict: attack_type -> [ops]
        exclusions          — dict: class -> [ops]
        env_distribution    — dict: environment -> MTS count
        service_distribution — dict: service -> MTS count
        prod_mts            — MTS in prod-* environments
        nonprod_mts         — MTS in non-prod environments
        total_mts_saveable  — MTS eliminated by parameterization
        total_excl_mts      — MTS eligible for exclusion
        reduction_pct       — estimated % MTS reduction if all actions taken
    """
    # ── Dedup into (op, svc, env) triples with mts_count ─────────────────────
    seen: dict[tuple, dict] = {}
    for row in ops:
        key = (row["operation"], row["service"], row["environment"])
        if key in seen:
            seen[key]["mts_count"] += 1
        else:
            seen[key] = {**row, "mts_count": 1}
    deduped = list(seen.values())

    # ── 1. Parameterization groups ────────────────────────────────────────────
    pattern_groups: dict[str, list] = defaultdict(list)
    for op in deduped:
        pattern = _normalize(op["operation"])
        pattern_groups[pattern].append(op)

    consolidation = []
    for pattern, members in pattern_groups.items():
        if len(members) < 2:
            continue
        total_mts = sum(m["mts_count"] for m in members)
        rx = _extraction_regex(pattern)
        unique_vals: set[str] = set()
        if rx:
            for op_rec in members:
                m = rx.search(op_rec["operation"])
                if m:
                    unique_vals.update(g for g in m.groups() if g)
        consolidation.append({
            "pattern":       pattern,
            "mts_count":     total_mts,
            "unique_ops":    len(members),
            "mts_saved":     total_mts - 1,
            "unique_values": len(unique_vals) if unique_vals else len(members),
            "val_samples":   sorted(unique_vals)[:8],
            "services":      sorted({o["service"] for o in members if o["service"]}),
            "environments":  sorted({o["environment"] for o in members if o["environment"]}),
            "op_samples":    [o["operation"] for o in members[:3]],
        })
    consolidation.sort(key=lambda x: -x["mts_count"])

    # ── 2. Attack / probe detection ───────────────────────────────────────────
    attacks = []
    for op in deduped:
        for sig_re, label in ATTACK_SIGNATURES:
            if sig_re.search(op["operation"]):
                attacks.append({**op, "attack_type": label})
                break

    attack_by_type: dict[str, list] = defaultdict(list)
    for a in attacks:
        attack_by_type[a["attack_type"]].append(a)

    # ── 3. Environment distribution ───────────────────────────────────────────
    env_dist: Counter = Counter()
    svc_dist: Counter = Counter()
    for op in deduped:
        env_dist[op["environment"]] += op["mts_count"]
        svc_dist[op["service"]] += op["mts_count"]

    total_mts    = sum(env_dist.values())
    prod_mts     = sum(v for k, v in env_dist.items() if k.startswith("prod-"))
    nonprod_mts  = total_mts - prod_mts

    # ── 4. Exclusion candidates ───────────────────────────────────────────────
    exclusions: dict[str, list] = defaultdict(list)
    for op in deduped:
        for cls, cls_re in EXCLUSION_CLASSES.items():
            if cls_re.search(op["operation"]):
                exclusions[cls].append(op)
                break

    # ── Summary ───────────────────────────────────────────────────────────────
    total_mts_saveable = sum(c["mts_saved"] for c in consolidation)
    total_excl_mts     = sum(
        sum(op["mts_count"] for op in members)
        for members in exclusions.values()
    )
    attack_mts     = sum(a["mts_count"] for a in attacks)
    reduction_pct  = round(
        (total_mts_saveable + attack_mts + total_excl_mts) / max(total_mts, 1) * 100, 1
    )

    return {
        "total_mts":           total_mts,
        "total_unique_ops":    len(deduped),
        "consolidation":       consolidation,
        "attacks":             attacks,
        "attack_by_type":      dict(attack_by_type),
        "exclusions":          dict(exclusions),
        "env_distribution":    dict(env_dist.most_common()),
        "service_distribution": dict(svc_dist.most_common(30)),
        "prod_mts":            prod_mts,
        "nonprod_mts":         nonprod_mts,
        "total_mts_saveable":  total_mts_saveable,
        "total_excl_mts":      total_excl_mts,
        "reduction_pct":       reduction_pct,
    }
