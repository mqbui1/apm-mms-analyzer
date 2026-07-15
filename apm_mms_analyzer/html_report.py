"""
HTML report generator for APM MMS analysis.
Combines the deterministic stats dashboard with the AI narrative report.
"""
from __future__ import annotations

import html
import re


# ---------------------------------------------------------------------------
# Minimal markdown → HTML converter (handles Claude's output format)
# ---------------------------------------------------------------------------

def _md_to_html(md: str) -> str:
    """Convert markdown to HTML — handles the subset Claude produces."""
    lines = md.split("\n")
    out: list[str] = []
    in_code = False
    in_table = False
    in_ul = False
    in_ol = False
    in_blockquote = False
    code_lang = ""

    def close_lists():
        nonlocal in_ul, in_ol
        if in_ul:
            out.append("</ul>")
            in_ul = False
        if in_ol:
            out.append("</ol>")
            in_ol = False

    def close_blockquote():
        nonlocal in_blockquote
        if in_blockquote:
            out.append("</blockquote>")
            in_blockquote = False

    def inline(text: str) -> str:
        """Apply inline formatting."""
        # Code (must come before bold/italic)
        text = re.sub(r'`([^`]+)`', lambda m: f'<code>{html.escape(m.group(1))}</code>', text)
        # Bold + italic
        text = re.sub(r'\*\*\*(.+?)\*\*\*', r'<strong><em>\1</em></strong>', text)
        text = re.sub(r'\*\*(.+?)\*\*', r'<strong>\1</strong>', text)
        text = re.sub(r'\*(.+?)\*', r'<em>\1</em>', text)
        # Links [text](url)
        text = re.sub(r'\[([^\]]+)\]\(([^)]+)\)', r'<a href="\2">\1</a>', text)
        return text

    i = 0
    while i < len(lines):
        line = lines[i]

        # Code block start/end
        if line.startswith("```"):
            if in_code:
                out.append("</code></pre>")
                in_code = False
            else:
                close_lists()
                close_blockquote()
                code_lang = line[3:].strip()
                lang_class = f' class="language-{html.escape(code_lang)}"' if code_lang else ""
                out.append(f'<pre><code{lang_class}>')
                in_code = True
            i += 1
            continue

        if in_code:
            out.append(html.escape(line))
            i += 1
            continue

        # Horizontal rule
        if re.match(r'^[-*_]{3,}\s*$', line):
            close_lists()
            close_blockquote()
            out.append("<hr>")
            i += 1
            continue

        # Headings
        m = re.match(r'^(#{1,4})\s+(.*)', line)
        if m:
            close_lists()
            close_blockquote()
            level = len(m.group(1))
            text = inline(html.escape(m.group(2)))
            anchor = re.sub(r'[^a-z0-9-]', '-', m.group(2).lower().strip())
            out.append(f'<h{level} id="{anchor}">{text}</h{level}>')
            i += 1
            continue

        # Table rows
        if line.startswith("|"):
            close_lists()
            close_blockquote()
            if not in_table:
                out.append('<table>')
                in_table = True
            # Skip separator rows (|---|---|)
            if re.match(r'^\|[-| :]+\|?\s*$', line):
                i += 1
                continue
            cols = [inline(html.escape(c.strip())) for c in line.strip("|").split("|")]
            # First table row = header
            if in_table and out[-1] == "<table>":
                out.append("<thead><tr>" + "".join(f"<th>{c}</th>" for c in cols) + "</tr></thead><tbody>")
            else:
                out.append("<tr>" + "".join(f"<td>{c}</td>" for c in cols) + "</tr>")
            i += 1
            continue
        elif in_table:
            out.append("</tbody></table>")
            in_table = False

        # Blockquote
        if line.startswith("> "):
            close_lists()
            if not in_blockquote:
                out.append("<blockquote>")
                in_blockquote = True
            out.append(f"<p>{inline(html.escape(line[2:]))}</p>")
            i += 1
            continue
        elif in_blockquote and line.strip() == "":
            close_blockquote()

        # Unordered list
        m = re.match(r'^(\s*)-\s+(.*)', line)
        if m:
            close_blockquote()
            if not in_ul:
                close_lists()
                out.append("<ul>")
                in_ul = True
            out.append(f"<li>{inline(html.escape(m.group(2)))}</li>")
            i += 1
            continue

        # Ordered list
        m = re.match(r'^(\s*)\d+\.\s+(.*)', line)
        if m:
            close_blockquote()
            if not in_ol:
                close_lists()
                out.append("<ol>")
                in_ol = True
            out.append(f"<li>{inline(html.escape(m.group(2)))}</li>")
            i += 1
            continue

        # Normal paragraph / blank line
        close_lists()
        if line.strip() == "":
            close_blockquote()
            out.append("")
        else:
            close_blockquote()
            out.append(f"<p>{inline(html.escape(line))}</p>")
        i += 1

    # Close any open blocks
    if in_code:
        out.append("</code></pre>")
    if in_table:
        out.append("</tbody></table>")
    close_lists()
    close_blockquote()

    return "\n".join(out)


# ---------------------------------------------------------------------------
# HTML report
# ---------------------------------------------------------------------------

_CSS = """
*, *::before, *::after { box-sizing: border-box; margin: 0; padding: 0; }

:root {
  --bg:      #f8fafc;
  --surface: #ffffff;
  --border:  #e2e8f0;
  --text:    #1e293b;
  --muted:   #64748b;
  --subtle:  #94a3b8;
  --accent:  #3b82f6;
  --red:     #ef4444;
  --orange:  #f97316;
  --yellow:  #eab308;
  --green:   #22c55e;
  --purple:  #8b5cf6;
}
[data-theme="dark"] {
  --bg:      #0f172a;
  --surface: #1e293b;
  --border:  #334155;
  --text:    #e2e8f0;
  --muted:   #94a3b8;
  --subtle:  #64748b;
}

body {
  font-family: -apple-system, BlinkMacSystemFont, "Segoe UI", Roboto, sans-serif;
  background: var(--bg);
  color: var(--text);
  font-size: 14px;
  line-height: 1.6;
}

.page { max-width: 1100px; margin: 0 auto; padding: 32px 24px 64px; }

/* Header */
.report-header { margin-bottom: 32px; }
.report-header h1 { font-size: 22px; font-weight: 700; color: var(--text); }
.report-header .meta { color: var(--muted); font-size: 12px; margin-top: 4px; }

/* Theme toggle */
.theme-btn {
  float: right; cursor: pointer; background: var(--border);
  border: none; border-radius: 6px; padding: 6px 12px;
  color: var(--text); font-size: 12px;
}

/* Stat grid */
.stat-grid { display: grid; grid-template-columns: repeat(auto-fit, minmax(150px, 1fr)); gap: 12px; margin-bottom: 28px; }
.stat-box {
  background: var(--surface); border: 1px solid var(--border);
  border-radius: 10px; padding: 16px; text-align: center;
}
.stat-box .val { font-size: 26px; font-weight: 700; line-height: 1.1; }
.stat-box .lbl { font-size: 11px; color: var(--muted); margin-top: 4px; text-transform: uppercase; letter-spacing: .5px; }
.stat-box.red   .val { color: var(--red); }
.stat-box.orange .val { color: var(--orange); }
.stat-box.green  .val { color: var(--green); }
.stat-box.blue   .val { color: var(--accent); }
.stat-box.yellow .val { color: var(--yellow); }
.stat-box.purple .val { color: var(--purple); }

/* Cards */
.card {
  background: var(--surface); border: 1px solid var(--border);
  border-radius: 12px; margin-bottom: 20px; overflow: hidden;
}
.card-header {
  padding: 14px 20px; font-weight: 600; font-size: 14px;
  display: flex; align-items: center; gap: 8px;
  cursor: pointer; user-select: none;
  border-bottom: 1px solid var(--border);
}
.card-header .toggle { margin-left: auto; color: var(--subtle); font-size: 12px; }
.card-body { padding: 20px; }
.card-body.hidden { display: none; }

/* Top patterns table */
.patterns-table { width: 100%; border-collapse: collapse; font-size: 13px; }
.patterns-table th {
  background: var(--bg); color: var(--muted);
  font-size: 11px; text-transform: uppercase; letter-spacing: .4px;
  padding: 8px 12px; text-align: left; border-bottom: 1px solid var(--border);
}
.patterns-table td { padding: 8px 12px; border-bottom: 1px solid var(--border); vertical-align: top; }
.patterns-table tr:last-child td { border-bottom: none; }
.patterns-table tr:hover td { background: var(--bg); }
.pat-code { font-family: "SFMono-Regular", Consolas, monospace; font-size: 12px; color: var(--accent); }
.badge {
  display: inline-block; padding: 2px 7px; border-radius: 4px;
  font-size: 11px; font-weight: 600;
}
.badge.red    { background: #fef2f2; color: var(--red); }
.badge.orange { background: #fff7ed; color: var(--orange); }
.badge.yellow { background: #fefce8; color: var(--yellow); }
.badge.green  { background: #f0fdf4; color: var(--green); }
[data-theme="dark"] .badge.red    { background: #3f1212; color: #fca5a5; }
[data-theme="dark"] .badge.orange { background: #3f1f0a; color: #fdba74; }
[data-theme="dark"] .badge.yellow { background: #3f3608; color: #fde047; }
[data-theme="dark"] .badge.green  { background: #0d2e1a; color: #86efac; }

.rank { color: var(--subtle); font-size: 12px; }

/* AI analysis content */
.ai-content { line-height: 1.7; }
.ai-content h1 { font-size: 20px; font-weight: 700; margin: 28px 0 10px; color: var(--text); }
.ai-content h2 { font-size: 17px; font-weight: 700; margin: 24px 0 8px; color: var(--text); border-bottom: 1px solid var(--border); padding-bottom: 6px; }
.ai-content h3 { font-size: 15px; font-weight: 600; margin: 20px 0 6px; color: var(--text); }
.ai-content h4 { font-size: 14px; font-weight: 600; margin: 16px 0 4px; color: var(--muted); }
.ai-content p  { margin: 8px 0; }
.ai-content ul, .ai-content ol { margin: 8px 0 8px 20px; }
.ai-content li { margin: 4px 0; }
.ai-content hr { border: none; border-top: 1px solid var(--border); margin: 20px 0; }
.ai-content blockquote {
  border-left: 3px solid var(--accent); margin: 12px 0;
  padding: 8px 16px; background: var(--bg); border-radius: 0 6px 6px 0;
  color: var(--muted);
}
.ai-content code {
  font-family: "SFMono-Regular", Consolas, monospace; font-size: 12px;
  background: var(--bg); border: 1px solid var(--border);
  border-radius: 4px; padding: 1px 5px; color: var(--accent);
}
.ai-content pre {
  background: #0f172a; border-radius: 8px; padding: 16px;
  overflow-x: auto; margin: 12px 0;
}
[data-theme="dark"] .ai-content pre { background: #020617; border: 1px solid var(--border); }
.ai-content pre code {
  background: none; border: none; color: #e2e8f0;
  font-size: 12px; padding: 0;
}
.ai-content table {
  width: 100%; border-collapse: collapse; font-size: 13px;
  margin: 12px 0; border: 1px solid var(--border); border-radius: 8px; overflow: hidden;
}
.ai-content th {
  background: var(--bg); font-size: 11px; text-transform: uppercase;
  letter-spacing: .4px; padding: 8px 12px; text-align: left;
  border-bottom: 1px solid var(--border); color: var(--muted);
}
.ai-content td { padding: 8px 12px; border-bottom: 1px solid var(--border); }
.ai-content tr:last-child td { border-bottom: none; }
.ai-content strong { font-weight: 600; }

/* Attack badge */
.attack-row td { background: #fef2f2 !important; }
[data-theme="dark"] .attack-row td { background: #2d1515 !important; }
"""

_JS = """
function toggleCard(id) {
  const body = document.getElementById(id);
  const icon = document.getElementById('icon-' + id);
  if (body.classList.contains('hidden')) {
    body.classList.remove('hidden');
    icon.textContent = '▲';
  } else {
    body.classList.add('hidden');
    icon.textContent = '▼';
  }
}
function toggleTheme() {
  const html = document.documentElement;
  html.setAttribute('data-theme', html.getAttribute('data-theme') === 'dark' ? 'light' : 'dark');
}
"""


def _card(title: str, body_html: str, card_id: str, open_by_default: bool = True,
          border_color: str = "") -> str:
    border_style = f"border-left: 3px solid {border_color};" if border_color else ""
    icon = "▲" if open_by_default else "▼"
    hidden = "" if open_by_default else " hidden"
    return f"""
<div class="card" style="{border_style}">
  <div class="card-header" onclick="toggleCard('{card_id}')">
    {html.escape(title)}
    <span class="toggle" id="icon-{card_id}">{icon}</span>
  </div>
  <div class="card-body{hidden}" id="{card_id}">
    {body_html}
  </div>
</div>"""


def _stat_box(value: str, label: str, color: str = "") -> str:
    color_class = f" {color}" if color else ""
    return f"""<div class="stat-box{color_class}">
  <div class="val">{value}</div>
  <div class="lbl">{label}</div>
</div>"""


def _severity_badge(mts: int) -> str:
    if mts >= 10000:
        return '<span class="badge red">CRITICAL</span>'
    elif mts >= 1000:
        return '<span class="badge orange">HIGH</span>'
    elif mts >= 100:
        return '<span class="badge yellow">MEDIUM</span>'
    return '<span class="badge green">LOW</span>'


def generate(analysis: dict, ai_text: str, realm: str = "", generated_at: str = "") -> str:
    """Build the full HTML report."""
    total_mms = analysis["total_mms"]
    total_mts = analysis["total_mts"]
    mms_save  = analysis["total_mms_saveable"]
    excl_mms  = analysis["total_excl_mms"]
    attacks   = len(analysis["attacks"])
    pct       = analysis["reduction_pct"]
    cost      = total_mts * 0.002
    nonprod_pct = round(analysis["nonprod_mts"] / max(total_mts, 1) * 100, 1)

    # ── Stat grid ─────────────────────────────────────────────────────────────
    sev_color = "red" if total_mms >= 10000 else "orange" if total_mms >= 2000 else "yellow" if total_mms >= 500 else "green"
    stats_html = f"""<div class="stat-grid">
  {_stat_box(f"{total_mms:,}", "Total APM MMS", sev_color)}
  {_stat_box(f"{total_mts:,}", "Underlying MTS", "")}
  {_stat_box(f"${cost:,.2f}", "Est. $/mo", "purple")}
  {_stat_box(f"{mms_save:,}", "MMS Saveable (Param)", "green")}
  {_stat_box(f"{excl_mms:,}", "MMS Saveable (Exclusion)", "green")}
  {_stat_box(f"{attacks}", "Attack Payloads", "red" if attacks else "green")}
  {_stat_box(f"{pct}%", "MMS Reduction Potential", "orange")}
  {_stat_box(f"{nonprod_pct}%", "Non-Prod MTS", "")}
</div>"""

    # ── Top patterns table ────────────────────────────────────────────────────
    top = analysis["consolidation"][:30]
    if top:
        rows = []
        for i, p in enumerate(top, 1):
            svcs_str = ", ".join(p["services"][:3])
            if len(p["services"]) > 3:
                svcs_str += f" +{len(p['services'])-3}"
            samples_str = " &bull; ".join(html.escape(s) for s in p["val_samples"][:4]) or "—"
            rows.append(f"""<tr>
  <td class="rank">{i}</td>
  <td><code class="pat-code">{html.escape(p['pattern'])}</code></td>
  <td style="text-align:right">{p['mms_count']:,}</td>
  <td style="text-align:right">{p['unique_values']:,}</td>
  <td style="text-align:right"><strong>{p['mms_saved']:,}</strong></td>
  <td style="color:var(--muted);font-size:12px">{svcs_str or '—'}</td>
  <td style="color:var(--muted);font-size:11px">{samples_str}</td>
</tr>""")
        patterns_html = f"""<table class="patterns-table">
<thead><tr>
  <th>#</th><th>Pattern</th><th style="text-align:right">MMS</th>
  <th style="text-align:right">Unique Vals</th><th style="text-align:right">MMS Saved</th>
  <th>Services</th><th>Sample Values</th>
</tr></thead>
<tbody>{"".join(rows)}</tbody>
</table>"""
    else:
        patterns_html = "<p style='color:var(--muted)'>No parameterizable patterns found.</p>"

    # ── Attack table ──────────────────────────────────────────────────────────
    if analysis["attacks"]:
        attack_rows = []
        for a in analysis["attacks"][:20]:
            attack_rows.append(f"""<tr class="attack-row">
  <td><code style="font-size:12px">{html.escape(a['operation'][:80])}</code></td>
  <td>{html.escape(a['service'])}</td>
  <td>{html.escape(a['environment'])}</td>
  <td><span class="badge red">{html.escape(a['attack_type'])}</span></td>
</tr>""")
        attacks_html = f"""<table class="patterns-table">
<thead><tr><th>Operation</th><th>Service</th><th>Environment</th><th>Signature</th></tr></thead>
<tbody>{"".join(attack_rows)}</tbody>
</table>"""
    else:
        attacks_html = "<p style='color:var(--green)'>No attack signatures detected.</p>"

    # ── Environment distribution ──────────────────────────────────────────────
    env_rows = []
    for env, count in list(analysis["env_distribution"].items())[:20]:
        pct_val = round(count / max(total, 1) * 100, 1)
        bar_w = max(1, int(pct_val * 2))
        prod_marker = " <span class='badge green' style='font-size:10px'>prod</span>" if env.startswith("prod-") else ""
        env_rows.append(f"""<tr>
  <td><code style="font-size:12px">{html.escape(env) if env else '<em style="color:var(--muted)">empty</em>'}</code>{prod_marker}</td>
  <td style="text-align:right">{count:,}</td>
  <td style="text-align:right">{pct_val}%</td>
  <td style="padding-right:12px"><div style="background:var(--accent);height:8px;border-radius:4px;width:{bar_w}px;opacity:.6"></div></td>
</tr>""")
    env_html = f"""<table class="patterns-table">
<thead><tr><th>Environment</th><th style="text-align:right">MTS</th><th style="text-align:right">%</th><th>Distribution</th></tr></thead>
<tbody>{"".join(env_rows)}</tbody>
</table>"""

    # ── AI analysis content ───────────────────────────────────────────────────
    # Strip the header block that cli.py prepends (already shown in stat grid)
    ai_body = ai_text
    # Remove the markdown header lines we added in cli.py
    ai_body = re.sub(r'^#\s+APM MMS AI Analysis Report\s*\n', '', ai_body)
    ai_body = re.sub(r'^\*\*Generated:\*\*.*\n', '', ai_body, flags=re.MULTILINE)
    ai_body = re.sub(r'^\*\*Total MTS:\*\*.*\n', '', ai_body, flags=re.MULTILINE)
    ai_body = re.sub(r'^\*\*Unique operations:\*\*.*\n', '', ai_body, flags=re.MULTILINE)
    ai_body = re.sub(r'^\*\*Reduction potential:\*\*.*\n', '', ai_body, flags=re.MULTILINE)
    ai_body = re.sub(r'^---\s*\n', '', ai_body, flags=re.MULTILINE)
    ai_body = ai_body.strip()

    ai_html = f'<div class="ai-content">{_md_to_html(ai_body)}</div>'

    # ── Assemble page ─────────────────────────────────────────────────────────
    realm_tag = f" &mdash; {html.escape(realm)}" if realm else ""
    meta = f"Generated {generated_at}{realm_tag}" if generated_at else ""

    body = f"""
{stats_html}
{_card("Top Parameterizable Patterns", patterns_html, "sec-patterns")}
{_card("AI Analysis", ai_html, "sec-ai", border_color="#3b82f6")}
{_card("Environment Distribution", env_html, "sec-env", open_by_default=False)}
{_card("Attack / Probe Signatures Detected", attacks_html, "sec-attacks",
       open_by_default=bool(analysis['attacks']),
       border_color="#ef4444" if analysis['attacks'] else "")}
"""

    return f"""<!DOCTYPE html>
<html lang="en" data-theme="light">
<head>
<meta charset="UTF-8">
<meta name="viewport" content="width=device-width, initial-scale=1">
<title>APM MMS Analysis Report</title>
<style>{_CSS}</style>
</head>
<body>
<div class="page">
  <div class="report-header">
    <button class="theme-btn" onclick="toggleTheme()">Toggle theme</button>
    <h1>APM MMS Analysis Report</h1>
    <div class="meta">{meta}</div>
  </div>
  {body}
  <p style="margin-top:32px;color:var(--subtle);font-size:11px">
    Generated by apm-mms-analyzer &mdash; Powered by Claude via AWS Bedrock
  </p>
</div>
<script>{_JS}</script>
</body>
</html>"""
