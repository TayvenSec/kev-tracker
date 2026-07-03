"""
KEV Tracker — GitHub Pages site generator
Builds a minimal dashboard: recent additions, ransomware flags, monthly archive.

Built by Tayven Cyber Security (https://tayvensec.com) — MIT License
"""

import json
from datetime import datetime, timedelta
from pathlib import Path

ROOT = Path(__file__).parent
DATA_DIR = ROOT / "data"
ADDITIONS_DIR = DATA_DIR / "additions"
CATALOG_PATH = DATA_DIR / "kev-catalog.json"
DOCS_DIR = ROOT / "docs"

CSS = """
* { box-sizing: border-box; margin: 0; padding: 0; }
body { font-family: -apple-system, BlinkMacSystemFont, 'Segoe UI', Roboto, sans-serif;
  font-size: 16px; line-height: 1.6; color: #1a1a2e; background: #f8f9fa; }
header { background: #1a1a2e; color: #fff; padding: 2rem 1rem; text-align: center; }
header h1 { font-size: 1.8rem; letter-spacing: -0.5px; }
header p { color: #a0aec0; margin-top: 0.5rem; font-size: 0.95rem; }
.container { max-width: 960px; margin: 0 auto; padding: 2rem 1rem; }
.stat-row { display: flex; gap: 1rem; flex-wrap: wrap; margin-bottom: 2rem; }
.stat { flex: 1; min-width: 150px; background: #fff; border: 1px solid #e2e8f0; border-radius: 8px;
  padding: 1rem; text-align: center; }
.stat .num { font-size: 1.9rem; font-weight: 700; color: #1a1a2e; }
.stat .label { font-size: 0.8rem; color: #718096; text-transform: uppercase; letter-spacing: 0.05em; }
.stat.danger .num { color: #c53030; }
.section-title { font-size: 1.1rem; font-weight: 600; color: #4a5568; margin: 2rem 0 0.75rem;
  border-bottom: 2px solid #e2e8f0; padding-bottom: 0.5rem; }
table { width: 100%; border-collapse: collapse; background: #fff; border: 1px solid #e2e8f0;
  border-radius: 8px; overflow: hidden; font-size: 0.88rem; }
th { text-align: left; padding: 0.55rem 0.75rem; background: #edf2f7; color: #4a5568;
  font-size: 0.75rem; text-transform: uppercase; letter-spacing: 0.05em; }
td { padding: 0.6rem 0.75rem; border-top: 1px solid #e2e8f0; vertical-align: top; }
.cve { font-weight: 600; white-space: nowrap; }
.ransom { color: #c53030; font-weight: 700; font-size: 0.75rem; }
.due { white-space: nowrap; color: #c05621; }
.archive-list a { display: inline-block; margin: 0.25rem 0.5rem 0.25rem 0; padding: 0.35rem 0.75rem;
  border: 1px solid #e2e8f0; border-radius: 5px; background: #fff; color: #4a5568;
  text-decoration: none; font-size: 0.85rem; }
.archive-list a:hover { background: #edf2f7; }
footer { text-align: center; padding: 2rem 1rem; color: #a0aec0; font-size: 0.82rem;
  border-top: 1px solid #e2e8f0; margin-top: 3rem; }
footer a { color: #718096; }
"""


def build():
    DOCS_DIR.mkdir(parents=True, exist_ok=True)
    (DOCS_DIR / ".nojekyll").write_text("")

    catalog = {}
    if CATALOG_PATH.exists():
        try:
            catalog = json.loads(CATALOG_PATH.read_text())
        except Exception:
            pass

    vulns = catalog.get("vulnerabilities", [])
    total = len(vulns)
    now = datetime.utcnow()
    cutoff_30 = (now - timedelta(days=30)).strftime("%Y-%m-%d")
    recent = sorted(
        [v for v in vulns if v.get("dateAdded", "") >= cutoff_30],
        key=lambda v: v.get("dateAdded", ""), reverse=True,
    )
    ransomware_recent = [v for v in recent if str(v.get("knownRansomwareCampaignUse", "")).lower() == "known"]
    due_soon = sorted(
        [v for v in vulns if now.strftime("%Y-%m-%d") <= v.get("dueDate", "") <= (now + timedelta(days=14)).strftime("%Y-%m-%d")],
        key=lambda v: v.get("dueDate", ""),
    )

    def rows(entries, limit=50):
        out = []
        for v in entries[:limit]:
            ransom = '<span class="ransom">RANSOMWARE</span>' if str(v.get("knownRansomwareCampaignUse", "")).lower() == "known" else ""
            out.append(
                f"<tr><td class='cve'>{v.get('cveID','')}</td>"
                f"<td>{v.get('vendorProject','')} {v.get('product','')}</td>"
                f"<td>{v.get('vulnerabilityName','')} {ransom}</td>"
                f"<td>{v.get('dateAdded','')}</td>"
                f"<td class='due'>{v.get('dueDate','')}</td></tr>"
            )
        return "\n".join(out) or "<tr><td colspan='5'>None</td></tr>"

    archive_links = ""
    if ADDITIONS_DIR.exists():
        months = sorted(ADDITIONS_DIR.glob("*-additions.md"), reverse=True)
        archive_links = "\n".join(
            f'<a href="https://github.com/TayvenSec/kev-tracker/blob/main/data/additions/{p.name}">{p.stem.replace("-additions","")}</a>'
            for p in months
        ) or "<p>No monthly logs yet.</p>"

    updated = catalog.get("dateReleased", "") or now.strftime("%Y-%m-%d")

    html = f"""<!DOCTYPE html>
<html lang="en">
<head>
<meta charset="UTF-8"><meta name="viewport" content="width=device-width, initial-scale=1.0">
<title>KEV Tracker — CISA Known Exploited Vulnerabilities</title>
<style>{CSS}</style>
</head>
<body>
<header>
  <h1>🎯 KEV Tracker</h1>
  <p>CISA Known Exploited Vulnerabilities — updated daily · Catalog date: {updated}</p>
</header>
<div class="container">
  <div class="stat-row">
    <div class="stat"><div class="num">{total}</div><div class="label">Total KEV CVEs</div></div>
    <div class="stat"><div class="num">{len(recent)}</div><div class="label">Added last 30 days</div></div>
    <div class="stat danger"><div class="num">{len(ransomware_recent)}</div><div class="label">Recent w/ ransomware use</div></div>
    <div class="stat danger"><div class="num">{len(due_soon)}</div><div class="label">Remediation due ≤14 days</div></div>
  </div>

  <p class="section-title">Added in the Last 30 Days</p>
  <table>
    <thead><tr><th>CVE</th><th>Vendor / Product</th><th>Vulnerability</th><th>Added</th><th>Due</th></tr></thead>
    <tbody>{rows(recent)}</tbody>
  </table>

  <p class="section-title">Remediation Due Within 14 Days</p>
  <table>
    <thead><tr><th>CVE</th><th>Vendor / Product</th><th>Vulnerability</th><th>Added</th><th>Due</th></tr></thead>
    <tbody>{rows(due_soon, 30)}</tbody>
  </table>

  <p class="section-title">Monthly Addition Logs</p>
  <div class="archive-list">{archive_links}</div>

  <p style="margin-top:2rem;font-size:0.85rem;color:#718096;">
    Data: official <a href="https://www.cisa.gov/known-exploited-vulnerabilities-catalog">CISA KEV catalog</a>.
    CVEs listed here are confirmed exploited in the wild — patch these first.
    Due dates are CISA BOD 22-01 deadlines for US federal agencies, and a strong prioritisation signal for everyone else.
  </p>
</div>
<footer>
  <p><a href="https://github.com/TayvenSec/kev-tracker">View on GitHub</a> ·
  <a href="https://tayvensec.com">Tayven Cyber Security</a> ·
  <a href="https://github.com/TayvenSec/patch-tuesday-tracker">Patch Tuesday Tracker</a></p>
</footer>
</body>
</html>"""

    (DOCS_DIR / "index.html").write_text(html)
    print(f"[SITE] Built index.html ({total} CVEs, {len(recent)} recent)")


if __name__ == "__main__":
    build()
